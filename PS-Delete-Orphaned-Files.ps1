#requires -RunAsAdministrator

<#
.SYNOPSIS
    MECM client cache and Windows Installer orphan cleanup.

.DESCRIPTION
    1. Records initial C: free space.
    2. Clears the Configuration Manager client cache using the supported
       UIResource.UIResourceMgr COM interface.
    3. Builds a list of cached MSI/MSP files referenced by Windows Installer.
    4. Identifies unreferenced MSI/MSP files.
    5. Deletes only files older than the configured safety period.
    6. Records detailed results to a log.
    7. Returns a summary suitable for MECM/script output.

.NOTES
    Run as SYSTEM or elevated administrator.
#>

# ============================================================
# Configuration
# ============================================================

$LogFolder = "C:\Logs"
$LogFile   = Join-Path $LogFolder "Installer_Cleanup.log"

$InstallerPath = Join-Path $env:windir "Installer"

# Additional safeguard. A file must be at least this old before
# this script will consider deleting it.
$MinimumAgeDays = 90

# Change to $true if you want to test without actually removing
# Installer files.
$WhatIfMode = $false


# ============================================================
# Logging
# ============================================================

if (-not (Test-Path -LiteralPath $LogFolder)) {
    New-Item -ItemType Directory -Path $LogFolder -Force | Out-Null
}

function Write-Log {
    param (
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet("Info", "Warning", "Error")]
        [string]$Type = "Info"
    )

    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Entry = "[$TimeStamp] [$Type] $Message"

    $Entry | Out-File -FilePath $LogFile -Append -Encoding utf8
    Write-Output $Entry
}


# ============================================================
# Start
# ============================================================

Write-Log "============================================================"
Write-Log "Starting automated cleanup on $env:COMPUTERNAME"
Write-Log "Minimum Installer file age: $MinimumAgeDays days"
Write-Log "WhatIf mode: $WhatIfMode"
Write-Log "============================================================"


# ============================================================
# 1. Initial disk statistics
# ============================================================

try {

    $DiskBefore = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"

    $InitialFreeBytes = [int64]$DiskBefore.FreeSpace
    $InitialFreeGB = [math]::Round($InitialFreeBytes / 1GB, 2)

    Write-Log "Initial C: free space: $InitialFreeGB GB"
}
catch {

    Write-Log "Unable to determine initial disk space: $($_.Exception.Message)" "Error"
    exit 1
}


# ============================================================
# 2. Clear MECM client cache
# ============================================================

$CCMRemovedCount = 0
$CCMRemovedBytes = [int64]0

Write-Log "Starting MECM client cache cleanup."

try {

    $CCM = New-Object -ComObject "UIResource.UIResourceMgr"
    $Cache = $CCM.GetCacheInfo()

    $CacheElements = @($Cache.GetCacheElements())

    Write-Log "MECM cache contains $($CacheElements.Count) element(s)."

    foreach ($Element in $CacheElements) {

        try {

            # Attempt to determine cached content size before deletion.
            $ContentLocation = $Element.Location
            $ElementSize = [int64]0

            if ($ContentLocation -and
                (Test-Path -LiteralPath $ContentLocation)) {

                $ElementSize = [int64](
                    (Get-ChildItem -LiteralPath $ContentLocation `
                        -Recurse `
                        -Force `
                        -File `
                        -ErrorAction SilentlyContinue |
                     Measure-Object -Property Length -Sum).Sum
                )
            }

            $Cache.DeleteCacheElement($Element.CacheElementID)

            $CCMRemovedCount++
            $CCMRemovedBytes += $ElementSize

            Write-Log "Removed MECM cache element: $($Element.CacheElementID)"
        }
        catch {

            Write-Log "Failed to remove MECM cache element $($Element.CacheElementID): $($_.Exception.Message)" "Warning"
        }
    }

    Write-Log "MECM cache cleanup completed. Elements removed: $CCMRemovedCount"
}
catch {

    #
    # IMPORTANT:
    # Do not manually delete ccmcache as a fallback.
    #
    Write-Log "Unable to access the MECM client cache API: $($_.Exception.Message)" "Warning"
}


# ============================================================
# 3. Build Windows Installer reference list
# ============================================================

Write-Log "Scanning Windows Installer database."

$SafeFiles = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)

try {

    $Installer = New-Object -ComObject WindowsInstaller.Installer
}
catch {

    Write-Log "Unable to create Windows Installer COM object: $($_.Exception.Message)" "Error"
    Write-Log "Installer cleanup ABORTED."

    $Installer = $null
}


# ============================================================
# Registered MSI products
# ============================================================

$ProductCount = 0
$ProductErrorCount = 0

if ($null -ne $Installer) {

    Write-Log "Enumerating registered MSI products."

    try {

        foreach ($ProductCode in $Installer.Products) {

            try {

                $LocalPackage = $Installer.ProductInfo(
                    $ProductCode,
                    "LocalPackage"
                )

                if ($LocalPackage) {

                    $NormalisedPath = [System.IO.Path]::GetFullPath(
                        $LocalPackage
                    )

                    [void]$SafeFiles.Add($NormalisedPath)
                    $ProductCount++
                }
            }
            catch {

                $ProductErrorCount++
            }
        }

        Write-Log "Registered MSI LocalPackage entries found: $ProductCount"

        if ($ProductErrorCount -gt 0) {
            Write-Log "MSI products that could not be queried: $ProductErrorCount" "Warning"
        }
    }
    catch {

        Write-Log "MSI product enumeration failed: $($_.Exception.Message)" "Error"
        $Installer = $null
    }
}


# ============================================================
# Registered MSP patches
# ============================================================

$PatchCount = 0
$PatchErrorCount = 0

if ($null -ne $Installer) {

    Write-Log "Enumerating registered Windows Installer patches."

    try {

        foreach ($PatchCode in $Installer.Patches("")) {

            try {

                $LocalPackage = $Installer.PatchInfo(
                    $PatchCode,
                    "LocalPackage"
                )

                if ($LocalPackage) {

                    $NormalisedPath = [System.IO.Path]::GetFullPath(
                        $LocalPackage
                    )

                    [void]$SafeFiles.Add($NormalisedPath)
                    $PatchCount++
                }
            }
            catch {

                $PatchErrorCount++
            }
        }

        Write-Log "Registered MSP LocalPackage entries found: $PatchCount"

        if ($PatchErrorCount -gt 0) {
            Write-Log "MSP patches that could not be queried: $PatchErrorCount" "Warning"
        }
    }
    catch {

        Write-Log "Patch enumeration failed: $($_.Exception.Message)" "Error"

        #
        # DO NOT continue with deletion if patch enumeration fails.
        #
        $Installer = $null
    }
}


# ============================================================
# 4. Examine Windows Installer cache
# ============================================================

$CandidateCount       = 0
$CandidateBytes       = [int64]0
$DeletedCount         = 0
$DeletedBytes         = [int64]0
$SkippedAgeCount      = 0
$FailedCount          = 0

if ($null -eq $Installer) {

    Write-Log "Installer database enumeration was incomplete." "Error"
    Write-Log "Windows Installer file deletion has been skipped for safety." "Warning"
}
else {

    Write-Log "Windows Installer database enumeration completed."
    Write-Log "Protected cached files: $($SafeFiles.Count)"
    Write-Log "Scanning physical Installer cache: $InstallerPath"

    $CutOffDate = (Get-Date).AddDays(-$MinimumAgeDays)

    try {

        $InstallerFiles = @(
            Get-ChildItem `
                -LiteralPath $InstallerPath `
                -File `
                -Force `
                -ErrorAction Stop |
            Where-Object {
                $_.Extension -match '^\.(msi|msp)$'
            }
        )

        Write-Log "Physical MSI/MSP files found: $($InstallerFiles.Count)"

        foreach ($File in $InstallerFiles) {

            $FullPath = [System.IO.Path]::GetFullPath(
                $File.FullName
            )

            #
            # Registered with Windows Installer.
            #
            if ($SafeFiles.Contains($FullPath)) {
                continue
            }

            #
            # File has not appeared in the Installer reference list.
            #
            $CandidateCount++
            $CandidateBytes += $File.Length

            #
            # Additional age protection.
            #
            if ($File.LastWriteTime -gt $CutOffDate) {

                $SkippedAgeCount++

                Write-Log "Skipped candidate because file is newer than $MinimumAgeDays days: $($File.Name)" "Warning"

                continue
            }

            #
            # WhatIf / pilot mode
            #
            if ($WhatIfMode) {

                Write-Log "WHATIF - Would delete Installer candidate: $($File.FullName) [$([math]::Round($File.Length / 1MB,2)) MB]"

                continue
            }

            #
            # Delete
            #
            try {

                $FileSize = [int64]$File.Length

                Remove-Item `
                    -LiteralPath $File.FullName `
                    -Force `
                    -ErrorAction Stop

                $DeletedCount++
                $DeletedBytes += $FileSize

                Write-Log "Deleted Installer candidate: $($File.Name) [$([math]::Round($FileSize / 1MB,2)) MB]"
            }
            catch {

                $FailedCount++

                Write-Log "FAILED to delete $($File.FullName): $($_.Exception.Message)" "Warning"
            }
        }
    }
    catch {

        Write-Log "Unable to enumerate Windows Installer cache: $($_.Exception.Message)" "Error"
    }
}


# ============================================================
# 5. Calculate final disk state
# ============================================================

try {

    #
    # Small delay allows filesystem changes to settle.
    #
    Start-Sleep -Seconds 2

    $DiskAfter = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"

    $FinalFreeBytes = [int64]$DiskAfter.FreeSpace
    $FinalFreeGB = [math]::Round($FinalFreeBytes / 1GB, 2)

    $ActualFreedBytes = $FinalFreeBytes - $InitialFreeBytes

    $ActualFreedGB = [math]::Round(
        $ActualFreedBytes / 1GB,
        2
    )
}
catch {

    $FinalFreeGB = 0
    $ActualFreedGB = 0

    Write-Log "Unable to determine final disk space: $($_.Exception.Message)" "Warning"
}


# ============================================================
# 6. Final logging
# ============================================================

$CandidateMB = [math]::Round(
    $CandidateBytes / 1MB,
    2
)

$DeletedMB = [math]::Round(
    $DeletedBytes / 1MB,
    2
)

$CCMRemovedMB = [math]::Round(
    $CCMRemovedBytes / 1MB,
    2
)

Write-Log "============================================================"
Write-Log "Cleanup completed"
Write-Log "MECM cache elements removed : $CCMRemovedCount"
Write-Log "Approx. MECM cache removed   : $CCMRemovedMB MB"
Write-Log "Installer candidates found   : $CandidateCount"
Write-Log "Installer candidate size     : $CandidateMB MB"
Write-Log "Skipped due to file age      : $SkippedAgeCount"
Write-Log "Installer files deleted      : $DeletedCount"
Write-Log "Installer files failed       : $FailedCount"
Write-Log "Installer space removed      : $DeletedMB MB"
Write-Log "Initial C: free space        : $InitialFreeGB GB"
Write-Log "Final C: free space          : $FinalFreeGB GB"
Write-Log "Actual disk space gained     : $ActualFreedGB GB"
Write-Log "============================================================"


# ============================================================
# 7. MECM-friendly output
# ============================================================

$Result = [PSCustomObject]@{

    Computer               = $env:COMPUTERNAME

    FreeBeforeGB           = $InitialFreeGB
    FreeAfterGB            = $FinalFreeGB
    ActualFreedGB          = $ActualFreedGB

    CCMElementsRemoved     = $CCMRemovedCount
    ApproxCCMRemovedMB     = $CCMRemovedMB

    InstallerCandidates    = $CandidateCount
    InstallerCandidateMB   = $CandidateMB

    InstallerFilesDeleted  = $DeletedCount
    InstallerDeletedMB     = $DeletedMB

    InstallerFilesFailed   = $FailedCount
    InstallerFilesAgeSkip  = $SkippedAgeCount

    WhatIf                  = $WhatIfMode
}

$Result | Format-Table -AutoSize