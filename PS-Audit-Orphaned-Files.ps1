#requires -RunAsAdministrator

<#
.SYNOPSIS
    Audits the Windows Installer cache and registration database.

.DESCRIPTION
    Checks registered Windows Installer products and patches and identifies:

      - Registered MSI products whose cached LocalPackage is missing
      - Registered MSP patches whose cached LocalPackage is missing
      - Corrupt or unreadable Windows Installer registrations
      - Physical MSI/MSP files in C:\Windows\Installer that were not found
        in the Windows Installer enumeration

    IMPORTANT:
    Orphan candidates are reported only.
    This script does NOT delete anything from C:\Windows\Installer.

.NOTES
    Intended for execution as SYSTEM or an elevated administrator through MECM.
#>

# ============================================================
# Configuration
# ============================================================

$LogFolder     = "C:\Logs"
$LogFile       = Join-Path -Path $LogFolder -ChildPath "Installer_Audit.log"
$InstallerPath = Join-Path -Path $env:windir -ChildPath "Installer"


# ============================================================
# Logging
# ============================================================

try {

    if (-not (Test-Path -LiteralPath $LogFolder)) {

        New-Item `
            -ItemType Directory `
            -Path $LogFolder `
            -Force `
            -ErrorAction Stop | Out-Null
    }
}
catch {

    Write-Error "Unable to create log directory '$LogFolder': $($_.Exception.Message)"
    exit 1
}


function Write-Log {

    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet(
            "Info",
            "Success",
            "Warning",
            "Error"
        )]
        [string]$Type = "Info"
    )

    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Entry = "[$TimeStamp] [$Type] $Message"

    try {

        $Entry |
            Out-File `
                -FilePath $LogFile `
                -Append `
                -Encoding utf8 `
                -ErrorAction Stop
    }
    catch {

        Write-Warning "Unable to write to log file '$LogFile'."
    }

    Write-Output $Entry
}


# ============================================================
# Helper Functions
# ============================================================

function Get-FriendlyName {

    param (
        [Parameter(Mandatory = $false)]
        [string]$Guid
    )

    if ([string]::IsNullOrWhiteSpace($Guid)) {
        return "Unknown Product"
    }

    $RegPaths = @(

        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$Guid",

        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$Guid"
    )

    foreach ($Path in $RegPaths) {

        try {

            $Name = Get-ItemPropertyValue `
                -LiteralPath $Path `
                -Name "DisplayName" `
                -ErrorAction Stop

            if (-not [string]::IsNullOrWhiteSpace($Name)) {
                return $Name
            }
        }
        catch {
            # Continue searching other registry locations.
        }
    }

    return "Unknown Product"
}


function Add-ReferencedInstallerFile {

    param (
        [Parameter(Mandatory = $false)]
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return
    }

    try {

        $NormalisedPath = [System.IO.Path]::GetFullPath(
            $Path.Trim()
        )

        [void]$script:ReferencedFiles.Add(
            $NormalisedPath
        )
    }
    catch {

        Write-Log `
            -Message "Unable to normalise Installer path: $Path | $($_.Exception.Message)" `
            -Type "Warning"
    }
}


# ============================================================
# Start Audit
# ============================================================

Write-Log "============================================================"
Write-Log "Starting Windows Installer Health Audit"
Write-Log "Computer: $env:COMPUTERNAME"

$Context = [Security.Principal.WindowsIdentity]::GetCurrent().Name

$ProcessArchitecture = if ([Environment]::Is64BitProcess) {
    "64-bit"
}
else {
    "32-bit"
}

$OSArchitecture = if ([Environment]::Is64BitOperatingSystem) {
    "64-bit"
}
else {
    "32-bit"
}

Write-Log "Execution Context: $Context"
Write-Log "PowerShell Process Architecture: $ProcessArchitecture"
Write-Log "Operating System Architecture: $OSArchitecture"
Write-Log "Installer Cache: $InstallerPath"
Write-Log "============================================================"


# ============================================================
# Counters and Collections
# ============================================================

$MissingPackages   = @()
$EnumerationErrors = @()
$OrphanCandidates  = @()

$ReferencedFiles = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)

$TotalProducts     = 0
$TotalPatches      = 0
$TotalChecked      = 0
$CorruptedProducts = 0
$CorruptedPatches  = 0

$AuditIncomplete = $false
$Installer       = $null


# ============================================================
# Create Windows Installer COM Object
# ============================================================

Write-Log "Connecting to Windows Installer database."

try {

    $Installer = New-Object -ComObject WindowsInstaller.Installer

    Write-Log `
        -Message "Windows Installer COM interface successfully opened." `
        -Type "Success"
}
catch {

    Write-Log `
        -Message "CRITICAL: Unable to create Windows Installer COM object: $($_.Exception.Message)" `
        -Type "Error"

    $AuditIncomplete = $true
}


# ============================================================
# Enumerate Products
# ============================================================

if ($null -ne $Installer) {

    Write-Log "Enumerating Windows Installer products."

    try {

        # MSIINSTALLCONTEXT_ALL = 7
        # S-1-1-0 = Everyone SID

        $AllProducts = $Installer.ProductsEx(
            "",
            "s-1-1-0",
            7
        )

        foreach ($ProductObject in $AllProducts) {

            $TotalProducts++

            $ProductCode = $null
            $ProductName = "Unknown Product"
            $LocalPackage = $null


            # ----------------------------------------------------
            # Obtain ProductCode
            # ----------------------------------------------------

            try {

                $ProductCode = $ProductObject.ProductCode()
            }
            catch {

                $CorruptedProducts++

                $EnumerationErrors += [PSCustomObject]@{
                    Type  = "Product"
                    Code  = "Unknown"
                    Name  = "Unknown Product"
                    Error = $_.Exception.Message
                }

                Write-Log `
                    -Message "Unable to read ProductCode from Installer registration: $($_.Exception.Message)" `
                    -Type "Warning"

                continue
            }


            # ----------------------------------------------------
            # Obtain Product Name
            # ----------------------------------------------------

            try {

                $ProductName = $ProductObject.InstallProperty(
                    "ProductName"
                )

                if ([string]::IsNullOrWhiteSpace($ProductName)) {

                    $ProductName = Get-FriendlyName `
                        -Guid $ProductCode
                }
            }
            catch {

                $ProductName = Get-FriendlyName `
                    -Guid $ProductCode
            }


            # ----------------------------------------------------
            # Audit Product LocalPackage
            # ----------------------------------------------------

            try {

                $LocalPackage = $ProductObject.InstallProperty(
                    "LocalPackage"
                )

                if (-not [string]::IsNullOrWhiteSpace($LocalPackage)) {

                    $TotalChecked++

                    Add-ReferencedInstallerFile `
                        -Path $LocalPackage

                    if (-not (
                        Test-Path `
                            -LiteralPath $LocalPackage `
                            -PathType Leaf
                    )) {

                        $MissingPackages += [PSCustomObject]@{

                            Type         = "Product"
                            ProductCode  = $ProductCode
                            PatchCode    = $null
                            Name         = $ProductName
                            ExpectedPath = $LocalPackage
                        }

                        Write-Log `
                            -Message "Missing MSI: $ProductName | $ProductCode | Expected: $LocalPackage" `
                            -Type "Warning"
                    }
                }
                else {

                    $CorruptedProducts++

                    Write-Log `
                        -Message "Product has no LocalPackage: $ProductName ($ProductCode)" `
                        -Type "Warning"
                }
            }
            catch {

                $CorruptedProducts++

                $EnumerationErrors += [PSCustomObject]@{

                    Type  = "Product"
                    Code  = $ProductCode
                    Name  = $ProductName
                    Error = $_.Exception.Message
                }

                Write-Log `
                    -Message "Unable to query product registration: $ProductName ($ProductCode) | $($_.Exception.Message)" `
                    -Type "Warning"
            }


            # ----------------------------------------------------
            # Audit Patches for this Product
            # ----------------------------------------------------

            try {

                $ProductPatches = @(
                    $Installer.Patches($ProductCode)
                )

                foreach ($PatchCode in $ProductPatches) {

                    $TotalPatches++

                    try {

                        $PatchLocalPackage = $Installer.PatchInfo(
                            $PatchCode,
                            "LocalPackage"
                        )

                        $PatchName = $Installer.PatchInfo(
                            $PatchCode,
                            "DisplayName"
                        )

                        if ([string]::IsNullOrWhiteSpace($PatchName)) {
                            $PatchName = $PatchCode
                        }


                        if (-not [string]::IsNullOrWhiteSpace($PatchLocalPackage)) {

                            $TotalChecked++

                            Add-ReferencedInstallerFile `
                                -Path $PatchLocalPackage

                            if (-not (
                                Test-Path `
                                    -LiteralPath $PatchLocalPackage `
                                    -PathType Leaf
                            )) {

                                $MissingPackages += [PSCustomObject]@{

                                    Type         = "Patch"
                                    ProductCode  = $ProductCode
                                    PatchCode    = $PatchCode
                                    Name         = "$ProductName - $PatchName"
                                    ExpectedPath = $PatchLocalPackage
                                }

                                Write-Log `
                                    -Message "Missing MSP: $ProductName | $PatchName | Expected: $PatchLocalPackage" `
                                    -Type "Warning"
                            }
                        }
                        else {

                            $CorruptedPatches++

                            Write-Log `
                                -Message "Patch has no LocalPackage: $PatchCode under $ProductName" `
                                -Type "Warning"
                        }
                    }
                    catch {

                        $CorruptedPatches++

                        $EnumerationErrors += [PSCustomObject]@{

                            Type  = "Patch"
                            Code  = $PatchCode
                            Name  = $ProductName
                            Error = $_.Exception.Message
                        }

                        Write-Log `
                            -Message "Unable to query patch $PatchCode under $ProductName : $($_.Exception.Message)" `
                            -Type "Warning"
                    }
                }
            }
            catch {

                $CorruptedPatches++

                $EnumerationErrors += [PSCustomObject]@{

                    Type  = "PatchEnumeration"
                    Code  = $ProductCode
                    Name  = $ProductName
                    Error = $_.Exception.Message
                }

                Write-Log `
                    -Message "Unable to enumerate patches for $ProductName ($ProductCode): $($_.Exception.Message)" `
                    -Type "Warning"
            }
        }
    }
    catch {

        $AuditIncomplete = $true

        Write-Log `
            -Message "CRITICAL: Windows Installer product enumeration failed: $($_.Exception.Message)" `
            -Type "Error"
    }
}


# ============================================================
# Physical Windows Installer Cache Comparison
# ============================================================

if (-not $AuditIncomplete) {

    Write-Log "Scanning physical Windows Installer cache."

    try {

        $PhysicalFiles = @(
            Get-ChildItem `
                -LiteralPath $InstallerPath `
                -File `
                -Force `
                -ErrorAction Stop |
            Where-Object {
                $_.Extension -match '^\.(msi|msp)$'
            }
        )

        Write-Log "Physical MSI/MSP files discovered: $($PhysicalFiles.Count)"
        Write-Log "Referenced cached files discovered: $($ReferencedFiles.Count)"


        foreach ($File in $PhysicalFiles) {

            try {

                $FullPath = [System.IO.Path]::GetFullPath(
                    $File.FullName
                )

                if (-not $ReferencedFiles.Contains($FullPath)) {

                    $OrphanCandidates += [PSCustomObject]@{

                        Name          = $File.Name
                        FullPath      = $File.FullName
                        Extension     = $File.Extension

                        SizeBytes     = [int64]$File.Length

                        SizeMB        = [Math]::Round(
                            $File.Length / 1MB,
                            2
                        )

                        LastWriteTime = $File.LastWriteTime
                    }
                }
            }
            catch {

                Write-Log `
                    -Message "Unable to examine Installer file $($File.FullName): $($_.Exception.Message)" `
                    -Type "Warning"
            }
        }
    }
    catch {

        $AuditIncomplete = $true

        Write-Log `
            -Message "Unable to scan physical Windows Installer cache: $($_.Exception.Message)" `
            -Type "Error"
    }
}
else {

    Write-Log `
        -Message "Physical Installer cache scan skipped because Installer database enumeration was incomplete." `
        -Type "Warning"
}


# ============================================================
# Calculate Orphan Candidate Size
# ============================================================

$OrphanCandidateBytes = [int64]0

foreach ($Candidate in $OrphanCandidates) {
    $OrphanCandidateBytes += [int64]$Candidate.SizeBytes
}

$OrphanCandidateMB = [Math]::Round(
    $OrphanCandidateBytes / 1MB,
    2
)

$OrphanCandidateGB = [Math]::Round(
    $OrphanCandidateBytes / 1GB,
    3
)


# ============================================================
# Registered Installer Cache Health
# ============================================================

Write-Log "============================================================"
Write-Log "REGISTERED INSTALLER CACHE HEALTH"
Write-Log "============================================================"

Write-Log "Products enumerated: $TotalProducts"
Write-Log "Patches enumerated: $TotalPatches"
Write-Log "Cached entries validated: $TotalChecked"


if ($MissingPackages.Count -gt 0) {

    Write-Log `
        -Messagen $MissingPackages {

        Write-Log `
            -Message "MISSING [$($Package.Type)] $($Package.Name) | Expected: $($Package.ExpectedPath)" `
            -Type "Warning"
    }
}
else {

    Write-Log `
        -Message "Missing registered cached files: 0" `
        -Type "Success"
}


# ============================================================
# Potential Orphaned Installer Files
# ============================================================

Write-Log "============================================================"
Write-Log "POTENTIAL ORPHANED INSTALLER FILES"
Write-Log "============================================================"


if ($AuditIncomplete) {

    Write-Log `
        -Message "Orphan assessment is NOT considered reliable because the audit was incomplete." `
        -Type "Warning"
}
elseif ($OrphanCandidates.Count -gt 0) {

    Write-Log `
        -Message "Potential orphan files found: $($OrphanCandidates.Count)" `
        -Type "Warning"

    Write-Log `
        -Message "Potential reclaimable space: $OrphanCandidateMB MB / $OrphanCandidateGB GB" `
        -Type "Warning"

    foreach ($Candidate in $OrphanCandidates) {

        Write-Log `
            -Message "CANDIDATE ONLY - $($Candidate.Name) | $($Candidate.SizeMB) MB | Modified: $($Candidate.LastWriteTime) | $($Candidate.FullPath)" `
            -Type "Warning"
    }
}
else {

    Write-Log `
        -Message "Potential orphan files found: 0" `
        -Type "Success"
}


# ============================================================
# Determine Overall Status
# ============================================================

$TotalCorruptions = (
    $CorruptedProducts +
    $CorruptedPatches
)

if ($AuditIncomplete) {

    $Status = "FAILED - INCOMPLETE"
}
elseif ($MissingPackages.Count -gt 0) {

    $Status = "WARNING - MISSING CACHE FILES"
}
elseif ($TotalCorruptions -gt 0) {

    $Status = "WARNING - REGISTRATION ERRORS"
}
elseif ($OrphanCandidates.Count -gt 0) {

    $Status = "WARNING - ORPHAN CANDIDATES"
}
else {

    $Status = "HEALTHY"
}


# ============================================================
# Final Log Summary
# ============================================================

Write-Log "============================================================"
Write-Log "AUDIT SUMMARY"
Write-Log "============================================================"

Write-Log "Status: $Status"
Write-Log "Products: $TotalProducts"
Write-Log "Patches: $TotalPatches"
Write-Log "Entries Checked: $TotalChecked"
Write-Log "Corrupt Products: $CorruptedProducts"
Write-Log "Corrupt Patches: $CorruptedPatches"
Write-Log "Enumeration Errors: $($EnumerationErrors.Count)"
Write-Log "Missing Cache Files: $($MissingPackages.Count)"
Write-Log "Orphan Candidates: $($OrphanCandidates.Count)"
Write-Log "Orphan Candidate Size: $OrphanCandidateMB MB"
Write-Log "Audit Incomplete: $AuditIncomplete"

Write-Log "============================================================"
Write-Log "End of Windows Installer Audit"
Write-Log "============================================================"


# ============================================================
# Release Windows Installer COM Object
# ============================================================

if ($null -ne $Installer) {

    try {

        [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject(
            $Installer
        )
    }
    catch {

        Write-Log `
            -Message "Unable to explicitly release Windows Installer COM object: $($_.Exception.Message)" `
            -Type "Warning"
    }
}


# ============================================================
# MECM Console Output
# ============================================================

$Result = [PSCustomObject]@{

    Computer           = $env:COMPUTERNAME
    Status             = $Status

    Products           = $TotalProducts
    Patches            = $TotalPatches
    EntriesChecked     = $TotalChecked

    CorruptProducts    = $CorruptedProducts
    CorruptPatches     = $CorruptedPatches
    EnumerationErrors  = $EnumerationErrors.Count

    MissingCacheFiles  = $MissingPackages.Count

    OrphanCandidates   = $OrphanCandidates.Count
    OrphanCandidateMB  = $OrphanCandidateMB

    AuditIncomplete    = $AuditIncomplete
}

$Result | Format-Table -AutoSize