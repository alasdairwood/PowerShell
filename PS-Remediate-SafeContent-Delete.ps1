<#
.SYNOPSIS
    Intune remediation script for safe AppData + system dump + SCCM cache cleanup.

.DESCRIPTION
    Cleans user profile AppData cache/temp content and system dump files older than configured thresholds.
    Also cleans SCCM (ConfigMgr) client cache content older than configured threshold.

.NOTES
    Designed for Microsoft Intune Remediations.
    Run as 64-bit PowerShell.
    Recommended to run using system context.
#>

# -----------------------------
# Configuration
# -----------------------------

$TempOlderThanDays        = 1
$CacheOlderThanDays       = 7
$CrashDumpOlderThanDays   = 7
$IncludeWindowsTemp       = $true

# SCCM cache cleanup
$CleanSccmCache           = $true
$SccmCacheOlderThanDays   = 7
$SccmCacheFallbackPath    = "C:\Windows\ccmcache"

# Safety controls
$SkipLoadedProfiles       = $false   # If $true, skips profiles currently loaded (logged in)
$RemoveEmptyDirectories   = $true
$WhatIf                   = $false   # Set $true for testing (no deletions)

# -----------------------------
# Variables
# -----------------------------

$Now = Get-Date

$TotalRemovedBytes = 0
$RemovedItems = New-Object System.Collections.Generic.List[object]
$Errors = New-Object System.Collections.Generic.List[string]

$ExcludedProfileNames = @(
    "Public",
    "Default",
    "Default User",
    "All Users",
    "WDAGUtilityAccount",
    "defaultuser0"
)

# -----------------------------
# Helper Functions
# -----------------------------

function Add-RemovedItem {
    param(
        [string]$ProfileName,
        [string]$Category,
        [string]$Path,
        [int64]$SizeBytes
    )

    $script:TotalRemovedBytes += $SizeBytes
    $script:RemovedItems.Add([PSCustomObject]@{
        ProfileName = $ProfileName
        Category    = $Category
        Path        = $Path
        SizeMB      = :Round($SizeBytes / 1MB, 2)
    }) | Out-Null
}

function Get-UserProfiles {
    $Profiles = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue |
        Where-Object {
            $_.LocalPath -like "C:\Users\*" -and
            $_.Special -eq $false -and
            $_.LocalPath -and
            (Test-Path -LiteralPath $_.LocalPath)
        }

    foreach ($UserProfile in $Profiles) {
        $ProfileName = Split-Path -Path $UserProfile.LocalPath -Leaf

        if ($ExcludedProfileNames -contains $ProfileName) { continue }
        if ($script:SkipLoadedProfiles -and $UserProfile.Loaded) { continue }

        [PSCustomObject]@{
            ProfileName = $ProfileName
            ProfilePath = $UserProfile.LocalPath
            Loaded      = $UserProfile.Loaded
            SID         = $UserProfile.SID
        }
    }
}

function Remove-OldFilesInDirectory {
    param(
        [string]$ProfileName,
        [string]$Category,
        [string]$Path,
        [datetime]$OlderThan
    )

    if (-not (Test-Path -LiteralPath $Path)) { return }

    try {
        $files = Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue |
                 Where-Object { $_.LastWriteTime -lt $OlderThan } |
                 Where-Object {
                    if ($_.Attributes) { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 } else { $true }
                 }

        foreach ($f in $files) {
            try {
                $size = [int64]$f.Length
                if (-not $script:WhatIf) {
                    Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop
                }
                Add-RemovedItem -ProfileName $ProfileName -Category $Category -Path $f.FullName -SizeBytes $size
            }
            catch {
                $script:Errors.Add("Failed to remove file: $($f.FullName) | $($_.Exception.Message)") | Out-Null
            }
        }

        if ($script:RemoveEmptyDirectories) {
            # Clean up empty folders bottom-up
            try {
                Get-ChildItem -LiteralPath $Path -Recurse -Force -Directory -ErrorAction SilentlyContinue |
                    Sort-Object FullName -Descending |
                    ForEach-Object {
                        try {
                            $hasChildren = Get-ChildItem -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue | Select-Object -First 1
                            if (-not $hasChildren) {
                                if (-not $script:WhatIf) {
                                    Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop
                                }
                            }
                        } catch { }
                    }
            } catch { }
        }
    }
    catch {
        $script:Errors.Add("Failed enumerating path: $Path | $($_.Exception.Message)") | Out-Null
    }
}

function Remove-OldSingleFile {
    param(
        [string]$ProfileName,
        [string]$Category,
        [string]$Path,
        [datetime]$OlderThan
    )

    if (-not (Test-Path -LiteralPath $Path)) { return }

    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($item.PSIsContainer) { return }

        if ($item.LastWriteTime -lt $OlderThan) {
            $size = [int64]$item.Length
            if (-not $script:WhatIf) {
                Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
            }
            Add-RemovedItem -ProfileName $ProfileName -Category $Category -Path $Path -SizeBytes $size
        }
    }
    catch {
        $script:Errors.Add("Failed to remove file: $Path | $($_.Exception.Message)") | Out-Null
    }
}

function Remove-DmpFilesInFolder {
    param(
        [string]$FolderPath,
        [string]$Category,
        [datetime]$OlderThan,
        [switch]$Recurse
    )

    if (-not (Test-Path -LiteralPath $FolderPath)) { return }

    try {
        $params = @{
            LiteralPath = $FolderPath
            Filter      = "*.dmp"
            File        = $true
            Force       = $true
            ErrorAction = "SilentlyContinue"
        }
        if ($Recurse) { $params.Recurse = $true }

        Get-ChildItem @params | Where-Object { $_.LastWriteTime -lt $OlderThan } | ForEach-Object {
            try {
                $size = [int64]$_.Length
                if (-not $script:WhatIf) {
                    Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop
                }
                Add-RemovedItem -ProfileName "System" -Category $Category -Path $_.FullName -SizeBytes $size
            }
            catch {
                $script:Errors.Add("Failed to remove DMP: $($_.FullName) | $($_.Exception.Message)") | Out-Null
            }
        }
    }
    catch {
        $script:Errors.Add("Failed enumerating DMP folder: $FolderPath | $($_.Exception.Message)") | Out-Null
    }
}

# -----------------------------
# SCCM Cache Cleanup (Preferred: WMI root\ccm\SoftMgmtAgent)
# -----------------------------

function Get-SccmCacheLocation {
    try {
        $cfg = Get-CimInstance -Namespace "root\ccm\SoftMgmtAgent" -ClassName "CCM_CacheConfig" -ErrorAction Stop
        # Common property names seen in different client versions:
        foreach ($p in @("Location","CacheRoot","Path")) {
            if ($cfg.$p -and (Test-Path -LiteralPath $cfg.$p)) { return $cfg.$p }
        }
    } catch { }
    return $script:SccmCacheFallbackPath
}

function Clear-SccmCacheOlderThan {
    param(
        [datetime]$OlderThan
    )

    $cachePath = Get-SccmCacheLocation

    # Try WMI element deletion first (safer)
    try {
        $elements = Get-CimInstance -Namespace "root\ccm\SoftMgmtAgent" -ClassName "CCM_CacheElement" -ErrorAction Stop

        foreach ($e in $elements) {
            $lastRef = $null
            try {
                if ($e.LastReferenceTime) {
                    $lastRef = [System.Management.ManagementDateTimeConverter]::ToDateTime($e.LastReferenceTime)
                }
            } catch { }

            if ($null -eq $lastRef) {
                # If we can't read LastReferenceTime, skip (safety)
                continue
            }

            if ($lastRef -lt $OlderThan) {
                # Measure approximate size from on-disk location (if available)
                $location = $e.Location
                $sizeBytes = 0
                if ($location -and (Test-Path -LiteralPath $location)) {
                    try {
                        $sizeBytes = (Get-ChildItem -LiteralPath $location -Recurse -Force -File -ErrorAction SilentlyContinue |
                                      Measure-Object -Property Length -Sum).Sum
                        if (-not $sizeBytes) { $sizeBytes = 0 }
                        $sizeBytes = [int64]$sizeBytes
                    } catch { $sizeBytes = 0 }
                }

                try {
                    if (-not $script:WhatIf) {
                        Invoke-CimMethod -InputObject $e -MethodName "Delete" -ErrorAction Stop | Out-Null
                    }
                    $pathOut = if ($location) { $location } else { $cachePath }
                    Add-RemovedItem -ProfileName "System" -Category "SCCM CCMCache (WMI element)" -Path $pathOut -SizeBytes $sizeBytes
                }
                catch {
                    $script:Errors.Add("Failed deleting SCCM cache element (WMI): $($e.CacheID) | $($_.Exception.Message)") | Out-Null
                }
            }
        }

        return
    }
    catch {
        # Fall back to file-based cleanup
        $script:Errors.Add("SCCM WMI not available or failed; falling back to file-based cleanup on $cachePath | $($_.Exception.Message)") | Out-Null
    }

    # Fallback: prune files in cache folder older than threshold
    Remove-OldFilesInDirectory -ProfileName "System" -Category "SCCM CCMCache (file fallback)" -Path $cachePath -OlderThan $OlderThan
}

# -----------------------------
# Main Remediation
# -----------------------------

try {
    $TempOlderThan       = $Now.AddDays(-$TempOlderThanDays)
    $CacheOlderThan      = $Now.AddDays(-$CacheOlderThanDays)
    $CrashDumpOlderThan  = $Now.AddDays(-$CrashDumpOlderThanDays)
    $SccmCacheOlderThan  = $Now.AddDays(-$SccmCacheOlderThanDays)

    $Profiles = Get-UserProfiles

    foreach ($UserProfile in $Profiles) {
        $ProfileName = $UserProfile.ProfileName
        $ProfilePath = $UserProfile.ProfilePath

        # User Temp
        Remove-OldFilesInDirectory -ProfileName $ProfileName -Category "User Temp" -Path (Join-Path $ProfilePath "AppData\Local\Temp") -OlderThan $TempOlderThan

        # Crash dumps (per-user)
        Remove-OldFilesInDirectory -ProfileName $ProfileName -Category "Crash Dumps" -Path (Join-Path $ProfilePath "AppData\Local\CrashDumps") -OlderThan $CrashDumpOlderThan

        # Edge cache - all profiles
        $EdgeUserData = Join-Path $ProfilePath "AppData\Local\Microsoft\Edge\User Data"
        if (Test-Path -LiteralPath $EdgeUserData) {
            Get-ChildItem -LiteralPath $EdgeUserData -Directory -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match "^(Default|Profile \d+|Guest Profile)$" } |
                ForEach-Object {
                    Remove-OldFilesInDirectory -ProfileName $ProfileName -Category "Edge Cache" -Path (Join-Path $_.FullName "Cache") -OlderThan $CacheOlderThan
                    Remove-OldFilesInDirectory -ProfileName $ProfileName -Category "Edge Code Cache" -Path (Join-Path $_.FullName "Code Cache") -OlderThan $CacheOlderThan
                    Remove-OldFilesInDirectory -ProfileName $ProfileName -Category "Edge GPU Cache" -Path (Join-Path $_.FullName "GPUCache") -OlderThan $CacheOlderThan
                    Remove-OldFilesInDirectory -ProfileName $ProfileName -Category "Edge Service Worker Cache" -Path (Join-Path $_.FullName "Service Worker\CacheStorage") -OlderThan $CacheOlderThan
                }
        }

        # Chrome cache - all profiles
        $ChromeUserData = Join-Path $ProfilePath "AppData\Local\Google\Chrome\User Data"
        if (Test-Path -LiteralPath $ChromeUserData) {
            Get-ChildItem -LiteralPath $ChromeUserData -Directory -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match "^(Default|Profile \d+|Guest Profile)$" } |
                ForEach-Object {
                    Remove-OldFilesInDirectory -ProfileName $ProfileName -Category "Chrome Cache" -Path (Join-Path $_.FullName "Cache") -OlderThan $CacheOlderThan
                    Remove-OldFilesInDirectory -ProfileName $ProfileName -Category "Chrome Code Cache" -Path (Join-Path $_.FullName "Code Cache") -OlderThan $CacheOlderThan
                    Remove-OldFilesInDirectory -ProfileName $ProfileName -Category "Chrome GPU Cache" -Path (Join-Path $_.FullName "GPUCache") -OlderThan $CacheOlderThan
                    Remove-OldFilesInDirectory -ProfileName $ProfileName -Category "Chrome Service Worker Cache" -Path (Join-Path $_.FullName "Service Worker\CacheStorage") -OlderThan $CacheOlderThan
                }
        }

        # Teams classic cache
        $TeamsClassicPaths = @(
            (Join-Path $ProfilePath "AppData\Roaming\Microsoft\Teams\Cache"),
            (Join-Path $ProfilePath "AppData\Roaming\Microsoft\Teams\Code Cache"),
            (Join-Path $ProfilePath "AppData\Roaming\Microsoft\Teams\GPUCache"),
            (Join-Path $ProfilePath "AppData\Roaming\Microsoft\Teams\IndexedDB"),
            (Join-Path $ProfilePath "AppData\Roaming\Microsoft\Teams\Local Storage"),
            (Join-Path $ProfilePath "AppData\Roaming\Microsoft\Teams\tmp"),
            (Join-Path $ProfilePath "AppData\Local\Microsoft\Teams\Cache"),
            (Join-Path $ProfilePath "AppData\Local\Microsoft\Teams\Code Cache"),
            (Join-Path $ProfilePath "AppData\Local\Microsoft\Teams\GPUCache"),
            (Join-Path $ProfilePath "AppData\Local\Microsoft\Teams\tmp")
        )
        foreach ($p in $TeamsClassicPaths) {
            Remove-OldFilesInDirectory -ProfileName $ProfileName -Category "Teams Classic Cache" -Path $p -OlderThan $CacheOlderThan
        }

        # New Teams cache (Store/UWP package)
        $NewTeamsBase = Join-Path $ProfilePath "AppData\Local\Packages\MSTeams_8wekyb3d8bbwe"
        $NewTeamsPaths = @(
            (Join-Path $NewTeamsBase "LocalCache\Microsoft\MSTeams\Cache"),
            (Join-Path $NewTeamsBase "LocalCache\Microsoft\MSTeams\Code Cache"),
            (Join-Path $NewTeamsBase "LocalCache\Microsoft\MSTeams\GPUCache"),
            (Join-Path $NewTeamsBase "LocalCache\Microsoft\MSTeams\Service Worker\CacheStorage"),
            (Join-Path $NewTeamsBase "TempState")
        )
        foreach ($p in $NewTeamsPaths) {
            Remove-OldFilesInDirectory -ProfileName $ProfileName -Category "New Teams Cache" -Path $p -OlderThan $CacheOlderThan
        }

        # Explorer cache (icon/thumbnail DBs typically)
        Remove-OldFilesInDirectory -ProfileName $ProfileName -Category "Explorer Cache" -Path (Join-Path $ProfilePath "AppData\Local\Microsoft\Windows\Explorer") -OlderThan $CacheOlderThan
    }

    # Windows Temp
    if ($IncludeWindowsTemp) {
        Remove-OldFilesInDirectory -ProfileName "System" -Category "Windows Temp" -Path "C:\Windows\Temp" -OlderThan $TempOlderThan
    }

    # SCCM cache (older than threshold)
    if ($CleanSccmCache) {
        Clear-SccmCacheOlderThan -OlderThan $SccmCacheOlderThan
    }

    # System dump files
    Remove-OldSingleFile -ProfileName "System" -Category "Windows MEMORY.DMP" -Path "C:\Windows\MEMORY.DMP" -OlderThan $CrashDumpOlderThan
    Remove-OldFilesInDirectory -ProfileName "System" -Category "Windows Minidumps" -Path "C:\Windows\Minidump" -OlderThan $CrashDumpOlderThan
    Remove-DmpFilesInFolder -FolderPath "C:\Windows" -Category "Windows DMP (root)" -OlderThan $CrashDumpOlderThan
    Remove-DmpFilesInFolder -FolderPath "C:\Windows\LiveKernelReports" -Category "LiveKernelReports DMP" -OlderThan $CrashDumpOlderThan -Recurse

    # -----------------------------
    # Output summary
    # -----------------------------

    $TotalRemovedMB = :Round($TotalRemovedBytes / 1MB, 2)
    Write-Output "Remediation complete. Removed approximately: $TotalRemovedMB MB"

    $RemovedItems |
        Sort-Object SizeMB -Descending |
        Select-Object -First 25 |
        ForEach-Object {
            Write-Output "$($_.ProfileName) | $($_.Category) | $($_.SizeMB) MB | $($_.Path)"
        }

    if ($Errors.Count -gt 0) {
        Write-Output "Non-fatal errors encountered: $($Errors.Count)"
        $Errors | Select-Object -First 15 | ForEach-Object { Write-Output "ERROR: $_" }
    }

    exit 0
}
catch {
    Write-Output "FATAL: Remediation failed: $($_.Exception.Message)"
    exit 1
}