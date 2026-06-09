<#
.SYNOPSIS
    Intune remediation script for safe AppData + system dump cleanup.

.DESCRIPTION
    Removes user profile AppData cache/temp content and system dump files
    older than configured thresholds.

    Enterprise hardened:
    - Safer for active users
    - Runtime protected
    - Lower memory usage
    - Reduced lock contention
    - Transcript logging support
    - Teams cleanup support
    - Delivery Optimization cleanup
    - SCCM cache cleanup
    - Recycle Bin cleanup
    - Intune-friendly reporting

.NOTES
    Designed for Microsoft Intune Remediations.
    Run as 64-bit PowerShell.
    Recommended to run using SYSTEM context.
#>

# -----------------------------
# Configuration
# -----------------------------

# User temp retention
$UserTempOlderThanDays = 1

# System temp retention
$SystemTempOlderThanDays = 3

# Browser / Teams cache retention
$CacheOlderThanDays = 7

# Crash dump retention
$CrashDumpOlderThanDays = 7

# SCCM cache retention
$SCCMCacheOlderThanDays = 7

# Include Windows Temp cleanup
$IncludeWindowsTemp = $true

# Include Recycle Bin cleanup
$IncludeRecycleBinCleanup = $true

# Skip browser / Teams cleanup for active users
$SkipLoadedProfilesForCacheCleanup = $true

# Remove empty directories after cleanup
$RemoveEmptyDirectories = $true

# Runtime protection
$script:MaxRuntimeMinutes = 25

# Transcript logging
$EnableTranscript = $true
$TranscriptPath = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\AppDataCleanup.log"

# Excluded profile names
$ExcludedProfileNames = @(
    "Public",
    "Default",
    "Default User",
    "All Users",
    "WDAGUtilityAccount",
    "defaultuser0"
)

# Optional path exclusions
$ExcludedPathPatterns = @(
    "*OneDrive*",
    "*FSLogix*",
    "*Citrix*",
    "*VMware*"
)

# -----------------------------
# Variables
# -----------------------------

$Now = Get-Date
$script:ScriptStart = Get-Date

$TotalFreedBytes = 0
$TotalRemovedFiles = 0
$TotalFailedRemovals = 0

$Actions = New-Object System.Collections.Generic.List[object]

# -----------------------------
# Logging
# -----------------------------

if ($EnableTranscript) {

    try {

        $TranscriptFolder = Split-Path $TranscriptPath -Parent

        if (-not (Test-Path $TranscriptFolder)) {

            New-Item `
                -Path $TranscriptFolder `
                -ItemType Directory `
                -Force | Out-Null
        }

        Start-Transcript `
            -Path $TranscriptPath `
            -Append `
            -ErrorAction SilentlyContinue
    }
    catch { }
}

# -----------------------------
# Functions
# -----------------------------

function Test-RuntimeExceeded {

    return (((Get-Date) - $script:ScriptStart).TotalMinutes -ge $script:MaxRuntimeMinutes)
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

        if ($ExcludedProfileNames -contains $ProfileName) {
            continue
        }

        $SkipProfile = $false

        foreach ($Pattern in $ExcludedPathPatterns) {

            if ($UserProfile.LocalPath -like $Pattern) {

                $SkipProfile = $true
                break
            }
        }

        if ($SkipProfile) {
            continue
        }

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
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [datetime]$OlderThan,

        [string]$Category = "Cleanup",

        [switch]$Recurse,

        [string]$Filter = "*"
    )

    if (Test-RuntimeExceeded) {

        Write-Output "Maximum runtime reached. Stopping cleanup safely."
        return
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    try {

        $gciParams = @{
            LiteralPath = $Path
            Force       = $true
            ErrorAction = "SilentlyContinue"
            File        = $true
            Filter      = $Filter
        }

        if ($Recurse) {
            $gciParams["Recurse"] = $true
        }

        Get-ChildItem @gciParams |

            Where-Object {

                -not ($_.Attributes -band [IO.FileAttributes]::System)
            } |

            ForEach-Object {

                if (Test-RuntimeExceeded) {
                    return
                }

                try {

                    if (($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                        return
                    }

                    if ($_.LastWriteTime -ge $OlderThan) {
                        return
                    }

                    $len = [int64]$_.Length

                    Remove-Item `
                        -LiteralPath $_.FullName `
                        -Force `
                        -ErrorAction Stop

                    $script:TotalFreedBytes += $len
                    $script:TotalRemovedFiles++

                    $script:Actions.Add([PSCustomObject]@{
                        Category = $Category
                        Path     = $_.FullName
                        FreedMB  = [math]::Round($len / 1MB, 2)
                    }) | Out-Null
                }
                catch {
                    $script:TotalFailedRemovals++
                }
            }

        if ($RemoveEmptyDirectories) {

            try {

                $dirParams = @{
                    LiteralPath = $Path
                    Force       = $true
                    ErrorAction = "SilentlyContinue"
                    Directory   = $true
                }

                if ($Recurse) {
                    $dirParams["Recurse"] = $true
                }

                Get-ChildItem @dirParams |

                    Sort-Object FullName -Descending |

                    ForEach-Object {

                        try {

                            $child = Get-ChildItem `
                                -LiteralPath $_.FullName `
                                -Force `
                                -ErrorAction SilentlyContinue |
                                Select-Object -First 1

                            if (-not $child) {

                                Remove-Item `
                                    -LiteralPath $_.FullName `
                                    -Force `
                                    -ErrorAction SilentlyContinue
                            }
                        }
                        catch { }
                    }
            }
            catch { }
        }
    }
    catch { }
}

function Remove-OldFile {

    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [datetime]$OlderThan,

        [string]$Category = "Cleanup"
    )

    if (Test-RuntimeExceeded) {
        return
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    try {

        $item = Get-Item `
            -LiteralPath $Path `
            -Force `
            -ErrorAction SilentlyContinue

        if ($null -eq $item -or $item.PSIsContainer) {
            return
        }

        if ($item.LastWriteTime -lt $OlderThan) {

            try {

                $len = [int64]$item.Length

                Remove-Item `
                    -LiteralPath $item.FullName `
                    -Force `
                    -ErrorAction Stop

                $script:TotalFreedBytes += $len
                $script:TotalRemovedFiles++

                $script:Actions.Add([PSCustomObject]@{
                    Category = $Category
                    Path     = $item.FullName
                    FreedMB  = [math]::Round($len / 1MB, 2)
                }) | Out-Null
            }
            catch {
                $script:TotalFailedRemovals++
            }
        }
    }
    catch { }
}

# -----------------------------
# Date Thresholds
# -----------------------------

$UserTempOlderThan   = $Now.AddDays(-$UserTempOlderThanDays)
$SystemTempOlderThan = $Now.AddDays(-$SystemTempOlderThanDays)
$CacheOlderThan      = $Now.AddDays(-$CacheOlderThanDays)
$CrashDumpOlderThan  = $Now.AddDays(-$CrashDumpOlderThanDays)
$SCCMCacheOlderThan  = $Now.AddDays(-$SCCMCacheOlderThanDays)

# -----------------------------
# User Profile Cleanup
# -----------------------------

$Profiles = Get-UserProfiles

foreach ($UserProfile in $Profiles) {

    if (Test-RuntimeExceeded) {
        break
    }

    $ProfileName = $UserProfile.ProfileName
    $ProfilePath = $UserProfile.ProfilePath
    $IsLoaded    = $UserProfile.Loaded

    Write-Output "Processing profile: $ProfileName"

    # User Temp
    Remove-OldFilesInDirectory `
        -Path (Join-Path $ProfilePath "AppData\Local\Temp") `
        -OlderThan $UserTempOlderThan `
        -Category "$ProfileName | User Temp" `
        -Recurse

    # Crash Dumps
    Remove-OldFilesInDirectory `
        -Path (Join-Path $ProfilePath "AppData\Local\CrashDumps") `
        -OlderThan $CrashDumpOlderThan `
        -Category "$ProfileName | Crash Dumps" `
        -Recurse

    # Skip cache cleanup for loaded profiles
    if ($SkipLoadedProfilesForCacheCleanup -and $IsLoaded) {

        Write-Output "Skipping browser/Teams cache cleanup for loaded profile: $ProfileName"
        continue
    }

    # Edge Cache
    $EdgeUserData = Join-Path $ProfilePath "AppData\Local\Microsoft\Edge\User Data"

    if (Test-Path -LiteralPath $EdgeUserData) {

        Get-ChildItem `
            -LiteralPath $EdgeUserData `
            -Directory `
            -Force `
            -ErrorAction SilentlyContinue |

            Where-Object {
                $_.Name -match "^(Default|Profile \d+|Guest Profile)$"
            } |

            ForEach-Object {

                Remove-OldFilesInDirectory `
                    -Path (Join-Path $_.FullName "Cache") `
                    -OlderThan $CacheOlderThan `
                    -Category "$ProfileName | Edge Cache" `
                    -Recurse

                Remove-OldFilesInDirectory `
                    -Path (Join-Path $_.FullName "Code Cache") `
                    -OlderThan $CacheOlderThan `
                    -Category "$ProfileName | Edge Code Cache" `
                    -Recurse

                Remove-OldFilesInDirectory `
                    -Path (Join-Path $_.FullName "GPUCache") `
                    -OlderThan $CacheOlderThan `
                    -Category "$ProfileName | Edge GPU Cache" `
                    -Recurse
            }
    }

    # Chrome Cache
    $ChromeUserData = Join-Path $ProfilePath "AppData\Local\Google\Chrome\User Data"

    if (Test-Path -LiteralPath $ChromeUserData) {

        Get-ChildItem `
            -LiteralPath $ChromeUserData `
            -Directory `
            -Force `
            -ErrorAction SilentlyContinue |

            Where-Object {
                $_.Name -match "^(Default|Profile \d+|Guest Profile)$"
            } |

            ForEach-Object {

                Remove-OldFilesInDirectory `
                    -Path (Join-Path $_.FullName "Cache") `
                    -OlderThan $CacheOlderThan `
                    -Category "$ProfileName | Chrome Cache" `
                    -Recurse

                Remove-OldFilesInDirectory `
                    -Path (Join-Path $_.FullName "Code Cache") `
                    -OlderThan $CacheOlderThan `
                    -Category "$ProfileName | Chrome Code Cache" `
                    -Recurse

                Remove-OldFilesInDirectory `
                    -Path (Join-Path $_.FullName "GPUCache") `
                    -OlderThan $CacheOlderThan `
                    -Category "$ProfileName | Chrome GPU Cache" `
                    -Recurse
            }
    }

    # Teams Cache
    Remove-OldFilesInDirectory `
        -Path (Join-Path $ProfilePath "AppData\Roaming\Microsoft\Teams") `
        -OlderThan $CacheOlderThan `
        -Category "$ProfileName | Teams Classic Cache" `
        -Recurse

    Remove-OldFilesInDirectory `
        -Path (Join-Path $ProfilePath "AppData\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache") `
        -OlderThan $CacheOlderThan `
        -Category "$ProfileName | Teams New Cache" `
        -Recurse

    # Explorer Thumbnail Cache
    Remove-OldFilesInDirectory `
        -Path (Join-Path $ProfilePath "AppData\Local\Microsoft\Windows\Explorer") `
        -OlderThan $CacheOlderThan `
        -Category "$ProfileName | Explorer Thumbnail Cache" `
        -Filter "thumbcache*.db"
}

# -----------------------------
# Windows Temp
# -----------------------------

if ($IncludeWindowsTemp) {

    Remove-OldFilesInDirectory `
        -Path "C:\Windows\Temp" `
        -OlderThan $SystemTempOlderThan `
        -Category "System | Windows Temp" `
        -Recurse
}

# -----------------------------
# Delivery Optimization Cache
# -----------------------------

Remove-OldFilesInDirectory `
    -Path "C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache" `
    -OlderThan $SystemTempOlderThan `
    -Category "System | Delivery Optimization Cache" `
    -Recurse

# -----------------------------
# SCCM Client Cache Cleanup
# -----------------------------

try {

    $CCMCachePath = "C:\Windows\ccmcache"

    if (Test-Path -LiteralPath $CCMCachePath) {

        Write-Output "Processing SCCM cache cleanup..."

        Get-ChildItem `
            -LiteralPath $CCMCachePath `
            -Directory `
            -Force `
            -ErrorAction SilentlyContinue |

            ForEach-Object {

                if (Test-RuntimeExceeded) {
                    return
                }

                try {

                    $NewestItem = Get-ChildItem `
                        -LiteralPath $_.FullName `
                        -Recurse `
                        -Force `
                        -ErrorAction SilentlyContinue |

                        Sort-Object LastWriteTime -Descending |

                        Select-Object -First 1

                    if ($NewestItem -and $NewestItem.LastWriteTime -ge $SCCMCacheOlderThan) {
                        return
                    }

                    $FolderSize = (
                        Get-ChildItem `
                            -LiteralPath $_.FullName `
                            -Recurse `
                            -Force `
                            -File `
                            -ErrorAction SilentlyContinue |

                            Measure-Object Length -Sum
                    ).Sum

                    Remove-Item `
                        -LiteralPath $_.FullName `
                        -Recurse `
                        -Force `
                        -ErrorAction Stop

                    $script:TotalFreedBytes += [int64]$FolderSize
                    $script:TotalRemovedFiles++

                    $script:Actions.Add([PSCustomObject]@{
                        Category = "System | SCCM Cache"
                        Path     = $_.FullName
                        FreedMB  = [math]::Round($FolderSize / 1MB, 2)
                    }) | Out-Null

                    Write-Output "Removed SCCM cache folder: $($_.FullName)"
                }
                catch {

                    $script:TotalFailedRemovals++

                    Write-Output "Failed to remove SCCM cache folder: $($_.FullName)"
                }
            }
    }
}
catch {

    Write-Output "SCCM cache cleanup encountered an error."
}

# -----------------------------
# System Dump Files
# -----------------------------

Remove-OldFile `
    -Path "C:\Windows\MEMORY.DMP" `
    -OlderThan $CrashDumpOlderThan `
    -Category "System | MEMORY.DMP"

Remove-OldFilesInDirectory `
    -Path "C:\Windows\Minidump" `
    -OlderThan $CrashDumpOlderThan `
    -Category "System | Minidumps" `
    -Recurse `
    -Filter "*.dmp"

Remove-OldFilesInDirectory `
    -Path "C:\Windows\LiveKernelReports" `
    -OlderThan $CrashDumpOlderThan `
    -Category "System | LiveKernelReports" `
    -Recurse `
    -Filter "*.dmp"

# -----------------------------
# Recycle Bin Cleanup
# -----------------------------

if ($IncludeRecycleBinCleanup) {

    try {

        Clear-RecycleBin `
            -Force `
            -ErrorAction SilentlyContinue

        Write-Output "Recycle Bin cleanup completed."
    }
    catch {

        Write-Output "Recycle Bin cleanup skipped."
    }
}

# -----------------------------
# Results
# -----------------------------

$FreedMB = [math]::Round($TotalFreedBytes / 1MB, 2)

Write-Output ""
Write-Output "Cleanup completed."
Write-Output "Total freed: $FreedMB MB"
Write-Output "Files removed: $TotalRemovedFiles"
Write-Output "Failed removals: $TotalFailedRemovals"

Write-Output ""
Write-Output "Top cleanup items:"

$Actions |

    Sort-Object FreedMB -Descending |

    Select-Object -First 25 |

    ForEach-Object {

        Write-Output "$($_.Category) | $($_.FreedMB) MB | $($_.Path)"
    }

Write-Output ""
Write-Output "RESULT: FreedMB=$FreedMB RemovedFiles=$TotalRemovedFiles Failed=$TotalFailedRemovals"

# -----------------------------
# Cleanup
# -----------------------------

if ($EnableTranscript) {

    try {
        Stop-Transcript | Out-Null
    }
    catch { }
}

exit 0