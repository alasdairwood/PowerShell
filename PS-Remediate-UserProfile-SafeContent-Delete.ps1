
<#
.SYNOPSIS
    Intune remediation script for safe AppData + system dump cleanup.

.DESCRIPTION
    Removes user profile AppData cache/temp content and system dump files that are older than the configured thresholds.
    Designed to match the detection script logic as closely as possible.

.NOTES
    Designed for Microsoft Intune Remediations.
    Run as 64-bit PowerShell.
    Recommended to run using system context.
#>

# -----------------------------
# Configuration (match Detection)
# -----------------------------

$TempOlderThanDays        = 1
$CacheOlderThanDays       = 7
$CrashDumpOlderThanDays   = 7
$IncludeWindowsTemp       = $true

# Optional: attempt to remove empty folders after deleting old files
$RemoveEmptyDirectories   = $true

$ExcludedProfileNames = @(
    "Public",
    "Default",
    "Default User",
    "All Users",
    "WDAGUtilityAccount",
    "defaultuser0"
)

# -----------------------------
# Variables
# -----------------------------

$Now = Get-Date
$TotalFreedBytes = 0
$TotalRemovedFiles = 0
$TotalFailedRemovals = 0

$Actions = New-Object System.Collections.Generic.List[object]

# -----------------------------
# Functions
# -----------------------------

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

    if (-not (Test-Path -LiteralPath $Path)) { return }

    try {
        $gciParams = @{
            LiteralPath = $Path
            Force       = $true
            ErrorAction = "SilentlyContinue"
            File        = $true
            Filter      = $Filter
        }
        if ($Recurse) { $gciParams["Recurse"] = $true }

        $files = Get-ChildItem @gciParams | Where-Object { $_.LastWriteTime -lt $OlderThan }

        # Avoid reparse points if possible
        $files = $files | Where-Object {
            if ($_.Attributes) { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 } else { $true }
        }

        foreach ($f in $files) {
            try {
                $len = [int64]$f.Length
                Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop

                $script:TotalFreedBytes += $len
                $script:TotalRemovedFiles++

                $Actions.Add([PSCustomObject]@{
                    Category = $Category
                    Path     = $f.FullName
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
                if ($Recurse) { $dirParams["Recurse"] = $true }

                # Remove empty directories bottom-up
                Get-ChildItem @dirParams |
                    Sort-Object FullName -Descending |
                    ForEach-Object {
                        try {
                            $hasChildren = Get-ChildItem -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue | Select-Object -First 1
                            if (-not $hasChildren) {
                                Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue
                            }
                        } catch { }
                    }
            } catch { }
        }
    }
    catch {
        # swallow and continue
    }
}

function Remove-OldFile {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [datetime]$OlderThan,

        [string]$Category = "Cleanup"
    )

    if (-not (Test-Path -LiteralPath $Path)) { return }

    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        if ($null -eq $item -or $item.PSIsContainer) { return }

        if ($item.LastWriteTime -lt $OlderThan) {
            try {
                $len = [int64]$item.Length
                Remove-Item -LiteralPath $item.FullName -Force -ErrorAction Stop

                $script:TotalFreedBytes += $len
                $script:TotalRemovedFiles++

                $Actions.Add([PSCustomObject]@{
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
    catch {
        # swallow and continue
    }
}

# -----------------------------
# Remediation
# -----------------------------

$TempOlderThan      = $Now.AddDays(-$TempOlderThanDays)
$CacheOlderThan     = $Now.AddDays(-$CacheOlderThanDays)
$CrashDumpOlderThan = $Now.AddDays(-$CrashDumpOlderThanDays)

$Profiles = Get-UserProfiles

foreach ($UserProfile in $Profiles) {
    $ProfileName = $UserProfile.ProfileName
    $ProfilePath = $UserProfile.ProfilePath

    # User Temp
    Remove-OldFilesInDirectory -Path (Join-Path $ProfilePath "AppData\Local\Temp") -OlderThan $TempOlderThan -Category "$ProfileName | User Temp" -Recurse

    # Per-user crash dumps
    Remove-OldFilesInDirectory -Path (Join-Path $ProfilePath "AppData\Local\CrashDumps") -OlderThan $CrashDumpOlderThan -Category "$ProfileName | Crash Dumps" -Recurse

    # Edge cache (all profiles)
    $EdgeUserData = Join-Path $ProfilePath "AppData\Local\Microsoft\Edge\User Data"
    if (Test-Path -LiteralPath $EdgeUserData) {
        Get-ChildItem -LiteralPath $EdgeUserData -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match "^(Default|Profile \d+|Guest Profile)$" } |
            ForEach-Object {
                Remove-OldFilesInDirectory -Path (Join-Path $_.FullName "Cache") -OlderThan $CacheOlderThan -Category "$ProfileName | Edge Cache" -Recurse
                Remove-OldFilesInDirectory -Path (Join-Path $_.FullName "Code Cache") -OlderThan $CacheOlderThan -Category "$ProfileName | Edge Code Cache" -Recurse
                Remove-OldFilesInDirectory -Path (Join-Path $_.FullName "GPUCache") -OlderThan $CacheOlderThan -Category "$ProfileName | Edge GPU Cache" -Recurse
                Remove-OldFilesInDirectory -Path (Join-Path $_.FullName "Service Worker\CacheStorage") -OlderThan $CacheOlderThan -Category "$ProfileName | Edge SW CacheStorage" -Recurse
            }
    }

    # Chrome cache (all profiles)
    $ChromeUserData = Join-Path $ProfilePath "AppData\Local\Google\Chrome\User Data"
    if (Test-Path -LiteralPath $ChromeUserData) {
        Get-ChildItem -LiteralPath $ChromeUserData -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match "^(Default|Profile \d+|Guest Profile)$" } |
            ForEach-Object {
                Remove-OldFilesInDirectory -Path (Join-Path $_.FullName "Cache") -OlderThan $CacheOlderThan -Category "$ProfileName | Chrome Cache" -Recurse
                Remove-OldFilesInDirectory -Path (Join-Path $_.FullName "Code Cache") -OlderThan $CacheOlderThan -Category "$ProfileName | Chrome Code Cache" -Recurse
                Remove-OldFilesInDirectory -Path (Join-Path $_.FullName "GPUCache") -OlderThan $CacheOlderThan -Category "$ProfileName | Chrome GPU Cache" -Recurse
                Remove-OldFilesInDirectory -Path (Join-Path $_.FullName "Service Worker\CacheStorage") -OlderThan $CacheOlderThan -Category "$ProfileName | Chrome SW CacheStorage" -Recurse
            }
    }

    # Teams classic cache paths
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
        Remove-OldFilesInDirectory -Path $p -OlderThan $CacheOlderThan -Category "$ProfileName | Teams Classic" -Recurse
    }

    # New Teams cache (Store app)
    $NewTeamsBase = Join-Path $ProfilePath "AppData\Local\Packages\MSTeams_8wekyb3d8bbwe"
    $NewTeamsPaths = @(
        (Join-Path $NewTeamsBase "LocalCache\Microsoft\MSTeams\Cache"),
        (Join-Path $NewTeamsBase "LocalCache\Microsoft\MSTeams\Code Cache"),
        (Join-Path $NewTeamsBase "LocalCache\Microsoft\MSTeams\GPUCache"),
        (Join-Path $NewTeamsBase "LocalCache\Microsoft\MSTeams\Service Worker\CacheStorage"),
        (Join-Path $NewTeamsBase "TempState")
    )
    foreach ($p in $NewTeamsPaths) {
        Remove-OldFilesInDirectory -Path $p -OlderThan $CacheOlderThan -Category "$ProfileName | New Teams" -Recurse
    }

    # Explorer cache
    Remove-OldFilesInDirectory -Path (Join-Path $ProfilePath "AppData\Local\Microsoft\Windows\Explorer") -OlderThan $CacheOlderThan -Category "$ProfileName | Explorer Cache" -Recurse
}

# Windows Temp
if ($IncludeWindowsTemp) {
    Remove-OldFilesInDirectory -Path "C:\Windows\Temp" -OlderThan $TempOlderThan -Category "System | Windows Temp" -Recurse
}

# -----------------------------
# System Dump Files (Windows + LiveKernelReports)
# -----------------------------

# C:\Windows\MEMORY.DMP
Remove-OldFile -Path "C:\Windows\MEMORY.DMP" -OlderThan $CrashDumpOlderThan -Category "System | MEMORY.DMP"

# C:\Windows\Minidump\*.dmp
Remove-OldFilesInDirectory -Path "C:\Windows\Minidump" -OlderThan $CrashDumpOlderThan -Category "System | Minidumps" -Recurse -Filter "*.dmp"

# Any *.dmp directly under C:\Windows
Remove-OldFilesInDirectory -Path "C:\Windows" -OlderThan $CrashDumpOlderThan -Category "System | Windows DMP (root)" -Filter "*.dmp"

# LiveKernelReports recursive *.dmp
$LiveKernelBase = "C:\Windows\LiveKernelReports"
Remove-OldFilesInDirectory -Path $LiveKernelBase -OlderThan $CrashDumpOlderThan -Category "System | LiveKernelReports DMP" -Recurse -Filter "*.dmp"

# -----------------------------
# Output + Exit Code
# -----------------------------

$FreedMB = [math]::Round($TotalFreedBytes / 1MB, 2)

Write-Output "Remediation complete."
Write-Output "Total freed: $FreedMB MB"
Write-Output "Files removed: $TotalRemovedFiles"
Write-Output "Failed removals (likely locked/in use): $TotalFailedRemovals"

# Show top 25 largest removals (if any)
$Actions |
    Sort-Object FreedMB -Descending |
    Select-Object -First 25 |
    ForEach-Object {
        Write-Output "$($_.Category) | $($_.FreedMB) MB | $($_.Path)"
    }

exit 0
