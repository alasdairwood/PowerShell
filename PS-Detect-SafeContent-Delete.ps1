<#
.SYNOPSIS
    Intune detection script for safe AppData + system dump cleanup.

.DESCRIPTION
    Detects user profile AppData cache/temp content and system dump files that are older than the configured thresholds.
    Also detects SCCM client cache (ccmcache) content older than the configured threshold.
    Exits 1 if cleanup is required (based on MinimumTotalSizeMB threshold).
    Exits 0 if no cleanup is required.

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

# NEW: SCCM cache detection
$DetectSccmCache          = $true
$SccmCacheOlderThanDays   = 7
$SccmCachePath            = "C:\Windows\ccmcache"

$IncludeWindowsTemp       = $true
$MinimumTotalSizeMB       = 250

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
$TotalDetectedBytes = 0
$DetectedItems = New-Object System.Collections.Generic.List[object]

# -----------------------------
# Functions
# -----------------------------

function Get-DirectorySize {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [datetime]$OlderThan
    )

    if (-not (Test-Path -LiteralPath $Path)) { return 0 }

    try {
        # Enumerate files older than threshold
        $items = Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue |
                 Where-Object { $_.LastWriteTime -lt $OlderThan }

        # Filter out reparse-point files (rare, but safe)
        $items = $items | Where-Object {
            if ($_.Attributes) { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 } else { $true }
        }

        $Size = $items | Measure-Object -Property Length -Sum
        if ($null -ne $Size.Sum) { return [int64]$Size.Sum } else { return 0 }
    }
    catch {
        return 0
    }
}

function Get-FileSize {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [datetime]$OlderThan
    )

    if (-not (Test-Path -LiteralPath $Path)) { return 0 }

    try {
        $Item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        if ($null -eq $Item -or $Item.PSIsContainer) { return 0 }

        if ($Item.LastWriteTime -lt $OlderThan) { return [int64]$Item.Length }
        return 0
    }
    catch {
        return 0
    }
}

function Add-DetectionResultDir {
    param (
        [string]$ProfileName,
        [string]$Category,
        [string]$Path,
        [datetime]$OlderThan
    )

    if (-not (Test-Path -LiteralPath $Path)) { return }

    $SizeBytes = Get-DirectorySize -Path $Path -OlderThan $OlderThan
    if ($SizeBytes -gt 0) {
        $script:TotalDetectedBytes += $SizeBytes
        $DetectedItems.Add([PSCustomObject]@{
            ProfileName = $ProfileName
            Category    = $Category
            Path        = $Path
            SizeMB      = [math]::Round($SizeBytes / 1MB, 2)
            OlderThan   = $OlderThan
        }) | Out-Null
    }
}

function Add-DetectionResultFile {
    param (
        [string]$ProfileName,
        [string]$Category,
        [string]$Path,
        [datetime]$OlderThan
    )

    if (-not (Test-Path -LiteralPath $Path)) { return }

    $SizeBytes = Get-FileSize -Path $Path -OlderThan $OlderThan
    if ($SizeBytes -gt 0) {
        $script:TotalDetectedBytes += $SizeBytes
        $DetectedItems.Add([PSCustomObject]@{
            ProfileName = $ProfileName
            Category    = $Category
            Path        = $Path
            SizeMB      = [math]::Round($SizeBytes / 1MB, 2)
            OlderThan   = $OlderThan
        }) | Out-Null
    }
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

        [PSCustomObject]@{
            ProfileName = $ProfileName
            ProfilePath = $UserProfile.LocalPath
            Loaded      = $UserProfile.Loaded
            SID         = $UserProfile.SID
        }
    }
}

function Add-DmpFilesInFolder {
    param(
        [string]$FolderPath,
        [string]$Category,
        [datetime]$OlderThan,
        [switch]$Recurse
    )

    if (-not (Test-Path -LiteralPath $FolderPath)) { return }

    try {
        $params = @{
            LiteralPath  = $FolderPath
            Filter       = "*.dmp"
            File         = $true
            Force        = $true
            ErrorAction  = "SilentlyContinue"
        }
        if ($Recurse) { $params["Recurse"] = $true }

        Get-ChildItem @params | ForEach-Object {
            Add-DetectionResultFile -ProfileName "System" -Category $Category -Path $_.FullName -OlderThan $OlderThan
        }
    }
    catch { }
}

# -----------------------------
# Detection
# -----------------------------

$TempOlderThan       = $Now.AddDays(-$TempOlderThanDays)
$CacheOlderThan      = $Now.AddDays(-$CacheOlderThanDays)
$CrashDumpOlderThan  = $Now.AddDays(-$CrashDumpOlderThanDays)

# NEW: SCCM cache threshold
$SccmCacheOlderThan  = $Now.AddDays(-$SccmCacheOlderThanDays)

$Profiles = Get-UserProfiles

foreach ($UserProfile in $Profiles) {
    $ProfileName = $UserProfile.ProfileName
    $ProfilePath = $UserProfile.ProfilePath

    # User Temp
    Add-DetectionResultDir -ProfileName $ProfileName -Category "User Temp" -Path (Join-Path $ProfilePath "AppData\Local\Temp") -OlderThan $TempOlderThan

    # Crash dumps (per-user)
    Add-DetectionResultDir -ProfileName $ProfileName -Category "Crash Dumps" -Path (Join-Path $ProfilePath "AppData\Local\CrashDumps") -OlderThan $CrashDumpOlderThan

    # Microsoft Edge cache - all profiles
    $EdgeUserData = Join-Path $ProfilePath "AppData\Local\Microsoft\Edge\User Data"
    if (Test-Path -LiteralPath $EdgeUserData) {
        Get-ChildItem -LiteralPath $EdgeUserData -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match "^(Default|Profile \d+|Guest Profile)$" } |
            ForEach-Object {
                Add-DetectionResultDir -ProfileName $ProfileName -Category "Edge Cache" -Path (Join-Path $_.FullName "Cache") -OlderThan $CacheOlderThan
                Add-DetectionResultDir -ProfileName $ProfileName -Category "Edge Code Cache" -Path (Join-Path $_.FullName "Code Cache") -OlderThan $CacheOlderThan
                Add-DetectionResultDir -ProfileName $ProfileName -Category "Edge GPU Cache" -Path (Join-Path $_.FullName "GPUCache") -OlderThan $CacheOlderThan
                Add-DetectionResultDir -ProfileName $ProfileName -Category "Edge Service Worker Cache" -Path (Join-Path $_.FullName "Service Worker\CacheStorage") -OlderThan $CacheOlderThan
            }
    }

    # Google Chrome cache - all profiles
    $ChromeUserData = Join-Path $ProfilePath "AppData\Local\Google\Chrome\User Data"
    if (Test-Path -LiteralPath $ChromeUserData) {
        Get-ChildItem -LiteralPath $ChromeUserData -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match "^(Default|Profile \d+|Guest Profile)$" } |
            ForEach-Object {
                Add-DetectionResultDir -ProfileName $ProfileName -Category "Chrome Cache" -Path (Join-Path $_.FullName "Cache") -OlderThan $CacheOlderThan
                Add-DetectionResultDir -ProfileName $ProfileName -Category "Chrome Code Cache" -Path (Join-Path $_.FullName "Code Cache") -OlderThan $CacheOlderThan
                Add-DetectionResultDir -ProfileName $ProfileName -Category "Chrome GPU Cache" -Path (Join-Path $_.FullName "GPUCache") -OlderThan $CacheOlderThan
                Add-DetectionResultDir -ProfileName $ProfileName -Category "Chrome Service Worker Cache" -Path (Join-Path $_.FullName "Service Worker\CacheStorage") -OlderThan $CacheOlderThan
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
    foreach ($TeamsPath in $TeamsClassicPaths) {
        Add-DetectionResultDir -ProfileName $ProfileName -Category "Teams Classic Cache" -Path $TeamsPath -OlderThan $CacheOlderThan
    }

    # New Teams cache
    $NewTeamsBase = Join-Path $ProfilePath "AppData\Local\Packages\MSTeams_8wekyb3d8bbwe"
    $NewTeamsPaths = @(
        (Join-Path $NewTeamsBase "LocalCache\Microsoft\MSTeams\Cache"),
        (Join-Path $NewTeamsBase "LocalCache\Microsoft\MSTeams\Code Cache"),
        (Join-Path $NewTeamsBase "LocalCache\Microsoft\MSTeams\GPUCache"),
        (Join-Path $NewTeamsBase "LocalCache\Microsoft\MSTeams\Service Worker\CacheStorage"),
        (Join-Path $NewTeamsBase "TempState")
    )
    foreach ($NewTeamsPath in $NewTeamsPaths) {
        Add-DetectionResultDir -ProfileName $ProfileName -Category "New Teams Cache" -Path $NewTeamsPath -OlderThan $CacheOlderThan
    }

    # Explorer thumbnail/icon cache
    Add-DetectionResultDir -ProfileName $ProfileName -Category "Explorer Cache" -Path (Join-Path $ProfilePath "AppData\Local\Microsoft\Windows\Explorer") -OlderThan $CacheOlderThan
}

# Windows Temp
if ($IncludeWindowsTemp) {
    Add-DetectionResultDir -ProfileName "System" -Category "Windows Temp" -Path "C:\Windows\Temp" -OlderThan $TempOlderThan
}

# -----------------------------
# NEW: SCCM Cache (ccmcache)
# -----------------------------
if ($DetectSccmCache) {
    Add-DetectionResultDir -ProfileName "System" -Category "SCCM CCMCache" -Path $SccmCachePath -OlderThan $SccmCacheOlderThan
}

# -----------------------------
# System Dump Files (Windows + LiveKernelReports)
# -----------------------------

# Full memory dump
Add-DetectionResultFile -ProfileName "System" -Category "Windows MEMORY.DMP" -Path "C:\Windows\MEMORY.DMP" -OlderThan $CrashDumpOlderThan

# Minidumps folder
Add-DetectionResultDir -ProfileName "System" -Category "Windows Minidumps" -Path "C:\Windows\Minidump" -OlderThan $CrashDumpOlderThan

# Any *.dmp directly under C:\Windows
Add-DmpFilesInFolder -FolderPath "C:\Windows" -Category "Windows DMP (root)" -OlderThan $CrashDumpOlderThan

# LiveKernelReports dumps (recursive)
$LiveKernelBase = "C:\Windows\LiveKernelReports"
Add-DmpFilesInFolder -FolderPath $LiveKernelBase -Category "LiveKernelReports DMP" -OlderThan $CrashDumpOlderThan -Recurse

# -----------------------------
# Output + Exit Codes
# -----------------------------

$TotalDetectedMB = [math]::Round($TotalDetectedBytes / 1MB, 2)

Write-Output "Detected reclaimable cache/dump size: $TotalDetectedMB MB"
$DetectedItems |
    Sort-Object SizeMB -Descending |
    Select-Object -First 25 |
    ForEach-Object {
        Write-Output "$($_.ProfileName) | $($_.Category) | $($_.SizeMB) MB | $($_.Path)"
    }

if ($TotalDetectedMB -ge $MinimumTotalSizeMB) {
    Write-Output "Cleanup required. Detected size is >= threshold of $MinimumTotalSizeMB MB."
    exit 1
}
else {
    Write-Output "No cleanup required. Detected size is below threshold of $MinimumTotalSizeMB MB."
    exit 0
}