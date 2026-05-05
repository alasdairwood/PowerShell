<#
.SYNOPSIS
    Intune detection script for safe AppData disk cleanup.

.DESCRIPTION
    Detects user profile AppData cache/temp content that is older than the configured age threshold.
    Exits 1 if cleanup is required.
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

    if (-not (Test-Path -LiteralPath $Path)) {
        return 0
    }

    try {
        $Size = Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt $OlderThan } |
            Measure-Object -Property Length -Sum

        if ($null -ne $Size.Sum) {
            return [int64]$Size.Sum
        }
        else {
            return 0
        }
    }
    catch {
        return 0
    }
}

function Add-DetectionResult {
    param (
        [string]$ProfileName,
        [string]$Category,
        [string]$Path,
        [datetime]$OlderThan
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

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

function Get-UserProfiles {
    $Profiles = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue |
        Where-Object {
            $_.LocalPath -like "C:\Users\*" -and
            $_.Special -eq $false -and
            $_.LocalPath -and
            (Test-Path -LiteralPath $_.LocalPath)
        }

    foreach ($Profile in $Profiles) {
        $ProfileName = Split-Path -Path $Profile.LocalPath -Leaf

        if ($ExcludedProfileNames -contains $ProfileName) {
            continue
        }

        [PSCustomObject]@{
            ProfileName = $ProfileName
            ProfilePath = $Profile.LocalPath
            Loaded      = $Profile.Loaded
            SID         = $Profile.SID
        }
    }
}

# -----------------------------
# Detection
# -----------------------------

$TempOlderThan      = $Now.AddDays(-$TempOlderThanDays)
$CacheOlderThan     = $Now.AddDays(-$CacheOlderThanDays)
$CrashDumpOlderThan = $Now.AddDays(-$CrashDumpOlderThanDays)

$Profiles = Get-UserProfiles

foreach ($Profile in $Profiles) {
    $ProfileName = $Profile.ProfileName
    $ProfilePath = $Profile.ProfilePath

    # User Temp
    Add-DetectionResult -ProfileName $ProfileName -Category "User Temp" -Path "$ProfilePath\AppData\Local\Temp" -OlderThan $TempOlderThan

    # Crash dumps
    Add-DetectionResult -ProfileName $ProfileName -Category "Crash Dumps" -Path "$ProfilePath\AppData\Local\CrashDumps" -OlderThan $CrashDumpOlderThan

    # Microsoft Edge cache - all profiles
    $EdgeUserData = "$ProfilePath\AppData\Local\Microsoft\Edge\User Data"
    if (Test-Path -LiteralPath $EdgeUserData) {
        Get-ChildItem -LiteralPath $EdgeUserData -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match "^(Default|Profile \d+|Guest Profile)$" } |
            ForEach-Object {
                Add-DetectionResult -ProfileName $ProfileName -Category "Edge Cache" -Path "$($_.FullName)\Cache" -OlderThan $CacheOlderThan
                Add-DetectionResult -ProfileName $ProfileName -Category "Edge Code Cache" -Path "$($_.FullName)\Code Cache" -OlderThan $CacheOlderThan
                Add-DetectionResult -ProfileName $ProfileName -Category "Edge GPU Cache" -Path "$($_.FullName)\GPUCache" -OlderThan $CacheOlderThan
                Add-DetectionResult -ProfileName $ProfileName -Category "Edge Service Worker Cache" -Path "$($_.FullName)\Service Worker\CacheStorage" -OlderThan $CacheOlderThan
            }
    }

    # Google Chrome cache - all profiles
    $ChromeUserData = "$ProfilePath\AppData\Local\Google\Chrome\User Data"
    if (Test-Path -LiteralPath $ChromeUserData) {
        Get-ChildItem -LiteralPath $ChromeUserData -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match "^(Default|Profile \d+|Guest Profile)$" } |
            ForEach-Object {
                Add-DetectionResult -ProfileName $ProfileName -Category "Chrome Cache" -Path "$($_.FullName)\Cache" -OlderThan $CacheOlderThan
                Add-DetectionResult -ProfileName $ProfileName -Category "Chrome Code Cache" -Path "$($_.FullName)\Code Cache" -OlderThan $CacheOlderThan
                Add-DetectionResult -ProfileName $ProfileName -Category "Chrome GPU Cache" -Path "$($_.FullName)\GPUCache" -OlderThan $CacheOlderThan
                Add-DetectionResult -ProfileName $ProfileName -Category "Chrome Service Worker Cache" -Path "$($_.FullName)\Service Worker\CacheStorage" -OlderThan $CacheOlderThan
            }
    }

    # Teams classic cache
    $TeamsClassicPaths = @(
        "$ProfilePath\AppData\Roaming\Microsoft\Teams\Cache",
        "$ProfilePath\AppData\Roaming\Microsoft\Teams\Code Cache",
        "$ProfilePath\AppData\Roaming\Microsoft\Teams\GPUCache",
        "$ProfilePath\AppData\Roaming\Microsoft\Teams\IndexedDB",
        "$ProfilePath\AppData\Roaming\Microsoft\Teams\Local Storage",
        "$ProfilePath\AppData\Roaming\Microsoft\Teams\tmp",
        "$ProfilePath\AppData\Local\Microsoft\Teams\Cache",
        "$ProfilePath\AppData\Local\Microsoft\Teams\Code Cache",
        "$ProfilePath\AppData\Local\Microsoft\Teams\GPUCache",
        "$ProfilePath\AppData\Local\Microsoft\Teams\tmp"
    )

    foreach ($TeamsPath in $TeamsClassicPaths) {
        Add-DetectionResult -ProfileName $ProfileName -Category "Teams Classic Cache" -Path $TeamsPath -OlderThan $CacheOlderThan
    }

    # New Teams cache
    $NewTeamsBase = "$ProfilePath\AppData\Local\Packages\MSTeams_8wekyb3d8bbwe"
    $NewTeamsPaths = @(
        "$NewTeamsBase\LocalCache\Microsoft\MSTeams\Cache",
        "$NewTeamsBase\LocalCache\Microsoft\MSTeams\Code Cache",
        "$NewTeamsBase\LocalCache\Microsoft\MSTeams\GPUCache",
        "$NewTeamsBase\LocalCache\Microsoft\MSTeams\Service Worker\CacheStorage",
        "$NewTeamsBase\TempState"
    )

    foreach ($NewTeamsPath in $NewTeamsPaths) {
        Add-DetectionResult -ProfileName $ProfileName -Category "New Teams Cache" -Path $NewTeamsPath -OlderThan $CacheOlderThan
    }

    # Explorer thumbnail/icon cache
    Add-DetectionResult -ProfileName $ProfileName -Category "Explorer Cache" -Path "$ProfilePath\AppData\Local\Microsoft\Windows\Explorer" -OlderThan $CacheOlderThan
}

# Windows Temp
if ($IncludeWindowsTemp -eq $true) {
    Add-DetectionResult -ProfileName "System" -Category "Windows Temp" -Path "C:\Windows\Temp" -OlderThan $TempOlderThan
}

$TotalDetectedMB = [math]::Round($TotalDetectedBytes / 1MB, 2)

Write-Output "Detected reclaimable AppData/system cache size: $TotalDetectedMB MB"

$DetectedItems |
    Sort-Object SizeMB -Descending |
    Select-Object -First 25 |
    ForEach-Object {
        Write-Output "$($_.ProfileName) | $($_.Category) | $($_.SizeMB) MB | $($_.Path)"
    }

if ($TotalDetectedMB -ge $MinimumTotalSizeMB) {
    Write-Output "Cleanup required. Detected size is greater than or equal to threshold of $MinimumTotalSizeMB MB."
    exit 1
}
else {
    Write-Output "No cleanup required. Detected size is below threshold of $MinimumTotalSizeMB MB."
    exit 0
}