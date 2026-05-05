<#
.SYNOPSIS
    Intune remediation script for safe AppData disk cleanup.

.DESCRIPTION
    Removes safe cache/temp content from user profile AppData locations.
    Does not delete Outlook OST files, OneDrive cache, full AppData folders, full browser profiles, or full Teams folders.

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

$LogRoot = "C:\ProgramData\IntuneRemediations\AppDataCleanup"
$LogFile = Join-Path $LogRoot "AppDataCleanup.log"

$ExcludedProfileNames = @(
    "Public",
    "Default",
    "Default User",
    "All Users",
    "WDAGUtilityAccount",
    "defaultuser0"
)

# Set to $true for testing only.
$WhatIfMode = $false

# -----------------------------
# Preparation
# -----------------------------

if (-not (Test-Path -LiteralPath $LogRoot)) {
    New-Item -Path $LogRoot -ItemType Directory -Force | Out-Null
}

# -----------------------------
# Functions
# -----------------------------

function Write-Log {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet("INFO", "WARN", "ERROR")]
        [string]$Level = "INFO"
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Entry = "$Timestamp [$Level] $Message"

    Write-Output $Entry

    try {
        Add-Content -Path $LogFile -Value $Entry -Encoding UTF8
    }
    catch {
        Write-Output "Unable to write to log file: $LogFile"
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

function Remove-OldFilesFromPath {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [datetime]$OlderThan,

        [Parameter(Mandatory = $true)]
        [string]$Category,

        [Parameter(Mandatory = $true)]
        [string]$ProfileName
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    Write-Log "Processing [$Category] for [$ProfileName]: $Path. Removing files older than $OlderThan"

    $DeletedFiles = 0
    $DeletedBytes = 0
    $FailedFiles = 0

    try {
        $Files = Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt $OlderThan }

        foreach ($File in $Files) {
            try {
                $FileSize = $File.Length

                if ($WhatIfMode -eq $true) {
                    Write-Log "WHATIF: Would delete file: $($File.FullName)"
                }
                else {
                    Remove-Item -LiteralPath $File.FullName -Force -ErrorAction Stop
                }

                $DeletedFiles++
                $DeletedBytes += $FileSize
            }
            catch {
                $FailedFiles++
                Write-Log "Failed to delete file: $($File.FullName). Error: $($_.Exception.Message)" "WARN"
            }
        }

        # Remove empty directories after file cleanup.
        $Directories = Get-ChildItem -LiteralPath $Path -Recurse -Force -Directory -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending

        foreach ($Directory in $Directories) {
            try {
                $HasChildren = Get-ChildItem -LiteralPath $Directory.FullName -Force -ErrorAction SilentlyContinue | Select-Object -First 1

                if ($null -eq $HasChildren) {
                    if ($WhatIfMode -eq $true) {
                        Write-Log "WHATIF: Would remove empty directory: $($Directory.FullName)"
                    }
                    else {
                        Remove-Item -LiteralPath $Directory.FullName -Force -ErrorAction Stop
                    }
                }
            }
            catch {
                Write-Log "Failed to remove empty directory: $($Directory.FullName). Error: $($_.Exception.Message)" "WARN"
            }
        }

        $DeletedMB = [math]::Round($DeletedBytes / 1MB, 2)
        Write-Log "Completed [$Category] for [$ProfileName]. Deleted files: $DeletedFiles. Failed files: $FailedFiles. Reclaimed: $DeletedMB MB"
    }
    catch {
        Write-Log "Failed processing path: $Path. Error: $($_.Exception.Message)" "ERROR"
    }
}

function Remove-MatchingFilesFromPath {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [datetime]$OlderThan,

        [Parameter(Mandatory = $true)]
        [string[]]$FileNamePatterns,

        [Parameter(Mandatory = $true)]
        [string]$Category,

        [Parameter(Mandatory = $true)]
        [string]$ProfileName
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    Write-Log "Processing matching file cleanup [$Category] for [$ProfileName]: $Path"

    foreach ($Pattern in $FileNamePatterns) {
        try {
            $Files = Get-ChildItem -LiteralPath $Path -Force -File -Filter $Pattern -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -lt $OlderThan }

            foreach ($File in $Files) {
                try {
                    if ($WhatIfMode -eq $true) {
                        Write-Log "WHATIF: Would delete file: $($File.FullName)"
                    }
                    else {
                        Remove-Item -LiteralPath $File.FullName -Force -ErrorAction Stop
                    }

                    Write-Log "Deleted file: $($File.FullName)"
                }
                catch {
                    Write-Log "Failed to delete file: $($File.FullName). Error: $($_.Exception.Message)" "WARN"
                }
            }
        }
        catch {
            Write-Log "Failed matching cleanup for pattern $Pattern in $Path. Error: $($_.Exception.Message)" "WARN"
        }
    }
}

# -----------------------------
# Main
# -----------------------------

Write-Log "Starting AppData cleanup remediation."
Write-Log "WhatIf mode: $WhatIfMode"

$Now = Get-Date
$TempOlderThan      = $Now.AddDays(-$TempOlderThanDays)
$CacheOlderThan     = $Now.AddDays(-$CacheOlderThanDays)
$CrashDumpOlderThan = $Now.AddDays(-$CrashDumpOlderThanDays)

$Profiles = Get-UserProfiles

foreach ($Profile in $Profiles) {
    $ProfileName = $Profile.ProfileName
    $ProfilePath = $Profile.ProfilePath

    Write-Log "Processing profile: $ProfileName | Loaded: $($Profile.Loaded) | Path: $ProfilePath"

    # ------------------------------------------------------------
    # User Temp
    # ------------------------------------------------------------

    Remove-OldFilesFromPath `
        -Path "$ProfilePath\AppData\Local\Temp" `
        -OlderThan $TempOlderThan `
        -Category "User Temp" `
        -ProfileName $ProfileName

    # ------------------------------------------------------------
    # Crash dumps
    # ------------------------------------------------------------

    Remove-OldFilesFromPath `
        -Path "$ProfilePath\AppData\Local\CrashDumps" `
        -OlderThan $CrashDumpOlderThan `
        -Category "Crash Dumps" `
        -ProfileName $ProfileName

    # ------------------------------------------------------------
    # Microsoft Edge cache - all Edge profiles
    # ------------------------------------------------------------

    $EdgeUserData = "$ProfilePath\AppData\Local\Microsoft\Edge\User Data"

    if (Test-Path -LiteralPath $EdgeUserData) {
        Get-ChildItem -LiteralPath $EdgeUserData -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match "^(Default|Profile \d+|Guest Profile)$" } |
            ForEach-Object {
                $EdgeProfilePath = $_.FullName

                $EdgeCachePaths = @(
                    "$EdgeProfilePath\Cache",
                    "$EdgeProfilePath\Code Cache",
                    "$EdgeProfilePath\GPUCache",
                    "$EdgeProfilePath\Service Worker\CacheStorage",
                    "$EdgeProfilePath\Media Cache"
                )

                foreach ($CachePath in $EdgeCachePaths) {
                    Remove-OldFilesFromPath `
                        -Path $CachePath `
                        -OlderThan $CacheOlderThan `
                        -Category "Edge Cache" `
                        -ProfileName $ProfileName
                }
            }
    }

    # ------------------------------------------------------------
    # Google Chrome cache - all Chrome profiles
    # ------------------------------------------------------------

    $ChromeUserData = "$ProfilePath\AppData\Local\Google\Chrome\User Data"

    if (Test-Path -LiteralPath $ChromeUserData) {
        Get-ChildItem -LiteralPath $ChromeUserData -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match "^(Default|Profile \d+|Guest Profile)$" } |
            ForEach-Object {
                $ChromeProfilePath = $_.FullName

                $ChromeCachePaths = @(
                    "$ChromeProfilePath\Cache",
                    "$ChromeProfilePath\Code Cache",
                    "$ChromeProfilePath\GPUCache",
                    "$ChromeProfilePath\Service Worker\CacheStorage",
                    "$ChromeProfilePath\Media Cache"
                )

                foreach ($CachePath in $ChromeCachePaths) {
                    Remove-OldFilesFromPath `
                        -Path $CachePath `
                        -OlderThan $CacheOlderThan `
                        -Category "Chrome Cache" `
                        -ProfileName $ProfileName
                }
            }
    }

    # ------------------------------------------------------------
    # Teams classic cache
    # ------------------------------------------------------------

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
        Remove-OldFilesFromPath `
            -Path $TeamsPath `
            -OlderThan $CacheOlderThan `
            -Category "Teams Classic Cache" `
            -ProfileName $ProfileName
    }

    # ------------------------------------------------------------
    # New Teams cache
    # ------------------------------------------------------------

    $NewTeamsBase = "$ProfilePath\AppData\Local\Packages\MSTeams_8wekyb3d8bbwe"

    $NewTeamsPaths = @(
        "$NewTeamsBase\LocalCache\Microsoft\MSTeams\Cache",
        "$NewTeamsBase\LocalCache\Microsoft\MSTeams\Code Cache",
        "$NewTeamsBase\LocalCache\Microsoft\MSTeams\GPUCache",
        "$NewTeamsBase\LocalCache\Microsoft\MSTeams\Service Worker\CacheStorage",
        "$NewTeamsBase\TempState"
    )

    foreach ($NewTeamsPath in $NewTeamsPaths) {
        Remove-OldFilesFromPath `
            -Path $NewTeamsPath `
            -OlderThan $CacheOlderThan `
            -Category "New Teams Cache" `
            -ProfileName $ProfileName
    }

    # ------------------------------------------------------------
    # Explorer thumbnail/icon cache
    # ------------------------------------------------------------

    $ExplorerCachePath = "$ProfilePath\AppData\Local\Microsoft\Windows\Explorer"

    Remove-MatchingFilesFromPath `
        -Path $ExplorerCachePath `
        -OlderThan $CacheOlderThan `
        -FileNamePatterns @(
            "thumbcache_*.db",
            "iconcache_*.db"
        ) `
        -Category "Explorer Thumbnail/Icon Cache" `
        -ProfileName $ProfileName
}

# ------------------------------------------------------------
# Windows Temp
# ------------------------------------------------------------

if ($IncludeWindowsTemp -eq $true) {
    Remove-OldFilesFromPath `
        -Path "C:\Windows\Temp" `
        -OlderThan $TempOlderThan `
        -Category "Windows Temp" `
        -ProfileName "System"
}

Write-Log "AppData cleanup remediation completed."

exit 0