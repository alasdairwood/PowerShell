<#
.SYNOPSIS
Audits and removes old user profiles using accurate last logon detection.

.DESCRIPTION
Priority-based last activity detection:
1. CIM LastLogon (High confidence)
2. UsrClass.dat LastWriteTime (Medium confidence)
3. Profile folder LastWriteTime (Low confidence – last resort)

Supports:
- -MonthsOld override
- -WhatIf / -Force safety
- Exclusions
- Orphaned profile detection
- CSV logging
- Interactive confirmation for high-risk deletion runs
- -ConfirmDangerous override for automation
#>

param(
    [switch]$WhatIf,
    [switch]$Force,
    [switch]$ConfirmDangerous,
    [int]$MonthsOld = 24,
    [string]$LogPath = ".\ProfileAudit.csv",
    [string[]]$ExcludeUsers = @(),
    [switch]$CleanOrphanedOnly,
    [switch]$Help
)

# --- Help / Usage ---
if ($Help -or $args -contains '/?' -or $args -contains '-?') {
    Write-Host ''
    Write-Host 'ProfileCleanup.ps1 - Available switches:' -ForegroundColor Cyan
    Write-Host ''
    Write-Host '  -WhatIf              Run in audit mode (no deletions performed)'
    Write-Host '  -Force               Enable profile deletion (required for removal)'
    Write-Host '  -ConfirmDangerous    Override safety when MonthsOld is less than 6 (non-interactive use)'
    Write-Host '  -MonthsOld N         Profiles older than N months (default: 24)'
    Write-Host '  -LogPath <path>      Base path for CSV output (default: .\ProfileAudit.csv)'
    Write-Host '  -ExcludeUsers <arr>  Array of usernames to exclude (e.g. svc accounts)'
    Write-Host ''
    Write-Host 'Safety behaviour:' -ForegroundColor Yellow
    Write-Host '  - If neither -WhatIf nor -Force is specified, script defaults to -WhatIf'
    Write-Host '  - If -Force is used with MonthsOld < 6:'
    Write-Host '      * Interactive run → prompts for confirmation'
    Write-Host '      * Non-interactive → blocked unless -ConfirmDangerous is supplied'
    Write-Host ''
    Write-Host 'Examples:' -ForegroundColor Yellow
    Write-Host '  .\ProfileCleanup.ps1'
    Write-Host '  .\ProfileCleanup.ps1 -WhatIf -MonthsOld 12'
    Write-Host '  .\ProfileCleanup.ps1 -Force -MonthsOld 12'
    Write-Host '  .\ProfileCleanup.ps1 -Force -MonthsOld 3'
    Write-Host '  .\ProfileCleanup.ps1 -Force -MonthsOld 3 -ConfirmDangerous'
    Write-Host '  .\ProfileCleanup.ps1 -Force -ExcludeUsers svcadmin,testuser'
    Write-Host ''
    return
}

# -----------------------------
# Default behavior
# -----------------------------
if (-not $WhatIf -and -not $Force) {
    $WhatIf = $true
}

# -----------------------------
# Run context (for logging)
# -----------------------------
$RunRisk = "Normal"
if ($MonthsOld -lt 6 -and $Force) {
    $RunRisk = "HighRisk"
}

$RunId = [guid]::NewGuid().Guid

# -----------------------------
# CSV column definitions
# -----------------------------
$MainLogColumns = @(
    'Timestamp',
    'UserProfile',
    'SID',
    'LastActivity',
    'Source',
    'Action',
    'RunRisk',
    'RunId'
)

$FailureLogColumns = @(
    'Timestamp',
    'UserProfile',
    'SID',
    'Reason',
    'RunRisk',
    'RunId'
)

# -----------------------------
# Helper: append CSV row safely
# -----------------------------
function Add-CsvRow {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string[]]$Columns,

        [Parameter(Mandatory = $true)]
        [hashtable]$Data
    )

    $obj = New-Object PSObject -Property $Data
    $csvLine = $obj |
        Select-Object $Columns |
        ConvertTo-Csv -NoTypeInformation |
        Select-Object -Skip 1

    $csvLine | Out-File -FilePath $Path -Append -Encoding UTF8
}

# -----------------------------
# Helper: test interactive session
# -----------------------------
function Test-IsInteractiveSession {
    try {
        if ($Host.Name -eq 'ConsoleHost' -and [Environment]::UserInteractive) {
            return $true
        }
    }
    catch {
        if ($Host.Name -eq 'ConsoleHost') {
            return $true
        }
    }
    return $false
}

# -----------------------------
# Helper: Protected Users
# -----------------------------
function Test-IsProtectedAccount {
    param(
        [string]$UserName
    )

    if (-not $UserName) {
        return $false
    }

    $u = $UserName.ToLower()

    # Exact match
    foreach ($acc in $ProtectedAccounts) {
        if ($u -eq $acc.ToLower()) {
            return $true
        }
    }

    # Pattern match
    foreach ($pattern in $ProtectedPatterns) {
        if ($u -match $pattern) {
            return $true
        }
    }

    return $false
}

# -----------------------------
# CSV paths
# -----------------------------
$hostname = $env:COMPUTERNAME
$LogDir = Split-Path -Path $LogPath -Parent

# Fix: handle null/empty LogDir safely

if ([string]::IsNullOrWhiteSpace($LogDir)) {
    $LogDir = "."
}

# Ensure directory exists
if ($LogDir -and -not (Test-Path -Path $LogDir)) {
    New-Item -Path $LogDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
}

$LogFileName = "{0}-{1}.csv" -f ([System.IO.Path]::GetFileNameWithoutExtension($LogPath)), $hostname
$LogPath = Join-Path -Path $LogDir -ChildPath $LogFileName
$FailureLogPath = Join-Path -Path $LogDir -ChildPath ("ProfileDeletionFailures-{0}.csv" -f $hostname)

Write-Host "[RUN] LogPath=$LogPath | Risk=$RunRisk | RunId=$RunId" -ForegroundColor DarkCyan

# Create CSV headers if files do not exist
if (-not (Test-Path -Path $LogPath)) {
    ($MainLogColumns -join ",") | Out-File -FilePath $LogPath -Encoding UTF8
}

if (-not (Test-Path -Path $FailureLogPath)) {
    ($FailureLogColumns -join ",") | Out-File -FilePath $FailureLogPath -Encoding UTF8
}

# -----------------------------
# Log run start marker
# -----------------------------
Add-CsvRow -Path $LogPath -Columns $MainLogColumns -Data @{
    Timestamp    = (Get-Date).ToString('s')
    UserProfile  = 'RUN_START'
    SID          = 'N/A'
    LastActivity = 'N/A'
    Source       = 'N/A'
    Action       = 'Started'
    RunRisk      = $RunRisk
    RunId        = $RunId
}

# -----------------------------
# Safety guard (interactive + automation override)
# -----------------------------
if ($MonthsOld -lt 6 -and $Force) {

    Write-Host "[GUARD] MonthsOld=$MonthsOld | Risk=HIGH (<6 months)" -ForegroundColor Yellow
    Write-Warning "This may delete recently used profiles."

    if ($ConfirmDangerous) {
        Write-Host "[GUARD] Override accepted via -ConfirmDangerous. Proceeding..." -ForegroundColor Cyan

        Add-CsvRow -Path $LogPath -Columns $MainLogColumns -Data @{
            Timestamp    = (Get-Date).ToString('s')
            UserProfile  = 'RUN_GUARD'
            SID          = 'N/A'
            LastActivity = 'N/A'
            Source       = 'N/A'
            Action       = 'ConfirmDangerousAccepted'
            RunRisk      = $RunRisk
            RunId        = $RunId
        }
    }
    else {
        $isInteractive = Test-IsInteractiveSession

        if (-not $isInteractive) {
            Write-Warning "Non-interactive session detected. Use -ConfirmDangerous to override."

            Add-CsvRow -Path $LogPath -Columns $MainLogColumns -Data @{
                Timestamp    = (Get-Date).ToString('s')
                UserProfile  = 'RUN_GUARD'
                SID          = 'N/A'
                LastActivity = 'N/A'
                Source       = 'N/A'
                Action       = 'AbortedNonInteractive'
                RunRisk      = $RunRisk
                RunId        = $RunId
            }

            Add-CsvRow -Path $LogPath -Columns $MainLogColumns -Data @{
                Timestamp    = (Get-Date).ToString('s')
                UserProfile  = 'RUN_END'
                SID          = 'N/A'
                LastActivity = 'N/A'
                Source       = 'N/A'
                Action       = 'Aborted'
                RunRisk      = $RunRisk
                RunId        = $RunId
            }

            return
        }

        $response = Read-Host "Type YES to continue with deletion, or anything else to cancel"

        if ($response -cne "YES") {
            Write-Host "Operation cancelled by user." -ForegroundColor Yellow

            Add-CsvRow -Path $LogPath -Columns $MainLogColumns -Data @{
                Timestamp    = (Get-Date).ToString('s')
                UserProfile  = 'RUN_GUARD'
                SID          = 'N/A'
                LastActivity = 'N/A'
                Source       = 'N/A'
                Action       = 'CancelledByUser'
                RunRisk      = $RunRisk
                RunId        = $RunId
            }

            Add-CsvRow -Path $LogPath -Columns $MainLogColumns -Data @{
                Timestamp    = (Get-Date).ToString('s')
                UserProfile  = 'RUN_END'
                SID          = 'N/A'
                LastActivity = 'N/A'
                Source       = 'N/A'
                Action       = 'Cancelled'
                RunRisk      = $RunRisk
                RunId        = $RunId
            }

            return
        }

        Write-Host "[GUARD] User confirmed high-risk operation. Proceeding..." -ForegroundColor Cyan

        Add-CsvRow -Path $LogPath -Columns $MainLogColumns -Data @{
            Timestamp    = (Get-Date).ToString('s')
            UserProfile  = 'RUN_GUARD'
            SID          = 'N/A'
            LastActivity = 'N/A'
            Source       = 'N/A'
            Action       = 'UserConfirmed'
            RunRisk      = $RunRisk
            RunId        = $RunId
        }
    }
}

$CutoffDate = (Get-Date).AddMonths(-$MonthsOld)

# -----------------------------
# Exclusions
# -----------------------------

# -----------------------------
# Protected accounts (never touch or scan)
# -----------------------------
$ProtectedAccounts = @(
    'SVC.MAP'
)

# Pattern-based protection (scalable)
$ProtectedPatterns = @(
    '^SVC\.'   # Anything starting with SVC.
)

Write-Host "[INIT] Protected Accounts: $($ProtectedAccounts -join ', ')" -ForegroundColor DarkCyan
Write-Host "[INIT] Protected Patterns: $($ProtectedPatterns -join ', ')" -ForegroundColor DarkCyan
Write-Host ""

$ExcludeUsersLower = @($ExcludeUsers | ForEach-Object { $_.ToLower() })
Write-Host "Excluding users:" ($ExcludeUsersLower -join ", ") -ForegroundColor DarkCyan

# -----------------------------
# Loaded registry hives (safe)
# -----------------------------
$loadedHives = @()
Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue | ForEach-Object {
    try {
        $loadedHives += (Split-Path $_.Name -Leaf)
    }
    catch {
    }
}

# -----------------------------
# CIM LastLogon lookup
# -----------------------------
$CIMLookup = @{}
Get-CimInstance Win32_NetworkLoginProfile -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -and $_.LastLogon } |
    ForEach-Object {
        $user = ($_.Name -split '\\')[-1].ToLower()
        if (-not $CIMLookup.ContainsKey($user)) {
            $CIMLookup[$user] = $_.LastLogon
        }
    }

# -----------------------------
# Helper: determine last activity
# -----------------------------
function Get-MostRecentLastLogon {
    param(
        [string]$ProfilePath,
        [string]$UserName
    )

    $result = [PSCustomObject]@{
        Date   = $null
        Source = 'None'
    }

    # CIM (High confidence)
    if ($CIMLookup.ContainsKey($UserName.ToLower())) {
        $result.Date = $CIMLookup[$UserName.ToLower()]
        $result.Source = 'CIM'
        return $result
    }

    # UsrClass.dat (Medium confidence)
    $usrClass = Join-Path -Path $ProfilePath -ChildPath 'AppData\Local\Microsoft\Windows\UsrClass.dat'
    if (Test-Path $usrClass) {
        try {
            $result.Date = (Get-Item -Path $usrClass -Force).LastWriteTime
            $result.Source = 'UsrClass'
            return $result
        }
        catch {
        }
    }

    # Profile folder (Low confidence)
    if (Test-Path $ProfilePath) {
        try {
            $result.Date = (Get-Item -Path $ProfilePath -Force).LastWriteTime
            $result.Source = 'ProfileFolder'
            return $result
        }
        catch {
        }
    }

    # Orphaned profile
    $result.Source = 'ProfileMissing'
    return $result
}

# -----------------------------
# Enumerate profiles
# -----------------------------
$OrphanCount = 0
$FailedDeletions = @()

$Profiles = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object {
    -not $_.Special -and
    $_.LocalPath -and
    $_.LocalPath -notmatch '^C:\\Users\\(Default|Public|All Users)(\\|$)'
}

foreach ($Profile in $Profiles) {

    $ProfilePath = $Profile.LocalPath
    $UserName = Split-Path -Path $ProfilePath -Leaf
    $SID = $Profile.SID
    
if (Test-IsProtectedAccount -UserName $UserName) {
    Write-Host "Skipping protected account: $UserName" -ForegroundColor Yellow
    continue
}


    if ($ExcludeUsersLower -contains $UserName.ToLower()) {
        Write-Host "Skipping excluded profile: $UserName"
        continue
    }

    if ($loadedHives -contains $SID) {
        Write-Host "Skipping active profile: $UserName"
        continue
    }

    $LastObj = Get-MostRecentLastLogon -ProfilePath $ProfilePath -UserName $UserName

    # Orphaned profile handling
if ($LastObj.Source -eq "ProfileMissing") {
$OrphanCount++
    Write-Host "[ORPHAN] SID profile without folder: $UserName (SID: $SID)" -ForegroundColor Yellow

    $Action = "OrphanDetected"

    if ($WhatIf) {
        $Action = "Orphan-WhatIf"
    }
    elseif ($Force -or $CleanOrphanedOnly) {

        Write-Host "[ORPHAN] Removing SID registry only: $SID" -ForegroundColor Cyan

        try {
            $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$SID"

            if (Test-Path $RegPath) {
                Remove-Item -Path $RegPath -Recurse -Force -ErrorAction Stop
            }

            $Action = "Orphan-Deleted"
        }
        catch {
            $Action = "Orphan-DeleteFailed"

            Write-Host "[ERROR][ORPHAN] Failed to delete SID $SID : $($_.Exception.Message)" -ForegroundColor Red

            Add-CsvRow -Path $FailureLogPath -Columns $FailureLogColumns -Data @{
                Timestamp   = (Get-Date).ToString('s')
                UserProfile = "SID:$SID"
                SID         = $SID
                Reason      = $_.Exception.Message
                RunRisk     = $RunRisk
                RunId       = $RunId
            }
        }
    }

    # ✅ Log it
    Add-CsvRow -Path $LogPath -Columns $MainLogColumns -Data @{
        Timestamp    = (Get-Date).ToString('s')
        UserProfile  = "SID:$SID"
        SID          = $SID
        LastActivity = "N/A"
        Source       = "ProfileMissing"
        Action       = $Action
        RunRisk      = $RunRisk
        RunId        = $RunId
    }

    continue
}

    if (-not $LastObj.Date -or $LastObj.Date -ge $CutoffDate) {
        continue
    }

    $LastFormatted = $LastObj.Date.ToString('yyyy-MM-dd')
    $Action = 'Skipped'

    if ($WhatIf) {
        Write-Host "[WhatIf] Would delete profile: $ProfilePath (SID: $SID, LastActivity: $LastFormatted, Source: $($LastObj.Source))"
        $Action = 'WhatIf'
    }
    elseif ($Force) {
        Write-Host "Deleting profile: $ProfilePath (SID: $SID)"

        try {
            try {
                reg unload "HKEY_USERS\$SID" 2>$null | Out-Null
            }
            catch {
            }

            $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$SID"
            if (Test-Path $RegPath) {
                Remove-Item -Path $RegPath -Recurse -Force -ErrorAction Stop
            }

            if (Test-Path $ProfilePath) {
                Remove-Item -Path $ProfilePath -Recurse -Force -ErrorAction Stop
            }

            $Action = 'Deleted'
        }
        catch {
            $Action = 'Delete Failed'
            $FailedDeletions += $ProfilePath

            Add-CsvRow -Path $FailureLogPath -Columns $FailureLogColumns -Data @{
                Timestamp   = (Get-Date).ToString('s')
                UserProfile = $ProfilePath
                SID         = $SID
                Reason      = $_.Exception.Message
                RunRisk     = $RunRisk
                RunId       = $RunId
            }
        }
    }

    Add-CsvRow -Path $LogPath -Columns $MainLogColumns -Data @{
        Timestamp    = (Get-Date).ToString('s')
        UserProfile  = $ProfilePath
        SID          = $SID
        LastActivity = $LastFormatted
        Source       = $LastObj.Source
        Action       = $Action
        RunRisk      = $RunRisk
        RunId        = $RunId
    }
}

# -----------------------------
# Summary
# -----------------------------
if ($Force) {
    Write-Host ""
    Write-Host "===== Deletion Summary =====" -ForegroundColor Cyan
    Write-Host "RunRisk: $RunRisk | RunId: $RunId" -ForegroundColor DarkCyan
    Write-Host "Orphaned SIDs processed: $OrphanCount" -ForegroundColor DarkCyan

    if ($FailedDeletions.Count -gt 0) {
        Write-Host "Failed deletions:" -ForegroundColor Red
        $FailedDeletions | ForEach-Object {
            Write-Host " - $_"
        }
    }
    else {
        Write-Host "All deletions succeeded." -ForegroundColor Green
        
    }
}
elseif ($WhatIf) {
    Write-Host ""
    Write-Host "===== Audit Summary =====" -ForegroundColor Cyan
    Write-Host "RunRisk: $RunRisk | RunId: $RunId" -ForegroundColor DarkCyan
    Write-Host "WhatIf mode was used. No profiles were deleted." -ForegroundColor Green
}

# -----------------------------
# Log run end marker
# -----------------------------
Add-CsvRow -Path $LogPath -Columns $MainLogColumns -Data @{
    Timestamp    = (Get-Date).ToString('s')
    UserProfile  = 'RUN_END'
    SID          = 'N/A'
    LastActivity = 'N/A'
    Source       = 'N/A'
    Action       = 'Completed'
    RunRisk      = $RunRisk
    RunId        = $RunId
}