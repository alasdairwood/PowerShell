<#
.DETECTION
Find local user profiles where "best available last use time" is older than X days.
Priority: Registry unload/load times -> Security log (optional) -> NTUSER/UsrClass file timestamps.

Exit 0 = Compliant
Exit 1 = Non-compliant (stale profiles found)

Run as SYSTEM / admin for best results (recommended for Intune PR).
#>

[CmdletBinding()]
param(
    [int]$AgeDays = 90,
    [switch]$UseSecurityLog,          # optional: more accurate if retention exists, but can be slower
    [int]$SecurityLogLookbackDays = 365,
    [string[]]$ExcludeProfileNames = @(
        'Public','Default','Default User','All Users','Administrator','defaultuser0'
    ),
    [string]$LogPath = "$env:ProgramData\ProfileCleanup\Detect.log"
)

# region logging
New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null
function Write-Log {
    param([string]$Message,[string]$Level='INFO')
    $line = "{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Add-Content -Path $LogPath -Value $line
    Write-Output $line
}
# endregion logging

function Convert-HighLowToDateTime {
    param(
        [Parameter(Mandatory=$true)][object]$High,
        [Parameter(Mandatory=$true)][object]$Low
    )
    try {
        $hi = [uint64]$High
        $lo = [uint64]$Low
        $ft = ($hi -shl 32) + $lo
        if ($ft -le 0) { return $null }
        return [DateTime]::FromFileTimeUtc([int64]$ft).ToLocalTime()
    } catch { return $null }
}

function Get-RegistryProfileTimes {
    param([string]$Sid)

    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$Sid"
    if (-not (Test-Path $regPath)) { return $null }

    try {
        $p = Get-ItemProperty -Path $regPath -ErrorAction Stop

        # Prefer Unload time if present; else Load time.
        $unload = $null
        if ($p.PSObject.Properties.Name -contains 'ProfileUnloadTimeHigh' -and
            $p.PSObject.Properties.Name -contains 'ProfileUnloadTimeLow') {
            $unload = Convert-HighLowToDateTime -High $p.ProfileUnloadTimeHigh -Low $p.ProfileUnloadTimeLow
        }

        $load = $null
        if ($p.PSObject.Properties.Name -contains 'ProfileLoadTimeHigh' -and
            $p.PSObject.Properties.Name -contains 'ProfileLoadTimeLow') {
            $load = Convert-HighLowToDateTime -High $p.ProfileLoadTimeHigh -Low $p.ProfileLoadTimeLow
        }

        $best = $unload
        $source = 'Registry(ProfileUnloadTime)'
        if (-not $best -and $load) { $best = $load; $source = 'Registry(ProfileLoadTime)' }

        if ($best) {
            return [pscustomobject]@{ Time = $best; Source = $source }
        }
        return $null
    } catch {
        return $null
    }
}

function Get-LastLogonFromSecurityLog {
    param(
        [string]$Sid,
        [int]$LookbackDays = 365
    )

    $start = (Get-Date).AddDays(-1 * $LookbackDays)

    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4624
            StartTime = $start
        } -ErrorAction Stop

        foreach ($evt in $events) {
            $xml = [xml]$evt.ToXml()

            $targetSid = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserSid' }).'#text'
            if ($targetSid -ne $Sid) { continue }

            $logonType = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'LogonType' }).'#text'
            if ($logonType -notin @('2','10','11')) { continue }

            return [pscustomobject]@{
                Time   = $evt.TimeCreated
                Source = 'SecurityLog(4624)'
            }
        }

        return $null
    }
    catch {
        return $null
    }
}

function Get-FileProxyTimes {
    param([string]$ProfilePath)

    $candidates = @()

    $ntUser = Join-Path $ProfilePath 'NTUSER.DAT'
    if (Test-Path $ntUser) {
        $candidates += [pscustomobject]@{ Time=(Get-Item $ntUser -ErrorAction SilentlyContinue).LastWriteTime; Source='File(NTUSER.DAT)' }
    }

    $usrClass = Join-Path $ProfilePath 'AppData\Local\Microsoft\Windows\UsrClass.dat'
    if (Test-Path $usrClass) {
        $candidates += [pscustomobject]@{ Time=(Get-Item $usrClass -ErrorAction SilentlyContinue).LastWriteTime; Source='File(UsrClass.dat)' }
    }

    if ($candidates.Count -gt 0) {
        $best = $candidates | Sort-Object Time -Descending | Select-Object -First 1
        return $best
    }
    return $null
}

function Get-BestLastUseTime {
    param(
        [string]$Sid,
        [string]$ProfilePath,
        [switch]$UseSecurityLog,
        [int]$SecurityLogLookbackDays
    )

    # 1) Registry
    $reg = Get-RegistryProfileTimes -Sid $Sid
    if ($reg) { return $reg }

    # 2) Security Log (optional)
    if ($UseSecurityLog) {
        $sec = Get-LastLogonFromSecurityLog -Sid $Sid -LookbackDays $SecurityLogLookbackDays
        if ($sec) { return $sec }
    }

    # 3) File proxy
    $file = Get-FileProxyTimes -ProfilePath $ProfilePath
    if ($file) { return $file }

    return [pscustomobject]@{ Time = $null; Source='Unknown' }
}

function Resolve-SidToName {
    param([string]$Sid)
    try {
        return ([System.Security.Principal.SecurityIdentifier]$Sid).Translate([System.Security.Principal.NTAccount]).Value
    } catch {
        return $Sid
    }
}

Write-Log "Starting profile stale detection. AgeDays=$AgeDays UseSecurityLog=$UseSecurityLog LookbackDays=$SecurityLogLookbackDays"

# Get real user profiles under C:\Users
$profiles = Get-CimInstance Win32_UserProfile |
    Where-Object {
        $_.LocalPath -like 'C:\Users\*' -and
        $_.Special -eq $false -and
        $_.SID -notin @('S-1-5-18','S-1-5-19','S-1-5-20')
    }

$now = Get-Date
$stale = @()

foreach ($p in $profiles) {
    $folderName = Split-Path $p.LocalPath -Leaf

    if ($ExcludeProfileNames -contains $folderName) { 
        Write-Log "Skipping excluded profile folder: $($p.LocalPath)"
        continue 
    }

    # Skip currently loaded profiles
    if ($p.Loaded) {
        Write-Log "Skipping loaded profile: $($p.LocalPath) SID=$($p.SID)"
        continue
    }

    $best = Get-BestLastUseTime -Sid $p.SID -ProfilePath $p.LocalPath -UseSecurityLog:$UseSecurityLog -SecurityLogLookbackDays $SecurityLogLookbackDays
    $lastUse = $best.Time
    $source  = $best.Source
    $name    = Resolve-SidToName -Sid $p.SID

    if (-not $lastUse) {
        Write-Log "No last-use signal for $name ($($p.LocalPath)). Source=$source" "WARN"
        continue
    }

    $age = (New-TimeSpan -Start $lastUse -End $now).TotalDays
    $ageRounded = [math]::Floor($age)

    Write-Log "Profile: $name Path=$($p.LocalPath) LastUse=$lastUse Source=$source AgeDays=$ageRounded"

    if ($age -ge $AgeDays) {
        $stale += [pscustomobject]@{
            User        = $name
            SID         = $p.SID
            LocalPath   = $p.LocalPath
            LastUseTime = $lastUse
            Source      = $source
            AgeDays     = $ageRounded
        }
    }
}

if ($stale.Count -gt 0) {
    Write-Log "NON-COMPLIANT: Found $($stale.Count) stale profiles older than $AgeDays days." "WARN"
    $stale | Sort-Object AgeDays -Descending | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Log $_.TrimEnd() }
    exit 1
}

Write-Log "COMPLIANT: No stale profiles older than $AgeDays days found."
exit 0