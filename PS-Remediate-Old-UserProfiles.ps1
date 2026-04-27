<#
.REMEDIATION
Delete local user profiles where best-available last use time is older than X days.

Recommended: run as SYSTEM (Intune Proactive Remediations).
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [int]$AgeDays = 90,
    [switch]$UseSecurityLog,
    [int]$SecurityLogLookbackDays = 365,
    [string[]]$ExcludeProfileNames = @(
        'Public','Default','Default User','All Users','Administrator','defaultuser0'
    ),
    [string]$LogPath = "$env:ProgramData\ProfileCleanup\Remediate.log"
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
    param([Parameter(Mandatory=$true)][object]$High,[Parameter(Mandatory=$true)][object]$Low)
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

        if ($best) { return [pscustomobject]@{ Time=$best; Source=$source } }
        return $null
    } catch { return $null }
}

function Get-LastLogonFromSecurityLog {
    param([string]$Sid,[int]$LookbackDays = 365)

    $filterXml = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) &lt;= $(($LookbackDays*24*60*60*1000)) ]]] 
      and *[EventData[Data[@Name='TargetUserSid']='$Sid']]
      and *[EventData[Data[@Name='LogonType']='2' or Data[@Name='LogonType']='10' or Data[@Name='LogonType']='11']]
    </Select>
  </Query>
</QueryList>
"@
    try {
        $evt = Get-WinEvent -FilterXml $filterXml -MaxEvents 1 -ErrorAction Stop
        if ($evt) { return [pscustomobject]@{ Time=$evt.TimeCreated; Source='SecurityLog(4624)' } }
        return $null
    } catch { return $null }
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
        return ($candidates | Sort-Object Time -Descending | Select-Object -First 1)
    }
    return $null
}

function Get-BestLastUseTime {
    param([string]$Sid,[string]$ProfilePath,[switch]$UseSecurityLog,[int]$SecurityLogLookbackDays)

    $reg = Get-RegistryProfileTimes -Sid $Sid
    if ($reg) { return $reg }

    if ($UseSecurityLog) {
        $sec = Get-LastLogonFromSecurityLog -Sid $Sid -LookbackDays $SecurityLogLookbackDays
        if ($sec) { return $sec }
    }

    $file = Get-FileProxyTimes -ProfilePath $ProfilePath
    if ($file) { return $file }

    return [pscustomobject]@{ Time=$null; Source='Unknown' }
}

function Resolve-SidToName {
    param([string]$Sid)
    try { ([System.Security.Principal.SecurityIdentifier]$Sid).Translate([System.Security.Principal.NTAccount]).Value }
    catch { $Sid }
}

Write-Log "Starting profile cleanup. AgeDays=$AgeDays UseSecurityLog=$UseSecurityLog LookbackDays=$SecurityLogLookbackDays WhatIf=$($WhatIfPreference)"

$profiles = Get-CimInstance Win32_UserProfile |
    Where-Object {
        $_.LocalPath -like 'C:\Users\*' -and
        $_.Special -eq $false -and
        $_.SID -notin @('S-1-5-18','S-1-5-19','S-1-5-20')
    }

$now = Get-Date
$targets = @()

foreach ($p in $profiles) {
    $folderName = Split-Path $p.LocalPath -Leaf

    if ($ExcludeProfileNames -contains $folderName) {
        Write-Log "Skipping excluded profile folder: $($p.LocalPath)"
        continue
    }

    if ($p.Loaded) {
        Write-Log "Skipping loaded profile: $($p.LocalPath) SID=$($p.SID)" "WARN"
        continue
    }

    $best = Get-BestLastUseTime -Sid $p.SID -ProfilePath $p.LocalPath -UseSecurityLog:$UseSecurityLog -SecurityLogLookbackDays $SecurityLogLookbackDays
    if (-not $best.Time) {
        Write-Log "No last-use signal for SID=$($p.SID) Path=$($p.LocalPath) - skipping." "WARN"
        continue
    }

    $age = (New-TimeSpan -Start $best.Time -End $now).TotalDays
    $ageRounded = [math]::Floor($age)

    $name = Resolve-SidToName -Sid $p.SID
    Write-Log "Candidate: $name Path=$($p.LocalPath) LastUse=$($best.Time) Source=$($best.Source) AgeDays=$ageRounded"

    if ($age -ge $AgeDays) {
        $targets += [pscustomobject]@{
            User        = $name
            SID         = $p.SID
            LocalPath   = $p.LocalPath
            LastUseTime = $best.Time
            Source      = $best.Source
            AgeDays     = $ageRounded
            CimObject   = $p
        }
    }
}

if ($targets.Count -eq 0) {
    Write-Log "No profiles older than $AgeDays days to remove."
    exit 0
}

Write-Log "Found $($targets.Count) profiles older than $AgeDays days to remove." "WARN"

$failures = 0

foreach ($t in ($targets | Sort-Object AgeDays -Descending)) {
    $msg = "Delete profile: $($t.User) SID=$($t.SID) Path=$($t.LocalPath) LastUse=$($t.LastUseTime) AgeDays=$($t.AgeDays) Source=$($t.Source)"

    if ($PSCmdlet.ShouldProcess($t.LocalPath, $msg)) {
        try {
            # Primary: Win32_UserProfile.Delete()
            $result = Invoke-CimMethod -InputObject $t.CimObject -MethodName Delete -ErrorAction Stop
            Write-Log "Deleted via Win32_UserProfile.Delete(): $msg ReturnValue=$($result.ReturnValue)"

            # Defensive cleanup if anything remains
            if (Test-Path $t.LocalPath) {
                Write-Log "Profile folder still exists after Delete(). Removing folder: $($t.LocalPath)" "WARN"
                Remove-Item -Path $t.LocalPath -Recurse -Force -ErrorAction Stop
                Write-Log "Folder removed: $($t.LocalPath)"
            }

            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($t.SID)"
            if (Test-Path $regPath) {
                Write-Log "ProfileList key still exists after Delete(). Removing key: $regPath" "WARN"
                Remove-Item -Path $regPath -Recurse -Force -ErrorAction Stop
                Write-Log "Registry key removed: $regPath"
            }
        }
        catch {
            $failures++
            Write-Log "FAILED to delete: $msg Error=$($_.Exception.Message)" "ERROR"
        }
    }
}

if ($failures -gt 0) {
    Write-Log "Cleanup completed with failures: $failures" "ERROR"
    exit 1
}

Write-Log "Cleanup completed successfully. Deleted $($targets.Count) profiles."
exit 0