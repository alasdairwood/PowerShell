<#
.SYNOPSIS
    Performs automated alert and report based Wintel security tasks.

.DESCRIPTION
    Runs a set of actions to generate Windows Security/System events used by Splunk alert/report detections.
    Supports interactive menu or non-interactive mode (Mode + DelaySeconds).

.NOTES
    Author:  Alasdair Wood (enhanced/refactored)
    Updated: 2026-04-23
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('Menu','Alerts','Reports')]
    [string]$Mode = 'Menu',

    [ValidateRange(0, 3600)]
    [int]$DelaySeconds = 3,

    # High-risk actions are opt-in
    [switch]$AllowClearEventLogs,
    [switch]$AllowTimeChange,

    # Reboot behaviour
    [switch]$NoReboot,

    # Where the script lives (for RunOnce resume)
    [string]$ScriptPath = $PSCommandPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-Step {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Action,
        [int]$Delay = 0,
        [ref]$GoodCount,
        [ref]$BadCount
    )

    try {
        Write-Host "$Name... " -NoNewline
        & $Action
        Write-Host "Done!" -ForegroundColor Green
        $GoodCount.Value++
    }
    catch {
        Write-Host "Failed!" -ForegroundColor Red
        $BadCount.Value++
        Write-Warning "$Name failed: $($_.Exception.Message)"
    }

    if ($Delay -gt 0) {
        Start-Sleep -Seconds $Delay
    }
}

function Confirm-ServiceRunning {
    param([Parameter(Mandatory)][string]$Name)
    $svc = Get-Service -Name $Name -ErrorAction Stop
    if ($svc.StartType -ne 'Automatic') {
        Set-Service -Name $Name -StartupType Automatic
    }
    if ($svc.Status -ne 'Running') {
        Start-Service -Name $Name
    }
}

function Start-ProcessAsCredentialAndStop {
    param(
        [Parameter(Mandatory)][System.Management.Automation.PSCredential]$Credential,
        [string]$FilePath = 'notepad.exe',
        [int]$RunSeconds = 5
    )
    $p = Start-Process -FilePath $FilePath -Credential $Credential -WorkingDirectory 'C:\Windows\System32' -WindowStyle Hidden -PassThru
    Start-Sleep -Seconds $RunSeconds
    if ($null -ne $p -and -not $p.HasExited) {
        Stop-Process -Id $p.Id -Force
    }
}

function Set-RunOnceResume {
    param([Parameter(Mandatory)][string]$ScriptPathToRun)
    $runonceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    $psExe = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
    $cmd = "$psExe -ExecutionPolicy Bypass -File `"$ScriptPathToRun`""
    Set-ItemProperty -Path $runonceKey -Name "NextRun" -Value $cmd
}

function Invoke-SecEditGrantServiceLogonRight {
    param(
        [Parameter(Mandatory)][string]$LocalUserName
    )

    # Use per-run temp folder
    $tempRoot = Join-Path $env:TEMP ("WintelSecEdit_" + [guid]::NewGuid().ToString())
    New-Item -Path $tempRoot -ItemType Directory | Out-Null

    $infPath = Join-Path $tempRoot "policies.inf"
    $logPath = Join-Path $tempRoot "policies.log"
    $sdbPath = Join-Path $tempRoot "secedit.sdb"

    try {
        $userRightPattern = "SeServiceLogonRight*"

        $export = Start-Process -FilePath "secedit.exe" -ArgumentList "/export /areas USER_RIGHTS /cfg `"$infPath`"" -Wait -PassThru
        if ($export.ExitCode -ne 0) { throw "secedit export failed (ExitCode=$($export.ExitCode))" }

        $sid = ((Get-LocalUser -Name $LocalUserName).SID).Value
        $policy = Get-Content -Path $infPath

        $newPol = foreach ($line in $policy) {
            if ($line -like $userRightPattern) {
                # Append SID only if not already present
                if ($line -notmatch [regex]::Escape($sid)) {
                    "$line,*$sid"
                } else {
                    $line
                }
            } else {
                $line
            }
        }

        $newPol | Set-Content -Path $infPath -Force

        $import = Start-Process -FilePath "secedit.exe" -ArgumentList "/configure /db `"$sdbPath`" /cfg `"$infPath`" /areas USER_RIGHTS /log `"$logPath`"" -Wait -PassThru
        if ($import.ExitCode -ne 0) { throw "secedit import failed (ExitCode=$($import.ExitCode))" }
    }
    finally {
        # Best-effort cleanup
        Remove-Item -Path $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-AlertsTests {
    param(
        [int]$Delay,
        [switch]$AllowClearEventLogs,
        [switch]$AllowTimeChange,
        [switch]$NoReboot,
        [string]$ScriptPath
    )

    $user      = "alertsuser"
    $badUser   = "baduser"
    $newUser   = "newuser"
    $password  = ConvertTo-SecureString -String "P@ssword1"   -AsPlainText -Force
    $newPass   = ConvertTo-SecureString -String "N3wP@ssword1" -AsPlainText -Force

    $good = 0
    $bad  = 0

    Write-Host "Running ALERT-based Wintel tests on $env:COMPUTERNAME" -ForegroundColor Cyan

    try {
        Invoke-Step -Name "Create local users ($user, $badUser)" -Delay $Delay -GoodCount ([ref]$good) -BadCount ([ref]$bad) -Action {
            New-LocalUser -Name $user -Password $password | Out-Null
            New-LocalUser -Name $badUser -Password $password | Out-Null
        }

        Invoke-Step -Name "Change password for $user" -Delay $Delay -GoodCount ([ref]$good) -BadCount ([ref]$bad) -Action {
            Set-LocalUser -Name $user -Password $newPass
        }

        Invoke-Step -Name "Modify account (add to Administrators + rename round-trip)" -Delay $Delay -GoodCount ([ref]$good) -BadCount ([ref]$bad) -Action {
            Add-LocalGroupMember -Group "Administrators" -Member $user
            Rename-LocalUser -Name $user -NewName $newUser
            Rename-LocalUser -Name $newUser -NewName $user
        }

        Invoke-Step -Name "Modify user right (SeServiceLogonRight) for $user" -Delay $Delay -GoodCount ([ref]$good) -BadCount ([ref]$bad) -Action {
            Invoke-SecEditGrantServiceLogonRight -LocalUserName $user
        }

        Invoke-Step -Name "Disable then enable $user" -Delay $Delay -GoodCount ([ref]$good) -BadCount ([ref]$bad) -Action {
            Disable-LocalUser -Name $user
            Enable-LocalUser -Name $user
        }

        Invoke-Step -Name "Blacklisted login simulation using $badUser (run Notepad as user)" -Delay $Delay -GoodCount ([ref]$good) -BadCount ([ref]$bad) -Action {
            Ensure-ServiceRunning -Name 'seclogon'
            Add-LocalGroupMember -Group "Administrators" -Member $badUser

            $cred = New-Object System.Management.Automation.PSCredential ($badUser, $password)
            Start-ProcessAsCredentialAndStop -Credential $cred -RunSeconds 5
        }

        Invoke-Step -Name "Approved privileged access using $user" -Delay $Delay -GoodCount ([ref]$good) -BadCount ([ref]$bad) -Action {
            $cred = New-Object System.Management.Automation.PSCredential ($user, $newPass)
            Start-ProcessAsCredentialAndStop -Credential $cred -RunSeconds 5
        }

        Invoke-Step -Name "Login default approved account using $user" -Delay $Delay -GoodCount ([ref]$good) -BadCount ([ref]$bad) -Action {
            $cred = New-Object System.Management.Automation.PSCredential ($user, $newPass)
            Start-ProcessAsCredentialAndStop -Credential $cred -RunSeconds 5
        }

        Invoke-Step -Name "Login disabled account attempt using $user (expected fail)" -Delay $Delay -GoodCount ([ref]$good) -BadCount ([ref]$bad) -Action {
            Disable-LocalUser -Name $user

            $cred = New-Object System.Management.Automation.PSCredential ($user, $newPass)
            # This may fail depending on system policy; still produces auth events.
            Start-Process -FilePath "$env:WINDIR\System32\notepad.exe" -Credential $cred -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
        }

        Invoke-Step -Name "Multiple failed logons for $user (ValidateCredentials)" -Delay $Delay -GoodCount ([ref]$good) -BadCount ([ref]$bad) -Action {
            Add-Type -AssemblyName System.DirectoryServices.AccountManagement
            $maxAttempts = 5
            $falsePassword = 'f4ls3p@ssw0rd'
            $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('Machine', $env:COMPUTERNAME)

            foreach ($i in 1..$maxAttempts) {
                $null = $ctx.ValidateCredentials($user, $falsePassword)
            }
        }

        if ($AllowTimeChange) {
            Invoke-Step -Name "Change system time back 15 minutes" -Delay $Delay -GoodCount ([ref]$good) -BadCount ([ref]$bad) -Action {
                Set-Date -Adjust -0:15:00 -DisplayHint Time | Out-Null
            }
        } else {
            Write-Host "Skipping time change (use -AllowTimeChange to enable)" -ForegroundColor Yellow
        }

        Invoke-Step -Name "Remove test local users ($user, $badUser)" -Delay $Delay -GoodCount ([ref]$good) -BadCount ([ref]$bad) -Action {
            Remove-LocalUser -Name $user -ErrorAction SilentlyContinue
            Remove-LocalUser -Name $badUser -ErrorAction SilentlyContinue
        }

        if ($AllowClearEventLogs) {
            Invoke-Step -Name "Clear Event Logs (high-risk action)" -Delay 0 -GoodCount ([ref]$good) -BadCount ([ref]$bad) -Action {
                # Safer alternative would be wevtutil per-log; keeping your original intent but with error handling
                Get-EventLog -LogName * -ErrorAction SilentlyContinue | ForEach-Object {
                    try { Clear-EventLog -LogName $_.Log -ErrorAction Stop } catch {}
                }
            }
        } else {
            Write-Host "Skipping event log clearing (use -AllowClearEventLogs to enable)" -ForegroundColor Yellow
        }

        Write-Host "`nSteps Completed Successfully: $good" -ForegroundColor Green
        Write-Host "Steps Failed: $bad" -ForegroundColor Red
    }
    finally {
        # Ensure user re-enabled if left disabled
        try { Enable-LocalUser -Name $user -ErrorAction SilentlyContinue } catch {}
    }

    if (-not $NoReboot) {
        if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Set RunOnce and reboot")) {
            Set-RunOnceResume -ScriptPathToRun $ScriptPath
            Write-Warning "Server restarting. You will be logged out. Script will continue after login (RunOnce)."
            Start-Sleep -Seconds 5
            Restart-Computer -Force
        }
    } else {
        Write-Host "Reboot skipped (-NoReboot specified)." -ForegroundColor Yellow
    }
}

function Invoke-ReportsTests {
    param(
        [int]$Delay,
        [switch]$NoReboot,
        [string]$ScriptPath
    )

    $user     = "reportsuser"
    $password = ConvertTo-SecureString -String "P@ssword1"   -AsPlainText -Force
    $newPass  = ConvertTo-SecureString -String "N3wP@ssword1" -AsPlainText -Force

    $good = 0
    $bad  = 0

    Write-Host "Running REPORT-based Wintel tests on $env:COMPUTERNAME" -ForegroundColor Cyan

    try {
        Invoke-Step -Name "Create local user ($user)" -Delay $Delay -GoodCount ([ref]$good) -BadCount ([ref]$bad) -Action {
            New-LocalUser -Name $user -Password $password | Out-Null
        }

        Invoke-Step -Name "Modify password for $user" -Delay $Delay -GoodCount ([ref]$good) -BadCount ([ref]$bad) -Action {
            Set-LocalUser -Name $user -Password $newPass
        }

        Invoke-Step -Name "Disable then enable $user" -Delay $Delay -GoodCount ([ref]$good) -BadCount ([ref]$bad) -Action {
            Disable-LocalUser -Name $user
            Enable-LocalUser -Name $user
        }

        if (-not $NoReboot) {
            Invoke-Step -Name "Set RunOnce + reboot (report test)" -Delay 0 -GoodCount ([ref]$good) -BadCount ([ref]$bad) -Action {
                Set-RunOnceResume -ScriptPathToRun $ScriptPath
                Write-Warning "Server restarting. You will be logged out. Script will continue after login (RunOnce)."
                Start-Sleep -Seconds 5
                Restart-Computer -Force
            }
        } else {
            Write-Host "Reboot skipped (-NoReboot specified)." -ForegroundColor Yellow
        }

        Invoke-Step -Name "Approved privileged access using $user" -Delay $Delay -GoodCount ([ref]$good) -BadCount ([ref]$bad) -Action {
            Ensure-ServiceRunning -Name 'seclogon'
            Add-LocalGroupMember -Group "Administrators" -Member $user
            $cred = New-Object System.Management.Automation.PSCredential ($user, $newPass)
            Start-ProcessAsCredentialAndStop -Credential $cred -RunSeconds 5
        }

        Invoke-Step -Name "Add $user to local Administrators" -Delay $Delay -GoodCount ([ref]$good) -BadCount ([ref]$bad) -Action {
            Add-LocalGroupMember -Group "Administrators" -Member $user
        }

        Invoke-Step -Name "Remove local user ($user)" -Delay $Delay -GoodCount ([ref]$good) -BadCount ([ref]$bad) -Action {
            Remove-LocalUser -Name $user -ErrorAction SilentlyContinue
        }

        Write-Host "`nSteps Completed Successfully: $good" -ForegroundColor Green
        Write-Host "Steps Failed: $bad" -ForegroundColor Red
    }
    finally {
        try { Remove-LocalUser -Name $user -ErrorAction SilentlyContinue } catch {}
    }
}

function ShowMenu {
    param([string]$Title = "Perform Wintel Tests on")
    Clear-Host
    Write-Output "================ $Title $env:COMPUTERNAME ================`n"
    Write-Output "1: Run Alert Based Wintel Tests`n"
    Write-Output "2: Run Report Based Wintel Tests`n"
    Write-Output "Q: Press 'Q' to quit`n"
}

# --- Pre-flight checks ---
if (-not (Test-IsAdministrator)) {
    throw "This script must be run as Administrator."
}

# --- Entry point ---
switch ($Mode) {
    'Alerts'  { Invoke-AlertsTests  -Delay $DelaySeconds -AllowClearEventLogs:$AllowClearEventLogs -AllowTimeChange:$AllowTimeChange -NoReboot:$NoReboot -ScriptPath $ScriptPath; break }
    'Reports' { Invoke-ReportsTests -Delay $DelaySeconds -NoReboot:$NoReboot -ScriptPath $ScriptPath; break }
    default {
        do {
            ShowMenu
            $sel = Read-Host "Please make a selection"
            switch ($sel.ToLower()) {
                '1' { Invoke-AlertsTests  -Delay $DelaySeconds -AllowClearEventLogs:$AllowClearEventLogs -AllowTimeChange:$AllowTimeChange -NoReboot:$NoReboot -ScriptPath $ScriptPath }
                '2' { Invoke-ReportsTests -Delay $DelaySeconds -NoReboot:$NoReboot -ScriptPath $ScriptPath }
                'q' { Write-Host "Closing Session..." -BackgroundColor Red -ForegroundColor White; return }
            }
            Pause
        } until ($sel -eq 'q')
    }
}