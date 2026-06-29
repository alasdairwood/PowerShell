<#
.SYNOPSIS
Remediation script for Intune Remediations.

.DESCRIPTION
Attempts to remove KB5094126 using WUSA.
Checks pending reboot state.
Logs to Intune Management Extension log folder.
Attempts to show a reboot toast notification to the logged-on user.

Exit codes:
0 = Remediation completed / no action required
1 = Remediation failed
3010 = Remediation completed, reboot required
#>

$KB = "KB5094126"
$KBNumber = $KB.Replace("KB", "")
$LogPath = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Remove-$KB-Remediation.log"
$ToastScriptPath = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Show-$KB-RebootToast.ps1"
$ToastTaskName = "Intune-$KB-RebootNotification"

function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Line = "$Timestamp [$Level] $Message"
    Write-Output $Line

    try {
        Add-Content -Path $LogPath -Value $Line -ErrorAction SilentlyContinue
    }
    catch {
        Write-Output "Failed to write to log file: $($_.Exception.Message)"
    }
}

function Test-PendingReboot {
    $Pending = $false
    $Reasons = @()

    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
        $Pending = $true
        $Reasons += "Component Based Servicing RebootPending"
    }

    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootInProgress") {
        $Pending = $true
        $Reasons += "Component Based Servicing RebootInProgress"
    }

    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
        $Pending = $true
        $Reasons += "Windows Update RebootRequired"
    }

    $SessionManager = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
    $PendingFileRename = Get-ItemProperty -Path $SessionManager -Name PendingFileRenameOperations -ErrorAction SilentlyContinue

    if ($null -ne $PendingFileRename) {
        $Pending = $true
        $Reasons += "PendingFileRenameOperations"
    }

    [PSCustomObject]@{
        Pending = $Pending
        Reasons = $Reasons
    }
}

function Test-KBInstalled {
    param (
        [string]$KBId
    )

    try {
        $HotFix = Get-HotFix -Id $KBId -ErrorAction SilentlyContinue

        if ($null -ne $HotFix) {
            return $true
        }
    }
    catch {
        Write-Log "Get-HotFix failed while checking $KBId`: $($_.Exception.Message)" "WARN"
    }

    return $false
}

function Get-LoggedOnUser {
    try {
        $ExplorerProcess = Get-CimInstance Win32_Process -Filter "Name = 'explorer.exe'" -ErrorAction SilentlyContinue |
            Select-Object -First 1

        if ($null -eq $ExplorerProcess) {
            return $null
        }

        $Owner = Invoke-CimMethod -InputObject $ExplorerProcess -MethodName GetOwner -ErrorAction SilentlyContinue

        if ($Owner.User -and $Owner.Domain) {
            return "$($Owner.Domain)\$($Owner.User)"
        }

        return $null
    }
    catch {
        Write-Log "Failed to determine logged-on user: $($_.Exception.Message)" "WARN"
        return $null
    }
}

function New-RebootToastScript {
    param (
        [string]$Path,
        [string]$KBId
    )

$ToastScript = @"
`$Title = "Restart required"
`$Message1 = "$KBId has been removed from this device."
`$Message2 = "Please restart your PC to complete the update rollback."

try {
    [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
    [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null

    `$Template = [Windows.UI.Notifications.ToastTemplateType]::ToastText02
    `$Xml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent(`$Template)

    `$TextNodes = `$Xml.GetElementsByTagName("text")
    `$TextNodes.Item(0).AppendChild(`$Xml.CreateTextNode(`$Title)) | Out-Null
    `$TextNodes.Item(1).AppendChild(`$Xml.CreateTextNode("`$Message1 `$Message2")) | Out-Null

    `$Toast = [Windows.UI.Notifications.ToastNotification]::new(`$Xml)

    # This AppID usually works on managed Windows devices.
    `$Notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Microsoft.IntuneManagementExtension")
    `$Notifier.Show(`$Toast)
}
catch {
    # Fallback for environments where native toast is blocked.
    try {
        msg.exe * "$KBId has been removed. Please restart your PC to complete the rollback."
    }
    catch {
        # Suppress fallback errors.
    }
}
"@

    try {
        Set-Content -Path $Path -Value $ToastScript -Encoding UTF8 -Force
        Write-Log "Toast script created at $Path"
        return $true
    }
    catch {
        Write-Log "Failed to create toast script: $($_.Exception.Message)" "WARN"
        return $false
    }
}

function Show-RebootNotification {
    param (
        [string]$KBId
    )

    $LoggedOnUser = Get-LoggedOnUser

    if ([string]::IsNullOrWhiteSpace($LoggedOnUser)) {
        Write-Log "No logged-on interactive user detected. Toast notification skipped." "WARN"
        return
    }

    Write-Log "Logged-on user detected: $LoggedOnUser"

    $Created = New-RebootToastScript -Path $ToastScriptPath -KBId $KBId

    if (-not $Created) {
        Write-Log "Toast script could not be created. Notification skipped." "WARN"
        return
    }

    try {
        $ExistingTask = Get-ScheduledTask -TaskName $ToastTaskName -ErrorAction SilentlyContinue

        if ($null -ne $ExistingTask) {
            Unregister-ScheduledTask -TaskName $ToastTaskName -Confirm:$false -ErrorAction SilentlyContinue
            Write-Log "Existing scheduled toast task removed."
        }

        $Action = New-ScheduledTaskAction `
            -Execute "powershell.exe" `
            -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ToastScriptPath`""

        $TriggerTime = (Get-Date).AddMinutes(1)

        $Trigger = New-ScheduledTaskTrigger `
            -Once `
            -At $TriggerTime

        $Principal = New-ScheduledTaskPrincipal `
            -UserId $LoggedOnUser `
            -LogonType Interactive `
            -RunLevel Limited

        $Task = New-ScheduledTask `
            -Action $Action `
            -Trigger $Trigger `
            -Principal $Principal `
            -Description "Displays reboot notification after $KBId removal"

        Register-ScheduledTask `
            -TaskName $ToastTaskName `
            -InputObject $Task `
            -Force | Out-Null

        Start-ScheduledTask -TaskName $ToastTaskName -ErrorAction SilentlyContinue

        Write-Log "Toast notification task created and started for $LoggedOnUser."
    }
    catch {
        Write-Log "Failed to create/start toast scheduled task: $($_.Exception.Message)" "WARN"

        try {
            msg.exe * "$KBId has been removed. Please restart your PC to complete the rollback."
            Write-Log "Fallback msg.exe notification attempted."
        }
        catch {
            Write-Log "Fallback msg.exe notification failed: $($_.Exception.Message)" "WARN"
        }
    }
}

Write-Log "============================================================"
Write-Log "Starting remediation for $KB"

$InstalledBefore = Test-KBInstalled -KBId $KB

if (-not $InstalledBefore) {
    Write-Log "$KB is not currently detected as installed."

    $RebootStatus = Test-PendingReboot

    if ($RebootStatus.Pending) {
        Write-Log "Device is already pending reboot. Reasons: $($RebootStatus.Reasons -join ', ')" "WARN"
        Show-RebootNotification -KBId $KB
        exit 3010
    }

    Write-Log "No remediation required."
    exit 0
}

Write-Log "$KB detected. Attempting removal using WUSA."

$Arguments = "/uninstall /kb:$KBNumber /quiet /norestart"

try {
    $Process = Start-Process `
        -FilePath "wusa.exe" `
        -ArgumentList $Arguments `
        -Wait `
        -PassThru `
        -WindowStyle Hidden

    $ExitCode = $Process.ExitCode
    Write-Log "WUSA completed with exit code: $ExitCode"
}
catch {
    Write-Log "Failed to start WUSA uninstall: $($_.Exception.Message)" "ERROR"
    exit 1
}

Start-Sleep -Seconds 10

$InstalledAfter = Test-KBInstalled -KBId $KB
$RebootStatusAfter = Test-PendingReboot

if ($InstalledAfter) {
    Write-Log "$KB still appears installed after WUSA execution." "WARN"

    if ($RebootStatusAfter.Pending) {
        Write-Log "Pending reboot detected. Reasons: $($RebootStatusAfter.Reasons -join ', ')"
        Show-RebootNotification -KBId $KB
        exit 3010
    }

    Write-Log "$KB still installed and no pending reboot detected. Remediation failed." "ERROR"
    exit 1
}

if ($RebootStatusAfter.Pending) {
    Write-Log "$KB no longer detected, but reboot is pending. Reasons: $($RebootStatusAfter.Reasons -join ', ')"
    Show-RebootNotification -KBId $KB
    exit 3010
}

Write-Log "$KB removed successfully. No pending reboot detected."
exit 0