<#
.SYNOPSIS
Detection script for Intune Remediations.

.DESCRIPTION
Detects whether KB5094126 is installed or whether the device is pending reboot after removal.

Exit codes:
0 = Compliant - KB not installed and no reboot pending
1 = Non-compliant - KB installed or reboot pending
#>

$KB = "KB5094126"
$LogPath = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Remove-$KB-Detection.log"

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

Write-Log "Starting detection for $KB"

$KBInstalled = $false

try {
    $HotFix = Get-HotFix -Id $KB -ErrorAction SilentlyContinue

    if ($null -ne $HotFix) {
        $KBInstalled = $true
        Write-Log "$KB detected via Get-HotFix."
    }
    else {
        Write-Log "$KB not detected via Get-HotFix."
    }
}
catch {
    Write-Log "Get-HotFix check failed: $($_.Exception.Message)" "WARN"
}

$RebootStatus = Test-PendingReboot

if ($RebootStatus.Pending) {
    Write-Log "Pending reboot detected. Reasons: $($RebootStatus.Reasons -join ', ')" "WARN"
}
else {
    Write-Log "No pending reboot detected."
}

if ($KBInstalled) {
    Write-Log "$KB is installed. Device is non-compliant."
    exit 1
}

if ($RebootStatus.Pending) {
    Write-Log "$KB not detected, but reboot is pending. Device is non-compliant until rebooted."
    exit 1
}

Write-Log "$KB not installed and no reboot pending. Device is compliant."
exit 0