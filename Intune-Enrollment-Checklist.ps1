<#
.SYNOPSIS
    Verify Intune enrollment prerequisites and trigger enrollment.

.DESCRIPTION
    Checks:
        - Entra join status
        - MDM enrollment status
        - MDM certificate presence
        - Enrollment scheduled tasks
        - Automatic MDM enrollment GPO
        - Existing enrollment IDs

    Optionally triggers MDM enrollment.

.NOTES
    Run as Administrator.
#>

[CmdletBinding()]
param(
    [switch]$TriggerEnrollment
)

function Write-Result {
    param(
        [string]$Check,
        [string]$Status,
        [string]$Details
    )

    [PSCustomObject]@{
        Check   = $Check
        Status  = $Status
        Details = $Details
    }
}

$Results = @()

Write-Host "=== Intune Enrollment Validation ===" -ForegroundColor Cyan

# dsregcmd status
try {
    $DsReg = dsregcmd /status

    $AzureAdJoined = ($DsReg | Select-String 'AzureAdJoined').ToString().Split(':')[-1].Trim()
    $DomainJoined  = ($DsReg | Select-String 'DomainJoined').ToString().Split(':')[-1].Trim()
    $DeviceId      = ($DsReg | Select-String 'DeviceId').ToString().Split(':')[-1].Trim()

    $Results += Write-Result `
        -Check "Join State" `
        -Status "PASS" `
        -Details "AzureAdJoined=$AzureAdJoined DomainJoined=$DomainJoined"
}
catch {
    $Results += Write-Result `
        -Check "Join State" `
        -Status "FAIL" `
        -Details $_.Exception.Message
}

# MDM enrollment ID
try {
    $Enrollment = Get-ItemProperty `
        -Path 'HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger' `
        -Name 'CurrentEnrollmentId' `
        -ErrorAction Stop

    $Results += Write-Result `
        -Check "Current Enrollment" `
        -Status "PASS" `
        -Details $Enrollment.CurrentEnrollmentId
}
catch {
    $Results += Write-Result `
        -Check "Current Enrollment" `
        -Status "WARN" `
        -Details "No CurrentEnrollmentId found"
}

# MDM certificates
$MdmCerts = Get-ChildItem Cert:\LocalMachine\My |
    Where-Object {
        $_.Issuer -match 'Microsoft Intune MDM Device CA' -or
        $_.Issuer -match 'SC_Online_Issuing'
    }

if ($MdmCerts) {
    $Results += Write-Result `
        -Check "MDM Certificate" `
        -Status "PASS" `
        -Details "$($MdmCerts.Count) certificate(s) found"
}
else {
    $Results += Write-Result `
        -Check "MDM Certificate" `
        -Status "FAIL" `
        -Details "No Intune MDM certificates found"
}

# EnterpriseMgmt scheduled tasks
try {
    $Tasks = Get-ScheduledTask `
        -TaskPath "\Microsoft\Windows\EnterpriseMgmt\" `
        -ErrorAction Stop

    $Results += Write-Result `
        -Check "Enrollment Tasks" `
        -Status "PASS" `
        -Details "$($Tasks.Count) task(s) found"
}
catch {
    $Results += Write-Result `
        -Check "Enrollment Tasks" `
        -Status "WARN" `
        -Details "No EnterpriseMgmt tasks found"
}

# Auto enrollment GPO
$GpoPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM"

if (Test-Path $GpoPath) {

    $Policy = Get-ItemProperty $GpoPath

    $Results += Write-Result `
        -Check "MDM Auto Enrollment Policy" `
        -Status "PASS" `
        -Details ($Policy | Out-String).Trim()
}
else {
    $Results += Write-Result `
        -Check "MDM Auto Enrollment Policy" `
        -Status "FAIL" `
        -Details "Policy not configured"
}

# Device Management Event Log
try {
    $RecentEvents = Get-WinEvent `
        -LogName 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin' `
        -MaxEvents 20

    $Results += Write-Result `
        -Check "MDM Event Log" `
        -Status "PASS" `
        -Details "$($RecentEvents.Count) recent events found"
}
catch {
    $Results += Write-Result `
        -Check "MDM Event Log" `
        -Status "FAIL" `
        -Details "Unable to read MDM log"
}

# Display Results
$Results | Format-Table -AutoSize

# Trigger enrollment if requested
if ($TriggerEnrollment) {

    Write-Host ""
    Write-Host "Attempting Intune enrollment..." -ForegroundColor Yellow

    try {

        Start-Process `
            -FilePath "$env:SystemRoot\System32\DeviceEnroller.exe" `
            -ArgumentList "/c /AutoEnrollMDM" `
            -Wait

        Write-Host "DeviceEnroller executed." -ForegroundColor Green
    }
    catch {
        Write-Warning $_.Exception.Message
    }
}

Write-Host ""
Write-Host "=== Recommended Follow-up Checks ===" -ForegroundColor Cyan

Write-Host "1. dsregcmd /status"
Write-Host "2. Settings > Accounts > Access work or school"
Write-Host "3. certlm.msc"
Write-Host "4. Event Viewer > DeviceManagement-Enterprise-Diagnostics-Provider"
Write-Host "5. Intune portal device record"