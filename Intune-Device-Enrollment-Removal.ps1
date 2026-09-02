<#
.SYNOPSIS
    Removes a stale Microsoft Intune MDM enrollment from a Windows device.

.DESCRIPTION
    Identifies the current Intune enrollment ID from the OMADM logger registry
    location and removes associated scheduled tasks, registry keys, and MDM
    certificates.

.NOTES
    Author: NHS Lanarkshire
    Version: 1.0
    Requires: Local Administrator permissions
#>

[CmdletBinding()]
param ()

#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'

function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('INFO','WARN','ERROR')]
        [string]$Level = 'INFO'
    )

    Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
}

function Remove-RegistryKey {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (Test-Path -Path $Path) {
        try {
            Remove-Item -Path $Path -Recurse -Force
            Write-Log "Removed registry key: $Path"
        }
        catch {
            Write-Log "Failed to remove registry key: $Path. $_" -Level ERROR
        }
    }
}

function Remove-CertificateByIssuer {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$IssuerPattern
    )

    try {
        $certificates = Get-ChildItem -Path Cert:\LocalMachine\My |
            Where-Object { $_.Issuer -match $IssuerPattern }

        foreach ($certificate in $certificates) {
            try {
                Remove-Item -Path $certificate.PSPath -Force
                Write-Log "Removed certificate: $($certificate.Subject)"
            }
            catch {
                Write-Log "Failed to remove certificate: $($certificate.Subject). $_" -Level ERROR
            }
        }
    }
    catch {
        Write-Log "Failed to enumerate certificates matching '$IssuerPattern'. $_" -Level ERROR
    }
}

try {
    Write-Log "Locating Intune enrollment ID..."

    $enrollment = Get-ItemProperty `
        -Path 'HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger' `
        -Name 'CurrentEnrollmentId' `
        -ErrorAction Stop

    $enrollmentId = $enrollment.CurrentEnrollmentId

    if (:IsNullOrWhiteSpace($enrollmentId)) {
        Write-Log "No Intune enrollment ID found."
        return
    }

    Write-Log "Found enrollment ID: $enrollmentId"

    # Remove Scheduled Tasks
    try {
        Write-Log "Removing scheduled tasks..."

        $scheduleService = New-Object -ComObject Schedule.Service
        $scheduleService.Connect()

        $taskFolderPath = "\Microsoft\Windows\EnterpriseMgmt\$enrollmentId"

        $taskFolder = $scheduleService.GetFolder($taskFolderPath)

        foreach ($task in $taskFolder.GetTasks(1)) {
            try {
                $taskFolder.DeleteTask($task.Name, 0)
                Write-Log "Deleted scheduled task: $($task.Name)"
            }
            catch {
                Write-Log "Failed to delete scheduled task: $($task.Name). $_" -Level ERROR
            }
        }

        $rootFolder = $scheduleService.GetFolder('\Microsoft\Windows\EnterpriseMgmt')
        $rootFolder.DeleteFolder($enrollmentId, 0)

        Write-Log "Deleted EnterpriseMgmt task folder."
    }
    catch {
        Write-Log "Failed to remove scheduled tasks. $_" -Level WARN
    }

    # Registry cleanup
    Write-Log "Removing enrollment registry keys..."

    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Enrollments\$enrollmentId"
        "HKLM:\SOFTWARE\Microsoft\Enrollments\Status\$enrollmentId"
        "HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked\$enrollmentId"
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\AdmxInstalled\$enrollmentId"
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers\$enrollmentId"
        "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\$enrollmentId"
        "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger\$enrollmentId"
        "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Sessions\$enrollmentId"
    )

    foreach ($path in $registryPaths) {
        Remove-RegistryKey -Path $path
    }

    try {
        Remove-ItemProperty `
            -Path 'HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger' `
            -Name 'CurrentEnrollmentId' `
            -Force `
            -ErrorAction SilentlyContinue

        Write-Log "Removed CurrentEnrollmentId registry value."
    }
    catch {
        Write-Log "Failed to remove CurrentEnrollmentId registry value. $_" -Level WARN
    }

    # Certificate cleanup
    Write-Log "Removing Intune certificates..."

    Remove-CertificateByIssuer -IssuerPattern 'CN=Microsoft Intune MDM Device CA'
    Remove-CertificateByIssuer -IssuerPattern 'CN=SC_Online_Issuing'

    Write-Log "Intune enrollment cleanup completed successfully."
}
catch {
    Write-Log "No Intune enrollment found or cleanup failed. $_" -Level ERROR
    exit 1
}

exit 0