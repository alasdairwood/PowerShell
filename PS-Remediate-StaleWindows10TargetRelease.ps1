<#
.SYNOPSIS
Removes stale Windows Update target release policy values that may pin a device to Windows 10 22H2.

.DESCRIPTION
Intended for Intune Remediations remediation script.

This script removes stale target release values from:
- HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate
- HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState

It does not remove WSUS or scan source values.

.NOTES
Run as 64-bit PowerShell in Intune.
Run using logged-on credentials: No
#>

$ErrorActionPreference = "Continue"

$LogFolder = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs"
$LogFile = Join-Path $LogFolder "Remediate-StaleWindows10TargetRelease.log"

if (-not (Test-Path $LogFolder)) {
    New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null
}

function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )

    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Line = "$TimeStamp [$Level] $Message"

    Write-Output $Line
    Add-Content -Path $LogFile -Value $Line
}

function Remove-RegistryValueIfExists {
    param (
        [string]$Path,
        [string]$Name
    )

    try {
        if (Test-Path $Path) {
            $Item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue

            if ($null -ne $Item) {
                Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction Stop
                Write-Log "Removed registry value '$Name' from '$Path'"
            }
            else {
                Write-Log "Registry value '$Name' not present in '$Path'"
            }
        }
        else {
            Write-Log "Registry path does not exist: $Path"
        }
    }
    catch {
        Write-Log "Failed to remove registry value '$Name' from '$Path'. Error: $($_.Exception.Message)" "ERROR"
    }
}

Write-Log "Starting remediation for stale Windows 10 target release policy values."

$PolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$PolicyStatePath = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState"

# ---------------------------------------------------------------------
# Remove source policy values from classic Windows Update policy path
# ---------------------------------------------------------------------
Write-Log "Checking classic Windows Update policy path."

$PolicyValuesToRemove = @(
    "ProductVersion",
    "TargetReleaseVersion",
    "TargetReleaseVersionInfo"
)

foreach ($Value in $PolicyValuesToRemove) {
    Remove-RegistryValueIfExists -Path $PolicyPath -Name $Value
}

# ---------------------------------------------------------------------
# Remove stale effective policy state values
# ---------------------------------------------------------------------
Write-Log "Checking effective Windows Update PolicyState path."

$PolicyStateValuesToRemove = @(
    "TargetProductVersion",
    "TargetReleaseVersion"
)

foreach ($Value in $PolicyStateValuesToRemove) {
    Remove-RegistryValueIfExists -Path $PolicyStatePath -Name $Value
}

# ---------------------------------------------------------------------
# Restart Windows Update-related services
# ---------------------------------------------------------------------
Write-Log "Restarting Windows Update-related services."

$Services = @(
    "wuauserv",
    "bits",
    "usosvc",
    "dosvc"
)

foreach ($Service in $Services) {
    try {
        $Svc = Get-Service -Name $Service -ErrorAction SilentlyContinue

        if ($null -ne $Svc) {
            if ($Svc.Status -eq "Running") {
                Restart-Service -Name $Service -Force -ErrorAction Stop
                Write-Log "Restarted service: $Service"
            }
            else {
                Start-Service -Name $Service -ErrorAction Stop
                Write-Log "Started service: $Service"
            }
        }
        else {
            Write-Log "Service not found: $Service"
        }
    }
    catch {
        Write-Log "Failed to restart/start service '$Service'. Error: $($_.Exception.Message)" "WARN"
    }
}

# ---------------------------------------------------------------------
# Trigger Windows Update policy refresh and scan
# ---------------------------------------------------------------------
Write-Log "Triggering Windows Update settings refresh."

try {
    Start-Process -FilePath "$env:SystemRoot\System32\UsoClient.exe" -ArgumentList "RefreshSettings" -WindowStyle Hidden -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 10
    Start-Process -FilePath "$env:SystemRoot\System32\UsoClient.exe" -ArgumentList "StartScan" -WindowStyle Hidden -ErrorAction SilentlyContinue
    Write-Log "Triggered UsoClient RefreshSettings and StartScan."
}
catch {
    Write-Log "Failed to trigger UsoClient actions. Error: $($_.Exception.Message)" "WARN"
}

Write-Log "Remediation completed."

exit 0
