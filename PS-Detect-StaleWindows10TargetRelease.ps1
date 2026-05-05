<#
.SYNOPSIS
Detects stale Windows Update target release policy values that may pin a device to Windows 10 22H2.

.DESCRIPTION
Intended for Intune Remediations detection script.

Returns:
Exit 0 = Compliant / no stale Windows 10 22H2 target release detected
Exit 1 = Non-compliant / stale target release detected

.NOTES
Run as 64-bit PowerShell in Intune.
#>

$ErrorActionPreference = "SilentlyContinue"

$DetectedIssues = New-Object System.Collections.Generic.List[string]

$PolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$PolicyStatePath = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState"
$PolicyManagerPath = "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update"

function Add-Issue {
    param (
        [string]$Message
    )

    if (-not [string]::IsNullOrWhiteSpace($Message)) {
        $DetectedIssues.Add($Message) | Out-Null
    }
}

Write-Output "Checking for stale Windows 10 target release policy values..."

# ---------------------------------------------------------------------
# Check classic policy path
# ---------------------------------------------------------------------
if (Test-Path $PolicyPath) {
    $PolicyValues = Get-ItemProperty -Path $PolicyPath

    if ($PolicyValues.ProductVersion -eq "Windows 10") {
        Add-Issue "Policy path contains ProductVersion = Windows 10"
    }

    if ($PolicyValues.TargetReleaseVersionInfo -eq "22H2") {
        Add-Issue "Policy path contains TargetReleaseVersionInfo = 22H2"
    }

    if ($PolicyValues.TargetReleaseVersion -eq 1 -and $PolicyValues.ProductVersion -eq "Windows 10") {
        Add-Issue "Policy path has TargetReleaseVersion enabled for Windows 10"
    }
}

# ---------------------------------------------------------------------
# Check effective Windows Update policy state
# ---------------------------------------------------------------------
if (Test-Path $PolicyStatePath) {
    $PolicyStateValues = Get-ItemProperty -Path $PolicyStatePath

    if ($PolicyStateValues.TargetProductVersion -eq "Windows 10") {
        Add-Issue "PolicyState contains TargetProductVersion = Windows 10"
    }

    if ($PolicyStateValues.TargetReleaseVersion -eq "22H2") {
        Add-Issue "PolicyState contains TargetReleaseVersion = 22H2"
    }
}

# ---------------------------------------------------------------------
# Check MDM PolicyManager path
# ---------------------------------------------------------------------
if (Test-Path $PolicyManagerPath) {
    $PolicyManagerValues = Get-ItemProperty -Path $PolicyManagerPath

    if ($PolicyManagerValues.ProductVersion -eq "Windows 10") {
        Add-Issue "PolicyManager contains ProductVersion = Windows 10"
    }

    if ($PolicyManagerValues.TargetReleaseVersionInfo -eq "22H2") {
        Add-Issue "PolicyManager contains TargetReleaseVersionInfo = 22H2"
    }

    if ($PolicyManagerValues.TargetReleaseVersion -eq 1 -and $PolicyManagerValues.ProductVersion -eq "Windows 10") {
        Add-Issue "PolicyManager has TargetReleaseVersion enabled for Windows 10"
    }
}

# ---------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------
if ($DetectedIssues.Count -gt 0) {
    Write-Output "Non-compliant. Stale Windows target release policy detected:"
    foreach ($Issue in $DetectedIssues) {
        Write-Output " - $Issue"
    }

    exit 1
}
else {
    Write-Output "Compliant. No stale Windows 10 22H2 target release policy detected."
    exit 0
}