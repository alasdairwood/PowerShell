# ============================================================
# REMOVE ALL MICROSOFT TEAMS (Classic + New + Machine-Wide)
# INTUNE READY - MIXED WINDOWS 10/11 ENVIRONMENT
# Safe for System context, silent
# ============================================================

$ErrorActionPreference = "SilentlyContinue"

Write-Output "`nStopping Teams processes..."
Get-Process -Name "ms-teams","teams","msteams","update" | Stop-Process -Force

# ------------------------------------------------------------
# Remove New Teams (MSIX / Windows Store)
# ------------------------------------------------------------
Write-Output "Removing New Teams (MSIX)..."
Get-AppxPackage -AllUsers *MSTeams* | ForEach-Object {
    Remove-AppxPackage -Package $_.PackageFullName -AllUsers
}

try {
    $Provisioned = Get-AppxProvisionedPackage -Online -ErrorAction Stop |
        Where-Object { $_.DisplayName -like "*MSTeams*" }

    foreach ($pkg in $Provisioned) {
        Remove-AppxProvisionedPackage -Online -PackageName $pkg.PackageName
    }
}
catch {
    Write-Output "Provisioned package removal skipped (DISM unavailable or restricted)."
}

# ------------------------------------------------------------
# Remove Teams Machine-Wide Installer (MSI)
# ------------------------------------------------------------
Write-Output "Removing Teams Machine-Wide Installer..."
$UninstallKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

foreach ($key in $UninstallKeys) {
    Get-ItemProperty $key | Where-Object { $_.DisplayName -like "*Teams Machine-Wide Installer*" } |
    ForEach-Object {
        Start-Process "msiexec.exe" -ArgumentList "/x $($_.PSChildName) /qn /norestart" -Wait
    }
}

# ------------------------------------------------------------
# Remove Classic Teams From All User Profiles
# ------------------------------------------------------------
Write-Output "Removing Classic Teams from user profiles..."
$Profiles = Get-ChildItem "C:\Users" -Directory

foreach ($profile in $Profiles) {
    $TeamsPath = "$($profile.FullName)\AppData\Local\Microsoft\Teams"
    $UpdateExe = "$TeamsPath\Update.exe"

    if (Test-Path $UpdateExe) {
        Start-Process $UpdateExe -ArgumentList "--uninstall -s" -Wait
    }

    if (Test-Path $TeamsPath) {
        Remove-Item $TeamsPath -Recurse -Force
    }
}

# ------------------------------------------------------------
# Remove Leftover System Folders
# ------------------------------------------------------------
$Folders = @(
    "C:\ProgramData\Microsoft\Teams",
    "C:\Program Files (x86)\Teams Installer"
)

foreach ($folder in $Folders) {
    if (Test-Path $folder) {
        Remove-Item $folder -Recurse -Force
    }
}

# ------------------------------------------------------------
# Clean Registry Entries
# ------------------------------------------------------------
$RunKeys = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
)

foreach ($key in $RunKeys) {
    if (Test-Path $key) {
        Remove-ItemProperty -Path $key -Name "com.squirrel.Teams.Teams" -ErrorAction SilentlyContinue
    }
}

$RegistryPaths = @(
    "HKCU:\Software\Microsoft\Teams",
    "HKLM:\Software\Microsoft\Teams"
)

foreach ($reg in $RegistryPaths) {
    if (Test-Path $reg) {
        Remove-Item $reg -Recurse -Force
    }
}

Write-Output "`nAll Microsoft Teams versions removed."
Write-Output "Device is now clean and ready for AFE Teams installation."
exit 0