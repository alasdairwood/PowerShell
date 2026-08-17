# Detect Teams Classic

$TeamsFound = $false

# Machine-wide installer
$MachineWide = Get-ItemProperty `
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" `
    -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -eq "Teams Machine-Wide Installer" }

if ($MachineWide) {
    Write-Output "Teams Machine-Wide Installer found"
    $TeamsFound = $true
}

# User profile installations
$Users = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue

foreach ($User in $Users) {
    $TeamsExe = Join-Path $User.FullName "AppData\Local\Microsoft\Teams\Current\Teams.exe"

    if (Test-Path $TeamsExe) {
        $Version = (Get-Item $TeamsExe).VersionInfo.ProductVersion
        Write-Output "Teams Classic found: $($User.Name) - $Version"
        $TeamsFound = $true
    }
}

if ($TeamsFound) {
    exit 1
}
else {
    Write-Output "Teams Classic not found"
    exit 0
}