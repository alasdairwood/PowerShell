$ErrorActionPreference = "SilentlyContinue"

Write-Output "Starting Teams Classic cleanup..."

# Remove Teams Machine-Wide Installer
$MachineWide = Get-ItemProperty `
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*", `
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" `
    -ErrorAction SilentlyContinue |
    Where-Object {
        $_.DisplayName -eq "Teams Machine-Wide Installer"
    }

foreach ($App in $MachineWide) {
    Write-Output "Removing Teams Machine-Wide Installer"

    if ($App.UninstallString) {
        $ProductCode = ($App.UninstallString -replace '.*?(\{.*\}).*','$1')

        if ($ProductCode -match '^\{.+\}$') {
            Start-Process msiexec.exe `
                -ArgumentList "/x $ProductCode /qn /norestart" `
                -Wait
        }
    }
}

# Process each user profile
$Users = Get-ChildItem "C:\Users" -Directory |
    Where-Object {
        $_.Name -notin @(
            'Public',
            'Default',
            'Default User',
            'All Users'
        )
    }

foreach ($User in $Users) {

    Write-Output "Checking profile: $($User.Name)"

    $TeamsFolder = Join-Path $User.FullName "AppData\Local\Microsoft\Teams"
    $UpdateExe   = Join-Path $TeamsFolder "Update.exe"

    # Uninstall Teams Classic
    if (Test-Path $UpdateExe) {

        Write-Output "Attempting uninstall for $($User.Name)"

        Start-Process `
            -FilePath $UpdateExe `
            -ArgumentList "--uninstall /s" `
            -Wait `
            -WindowStyle Hidden
    }

    # Stop any remaining Teams processes
    Get-Process Teams -ErrorAction SilentlyContinue | Stop-Process -Force

    # Remove Teams folders
    $FoldersToRemove = @(
        "$($User.FullName)\AppData\Local\Microsoft\Teams",
        "$($User.FullName)\AppData\Roaming\Microsoft\Teams"
    )

    foreach ($Folder in $FoldersToRemove) {
        if (Test-Path $Folder) {
            Write-Output "Removing $Folder"
            Remove-Item $Folder -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # Remove desktop shortcut
    $DesktopShortcut = "$($User.FullName)\Desktop\Microsoft Teams.lnk"

    if (Test-Path $DesktopShortcut) {
        Remove-Item $DesktopShortcut -Force
    }
}

Write-Output "Teams Classic cleanup completed"
exit 0