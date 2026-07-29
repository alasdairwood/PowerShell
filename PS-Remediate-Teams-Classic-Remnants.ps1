# Stop Teams processes
Get-Process | Where-Object {
    $_.ProcessName -match "Teams"
} | Stop-Process -Force -ErrorAction SilentlyContinue

# Remove Teams Machine-Wide Installer
$MWI = Get-ItemProperty `
    HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, `
    HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* `
    -ErrorAction SilentlyContinue |
    Where-Object {
        $_.DisplayName -eq "Teams Machine-Wide Installer"
    }

foreach ($App in $MWI) {
    if ($App.UninstallString) {

        if ($App.UninstallString -match "{.*}") {
            $Guid = $matches[0]

            Start-Process msiexec.exe `
                -ArgumentList "/x $Guid /qn /norestart" `
                -Wait
        }
    }
}

# Remove Classic Teams folders from all profiles
Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {

    $Folders = @(
        "$($_.FullName)\AppData\Local\Microsoft\Teams",
        "$($_.FullName)\AppData\Roaming\Microsoft\Teams"
    )

    foreach ($Folder in $Folders) {

        if (Test-Path $Folder) {

            try {
                Remove-Item $Folder -Recurse -Force -ErrorAction Stop
                Write-Output "Removed $Folder"
            }
            catch {
                Write-Warning "Failed to remove $Folder"
            }
        }
    }
}

# Verify New Teams remains installed
$NewTeams = Get-AppxPackage -AllUsers | Where-Object {
    $_.Name -eq "MSTeams"
}

if ($NewTeams) {
    Write-Output "New Teams version: $($NewTeams.Version)"
}
else {
    Write-Warning "New Teams not detected"
}

exit 0