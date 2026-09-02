$shortcutName = "OneDrive Photos.lnk"
$found = $false

$searchLocations = @(
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs",
    "$env:PUBLIC\Desktop"
)

foreach ($location in $searchLocations) {
    $shortcut = Join-Path $location $shortcutName

    if (Test-Path -LiteralPath $shortcut) {
        Write-Output "Found shortcut: $shortcut"
        $found = $true
    }
}

$userFolders = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue

foreach ($user in $userFolders) {

    $userShortcut = Join-Path $user.FullName "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\$shortcutName"

    if (Test-Path -LiteralPath $userShortcut) {
        Write-Output "Found shortcut: $userShortcut"
        $found = $true
    }
}

if ($found) {
    exit 1
}

Write-Output "OneDrive Photos shortcut not detected."
exit 0