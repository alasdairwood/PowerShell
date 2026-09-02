$logFile = "C:\ProgramData\OneDrivePhotosRemediation.log"
$shortcut = "OneDrive Photos.lnk"

$shortcutList = @(
    (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\$shortcut")
    (Join-Path $env:PUBLIC "Desktop\$shortcut")
)

Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $shortcutList += Join-Path $_.FullName "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\$shortcut"
}

Add-Content -Path $logFile -Value "----- $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') -----"

foreach ($item in $shortcutList) {
    if (Test-Path -LiteralPath $item) {
        Remove-Item -LiteralPath $item -Force
        Add-Content -Path $logFile -Value "Removed: $item"
        Write-Output "Removed: $item"
    }
    else {
        Add-Content -Path $logFile -Value "Not found: $item"
    }
}

Add-Content -Path $logFile -Value "Remediation completed.`r`n"

exit 0