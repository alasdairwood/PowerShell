$Found = $false

$MWI = Get-ItemProperty `
    HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, `
    HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* `
    -ErrorAction SilentlyContinue |
    Where-Object {
        $_.DisplayName -eq "Teams Machine-Wide Installer"
    }

if ($MWI) {
    $Found = $true
}

if (Get-ChildItem "C:\Users\*\AppData\Local\Microsoft\Teams" -ErrorAction SilentlyContinue) {
    $Found = $true
}

if ($Found) {
    Write-Output "Classic Teams remnants found"
    exit 1
}

Write-Output "Compliant"
exit 0