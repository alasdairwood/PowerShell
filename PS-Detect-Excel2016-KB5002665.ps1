$ExcelPath = "C:\Program Files\Microsoft Office\Office16\EXCEL.EXE"
$RequiredVersion = [version]"16.0.5569.1006"

if (-not (Test-Path -LiteralPath $ExcelPath)) {
    Write-Output "Excel 2016 x64 not found"
    exit 1
}

try {
    $ExcelFile = Get-Item -LiteralPath $ExcelPath -ErrorAction Stop
    $InstalledVersion = [version]$ExcelFile.VersionInfo.FileVersion

    Write-Output "Installed Excel version: $InstalledVersion"
    Write-Output "Required Excel version: $RequiredVersion"

    if ($InstalledVersion -ge $RequiredVersion) {
        Write-Output "KB5002665 or a later Excel update is detected"
        exit 0
    }

    Write-Output "Excel version is below the required version"
    exit 1
}
catch {
    Write-Output "Detection error: $($_.Exception.Message)"
    exit 1
}