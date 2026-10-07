# Halcyon Anti-Ransomware - Intune Detection Script

$AppName         = "Halcyon"
$FilePath        = "C:\Program Files\Halcyon\HalcyonAR\agent.exe"
$RequiredVersion = [version]"2.0.2512.43"

try {
    # Check that the executable exists
    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) {
        Write-Output "$AppName not detected. File not found: $FilePath"
        exit 1
    }

    # Retrieve file version information
    $File = Get-Item -LiteralPath $FilePath -ErrorAction Stop
    $VersionString = $File.VersionInfo.FileVersion

    # Ensure a version was returned
    if ([string]::IsNullOrWhiteSpace($VersionString)) {
        Write-Output "$AppName detected, but no file version information is available."
        exit 1
    }

    # Extract numeric version
    # Handles values such as:
    # 2.0.2512.43
    # 2.0.2512.43 (release)
    if ($VersionString -notmatch '\d+(?:\.\d+){1,3}') {
        Write-Output "$AppName detected, but file version '$VersionString' could not be parsed."
        exit 1
    }

    $InstalledVersion = [version]$Matches[0]

    # Compare installed version against required version
    if ($InstalledVersion -ge $RequiredVersion) {
        Write-Output "$AppName $InstalledVersion detected. Required version: $RequiredVersion."
        exit 0
    }
    else {
        Write-Output "$AppName $InstalledVersion detected, but version $RequiredVersion or later is required."
        exit 1
    }
}
catch {
    Write-Output "$AppName detection failed: $($_.Exception.Message)"
    exit 1
}