# ============================================================
# Adobe Acrobat Reader
# Remove legacy Reader DC 2017 and install current Reader
# Designed for Intune SYSTEM context
# ============================================================

$ErrorActionPreference = "Stop"

$LogFolder = "C:\ProgramData\NHSL\Logs"
$LogFile   = "$LogFolder\AdobeReader26-Install.log"

if (!(Test-Path $LogFolder)) {
    New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null
}

Start-Transcript -Path $LogFile -Append

try {

    Write-Output "Searching for legacy Adobe Reader installations..."

    $UninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $LegacyAdobe = Get-ItemProperty $UninstallPaths -ErrorAction SilentlyContinue |
        Where-Object {
            $_.DisplayName -match "^Adobe Acrobat Reader DC" -and
            $_.DisplayVersion -like "17.*"
        }

    foreach ($App in $LegacyAdobe) {

        Write-Output "Found legacy installation:"
        Write-Output "$($App.DisplayName) $($App.DisplayVersion)"

        if ($App.PSChildName -match "^\{.*\}$") {

            $ProductCode = $App.PSChildName

            Write-Output "Removing MSI product $ProductCode"

            $Process = Start-Process `
                -FilePath "msiexec.exe" `
                -ArgumentList "/x $ProductCode /qn /norestart" `
                -Wait `
                -PassThru

            Write-Output "Uninstall exit code: $($Process.ExitCode)"

            if ($Process.ExitCode -notin @(0,3010,1605)) {
                throw "Legacy Adobe uninstall failed with code $($Process.ExitCode)"
            }
        }
        else {
            Write-Warning "Adobe installation does not expose an MSI product code."
            Write-Warning "Uninstall string: $($App.UninstallString)"
        }
    }


    # --------------------------------------------------------
    # Install Adobe Acrobat Reader 26.002.21932
    # --------------------------------------------------------

    Write-Output "Installing Adobe Acrobat Reader..."

    $Setup = Join-Path $PSScriptRoot "setup.exe"

    if (!(Test-Path $Setup)) {
        throw "Adobe setup.exe not found."
    }

    $Process = Start-Process `
        -FilePath $Setup `
        -ArgumentList "--silent" `
        -Wait `
        -PassThru

    Write-Output "Adobe installer exit code: $($Process.ExitCode)"

    if ($Process.ExitCode -notin @(0,3010)) {
        throw "Adobe installation failed with code $($Process.ExitCode)"
    }


    # --------------------------------------------------------
    # Verify installation
    # --------------------------------------------------------

    $Adobe = Get-ItemProperty $UninstallPaths -ErrorAction SilentlyContinue |
        Where-Object {
            $_.DisplayName -match "^Adobe Acrobat Reader" -and
            $_.DisplayVersion -match "26.002.21931"
        } |
        Select-Object -First 1

    if (!$Adobe) {
        throw "Adobe Acrobat Reader 26.002.21931 was not detected following installation."
    }

    Write-Output "Successfully installed:"
    Write-Output "$($Adobe.DisplayName) $($Adobe.DisplayVersion)"

    Stop-Transcript
    exit 0
}
catch {

    Write-Error $_
    Stop-Transcript
    exit 1
}