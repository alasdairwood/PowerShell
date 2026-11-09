<#
.SYNOPSIS
    Removes Microsoft Excel 2016 MSI update KB5002934 by processing the exact
    Windows Installer product-to-patch associations registered on the device.

.DESCRIPTION
    Production remediation script for Microsoft Intune Remediations.

    The script:
      Runs safely under SYSTEM in 64-bit PowerShell.
      Detects MSI and Click-to-Run Office installations.
      Treats Click-to-Run as not applicable because KB5002934 is MSI-only.
      Finds every registered KB5002934 ProductCode/PatchCode association.
      Deduplicates associations before removal.
      Stops Excel only when remediation is required.
      Removes each association with msiexec.exe.
      Uses fully silent operation when running under SYSTEM.
      Creates a separate verbose MSI log for every removal attempt.
      Verifies that no KB5002934 association remains.
      Returns exit code 0 only when compliant or not applicable.

.EXIT CODES
    0 = KB absent, successfully removed, or not applicable.
    1 = Detection/removal/verification failure.

.NOTES
    Intune settings:
      Run this script using logged-on credentials: No
      Run script in 64-bit PowerShell: Yes
      Enforce script signature check: According to organisational policy

    KB5002934 is a security update. Use this rollback only as an approved,
    temporary mitigation and monitor for a corrected or superseding update.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$TargetKB = 'KB5002934'
$PatchRegistryRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products'
$IntuneLogRoot = Join-Path $env:ProgramData 'Microsoft\IntuneManagementExtension\Logs'
$FallbackLogRoot = Join-Path $env:ProgramData 'KB5002934-Remediation\Logs'
$LogRoot = if (Test-Path -LiteralPath (Split-Path $IntuneLogRoot -Parent)) { $IntuneLogRoot } else { $FallbackLogRoot }
$MainLog = Join-Path $LogRoot 'Remove-KB5002934.log'
$MsiLogRoot = Join-Path $LogRoot 'KB5002934-MSI'
$MsiExec = Join-Path $env:SystemRoot 'System32\msiexec.exe'
$RestartRequired = $false

function Initialize-Logging {
    foreach ($Path in @($LogRoot, $MsiLogRoot)) {
        if (-not (Test-Path -LiteralPath $Path)) {
            New-Item -Path $Path -ItemType Directory -Force | Out-Null
        }
    }
}

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('INFO', 'WARNING', 'ERROR')]
        [string]$Level = 'INFO'
    )

    $Entry = '[{0}] [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Add-Content -LiteralPath $MainLog -Value $Entry -Encoding UTF8
    Write-Output $Entry
}

function Get-SafePropertyValue {
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][string]$PropertyName
    )

    if ($null -eq $InputObject) { return $null }
    $Property = $InputObject.PSObject.Properties[$PropertyName]
    if ($null -eq $Property) { return $null }
    return $Property.Value
}

function ConvertFrom-PackedGuid {
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[0-9A-Fa-f]{32}$')]
        [string]$PackedGuid
    )

    $Value = $PackedGuid.ToUpperInvariant()
    $Part1 = -join $Value.Substring(0, 8).ToCharArray()[7..0]
    $Part2 = -join $Value.Substring(8, 4).ToCharArray()[3..0]
    $Part3 = -join $Value.Substring(12, 4).ToCharArray()[3..0]
    $Remaining = $Value.Substring(16, 16)
    $ReversedPairs = New-Object System.Text.StringBuilder

    for ($Index = 0; $Index -lt $Remaining.Length; $Index += 2) {
        [void]$ReversedPairs.Append($Remaining[$Index + 1])
        [void]$ReversedPairs.Append($Remaining[$Index])
    }

    $Part4And5 = $ReversedPairs.ToString()
    return '{{{0}-{1}-{2}-{3}-{4}}}' -f $Part1, $Part2, $Part3, $Part4And5.Substring(0, 4), $Part4And5.Substring(4, 12)
}

function Test-TargetKBReference {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return $false
    }

    return ([string]$Value -match '(?i)(?:KB\s*)?5002934')
}

function Get-OfficeType {
    $ClickToRunPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\ClickToRun\Configuration'
    )

    foreach ($Path in $ClickToRunPaths) {
        if (-not (Test-Path -LiteralPath $Path)) {
            continue
        }

        $Configuration = Get-ItemProperty -LiteralPath $Path -ErrorAction SilentlyContinue
        if ($null -ne $Configuration -and
            ((Get-SafePropertyValue -InputObject $Configuration -PropertyName 'ProductReleaseIds') -or (Get-SafePropertyValue -InputObject $Configuration -PropertyName 'ClientVersionToReport') -or (Get-SafePropertyValue -InputObject $Configuration -PropertyName 'InstallationPath'))) {
            return [PSCustomObject]@{
                Type       = 'ClickToRun'
                Version    = Get-SafePropertyValue -InputObject $Configuration -PropertyName 'ClientVersionToReport'
                Platform   = Get-SafePropertyValue -InputObject $Configuration -PropertyName 'Platform'
                ProductIDs = Get-SafePropertyValue -InputObject $Configuration -PropertyName 'ProductReleaseIds'
            }
        }
    }

    $ExcelCandidates = @(
        [PSCustomObject]@{ Path = (Join-Path $env:ProgramFiles 'Microsoft Office\Office16\EXCEL.EXE'); Platform = 'x64' },
        [PSCustomObject]@{ Path = $(if (${env:ProgramFiles(x86)}) { Join-Path ${env:ProgramFiles(x86)} 'Microsoft Office\Office16\EXCEL.EXE' } else { $null }); Platform = 'x86' }
    )

    foreach ($Candidate in $ExcelCandidates) {
        if (-not [string]::IsNullOrWhiteSpace($Candidate.Path) -and (Test-Path -LiteralPath $Candidate.Path)) {
            $ExcelFile = Get-Item -LiteralPath $Candidate.Path
            return [PSCustomObject]@{
                Type       = 'MSI'
                Version    = $ExcelFile.VersionInfo.FileVersion
                Platform   = $Candidate.Platform
                ProductIDs = $null
            }
        }
    }

    return [PSCustomObject]@{
        Type       = 'NotDetected'
        Version    = $null
        Platform   = $null
        ProductIDs = $null
    }
}

function Get-TargetPatchAssociations {
    $Results = New-Object System.Collections.Generic.List[object]

    if (-not (Test-Path -LiteralPath $PatchRegistryRoot)) {
        return @()
    }

    $ProductRegistrations = Get-ChildItem -LiteralPath $PatchRegistryRoot -ErrorAction SilentlyContinue

    foreach ($ProductRegistration in $ProductRegistrations) {
        $PatchesPath = Join-Path $ProductRegistration.PSPath 'Patches'
        if (-not (Test-Path -LiteralPath $PatchesPath)) {
            continue
        }

        $PatchRegistrations = Get-ChildItem -LiteralPath $PatchesPath -ErrorAction SilentlyContinue

        foreach ($PatchRegistration in $PatchRegistrations) {
            $Properties = Get-ItemProperty -LiteralPath $PatchRegistration.PSPath -ErrorAction SilentlyContinue
            if ($null -eq $Properties) {
                continue
            }

            $SearchValues = @(
                Get-SafePropertyValue -InputObject $Properties -PropertyName 'DisplayName'
                Get-SafePropertyValue -InputObject $Properties -PropertyName 'PatchName'
                Get-SafePropertyValue -InputObject $Properties -PropertyName 'KBArticle'
                Get-SafePropertyValue -InputObject $Properties -PropertyName 'MoreInfoURL'
                Get-SafePropertyValue -InputObject $Properties -PropertyName 'HelpLink'
                Get-SafePropertyValue -InputObject $Properties -PropertyName 'Comments'
            )

            $Matched = $false
            foreach ($SearchValue in $SearchValues) {
                if (Test-TargetKBReference -Value $SearchValue) {
                    $Matched = $true
                    break
                }
            }

            if (-not $Matched) {
                continue
            }

            try {
                $Results.Add([PSCustomObject]@{
                    DisplayName  = Get-SafePropertyValue -InputObject $Properties -PropertyName 'DisplayName'
                    ProductCode  = ConvertFrom-PackedGuid -PackedGuid $ProductRegistration.PSChildName
                    PatchCode    = ConvertFrom-PackedGuid -PackedGuid $PatchRegistration.PSChildName
                    LocalPackage = Get-SafePropertyValue -InputObject $Properties -PropertyName 'LocalPackage'
                    RegistryPath = $PatchRegistration.PSPath
                })
            }
            catch {
                Write-Log -Message "Could not convert an Installer GUID at '$($PatchRegistration.PSPath)': $($_.Exception.Message)" -Level 'WARNING'
            }
        }
    }

    return @($Results | Sort-Object ProductCode, PatchCode -Unique)
}

function Stop-ExcelProcess {
    $ExcelProcesses = @(Get-Process -Name 'EXCEL' -ErrorAction SilentlyContinue)
    if ($ExcelProcesses.Count -eq 0) {
        Write-Log -Message 'EXCEL.EXE is not running.'
        return
    }

    foreach ($ExcelProcess in $ExcelProcesses) {
        Write-Log -Message "Stopping EXCEL.EXE. ProcessId=$($ExcelProcess.Id). Unsaved work may be lost." -Level 'WARNING'
        Stop-Process -Id $ExcelProcess.Id -Force -ErrorAction Stop
    }

    Start-Sleep -Seconds 3
}

function Invoke-PatchRemoval {
    param(
        [Parameter(Mandatory)][string]$ProductCode,
        [Parameter(Mandatory)][string]$PatchCode,
        [Parameter(Mandatory)][string]$MsiLogFile
    )

    $ArgumentString = @(
        '/package',
        ('"{0}"' -f $ProductCode),
        '/uninstall',
        ('"{0}"' -f $PatchCode),
        '/qn',
        '/norestart',
        'REBOOT=ReallySuppress',
        '/L*v',
        ('"{0}"' -f $MsiLogFile)
    ) -join ' '

    Write-Log -Message "Executing msiexec.exe for ProductCode='$ProductCode'; PatchCode='$PatchCode'."

    $Process = Start-Process -FilePath $MsiExec -ArgumentList $ArgumentString -Wait -PassThru -WindowStyle Hidden
    $ExitCode = $Process.ExitCode

    Write-Log -Message "msiexec.exe returned exit code '$ExitCode'. MSI log='$MsiLogFile'."
    return $ExitCode
}

try {
    Initialize-Logging
    Write-Log -Message "Starting $TargetKB remediation. User='$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)'; PowerShell64Bit='$([Environment]::Is64BitProcess)'."

    if (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) {
        Write-Log -Message 'The script is running in 32-bit PowerShell on 64-bit Windows. Configure Intune to use 64-bit PowerShell.' -Level 'ERROR'
        exit 1
    }

    if (-not (Test-Path -LiteralPath $MsiExec)) {
        Write-Log -Message "Windows Installer was not found at '$MsiExec'." -Level 'ERROR'
        exit 1
    }

    $Office = Get-OfficeType
    Write-Log -Message "Office detection: Type='$($Office.Type)'; Version='$($Office.Version)'; Platform='$($Office.Platform)'."

    if ($Office.Type -eq 'ClickToRun') {
        Write-Log -Message "$TargetKB is not applicable to Click-to-Run Office. No action required."
        exit 0
    }

    $Associations = @(Get-TargetPatchAssociations)

    if ($Associations.Count -eq 0) {
        Write-Log -Message "$TargetKB was not detected. Device is compliant."
        exit 0
    }

    Write-Log -Message "Detected $($Associations.Count) unique $TargetKB product-to-patch association(s)."
    Stop-ExcelProcess

    $RemovalFailures = New-Object System.Collections.Generic.List[string]

    foreach ($Association in $Associations) {
        $SafeProductCode = $Association.ProductCode.Trim('{}')
        $SafePatchCode = $Association.PatchCode.Trim('{}')
        $MsiLogFile = Join-Path $MsiLogRoot ("KB5002934-{0}-{1}.log" -f $SafeProductCode, $SafePatchCode)

        try {
            $ExitCode = Invoke-PatchRemoval -ProductCode $Association.ProductCode -PatchCode $Association.PatchCode -MsiLogFile $MsiLogFile

            switch ($ExitCode) {
                0 {
                    Write-Log -Message "Association removed successfully: ProductCode='$($Association.ProductCode)'."
                }
                1605 {
                    Write-Log -Message "Product is no longer installed: ProductCode='$($Association.ProductCode)'." -Level 'WARNING'
                }
                1614 {
                    Write-Log -Message "Product or patch is already uninstalled: ProductCode='$($Association.ProductCode)'." -Level 'WARNING'
                }
                1641 {
                    $RestartRequired = $true
                    Write-Log -Message "Association removed and restart initiated: ProductCode='$($Association.ProductCode)'." -Level 'WARNING'
                }
                1647 {
                    Write-Log -Message "Patch is not currently applied to ProductCode='$($Association.ProductCode)'. Final verification will determine compliance." -Level 'WARNING'
                }
                3010 {
                    $RestartRequired = $true
                    Write-Log -Message "Association removed; restart required: ProductCode='$($Association.ProductCode)'." -Level 'WARNING'
                }
                default {
                    $RemovalFailures.Add("ProductCode=$($Association.ProductCode); PatchCode=$($Association.PatchCode); ExitCode=$ExitCode")
                    Write-Log -Message "Removal returned an unsuccessful MSI exit code '$ExitCode' for ProductCode='$($Association.ProductCode)'." -Level 'ERROR'
                }
            }
        }
        catch {
            $RemovalFailures.Add("ProductCode=$($Association.ProductCode); PatchCode=$($Association.PatchCode); Error=$($_.Exception.Message)")
            Write-Log -Message "Removal exception for ProductCode='$($Association.ProductCode)': $($_.Exception.Message)" -Level 'ERROR'
        }
    }

    Start-Sleep -Seconds 10
    $RemainingAssociations = @(Get-TargetPatchAssociations)

    if ($RemainingAssociations.Count -gt 0) {
        $Remaining = ($RemainingAssociations | ForEach-Object { "$($_.ProductCode)/$($_.PatchCode)" }) -join '; '
        Write-Log -Message "Verification failed. $TargetKB remains registered in $($RemainingAssociations.Count) association(s): $Remaining" -Level 'ERROR'
        exit 1
    }

    if ($RemovalFailures.Count -gt 0) {
        Write-Log -Message "Final verification passed, although some removal attempts returned errors: $($RemovalFailures -join ' | ')" -Level 'WARNING'
    }

    if ($RestartRequired) {
        Write-Log -Message "$TargetKB was removed successfully. Windows Installer reported that a restart is required."
    }
    else {
        Write-Log -Message "$TargetKB was removed successfully and is no longer detected. A restart is recommended before testing Excel."
    }

    exit 0
}
catch {
    try {
        Initialize-Logging
        Write-Log -Message "Unhandled remediation error: $($_.Exception.Message)" -Level 'ERROR'
    }
    catch {
        Write-Output "Unhandled remediation error: $($_.Exception.Message)"
    }

    exit 1
}