<#
.SYNOPSIS
    Detects KB5002934 product-to-patch associations for Intune Remediations.

.DESCRIPTION
    Exit 1: KB5002934 is detected and remediation is required.
    Exit 0: KB5002934 is absent, Office is Click-to-Run/not applicable, or
            detection cannot establish that the target update is installed.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$TargetKB = 'KB5002934'
$PatchRegistryRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products'

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
    $Part1 = -join $Value.Substring(0,8).ToCharArray()[7..0]
    $Part2 = -join $Value.Substring(8,4).ToCharArray()[3..0]
    $Part3 = -join $Value.Substring(12,4).ToCharArray()[3..0]
    $Remaining = $Value.Substring(16,16)
    $Pairs = New-Object System.Text.StringBuilder
    for ($Index=0; $Index -lt $Remaining.Length; $Index+=2) {
        [void]$Pairs.Append($Remaining[$Index+1])
        [void]$Pairs.Append($Remaining[$Index])
    }
    $Part4And5 = $Pairs.ToString()
    return '{{{0}-{1}-{2}-{3}-{4}}}' -f $Part1,$Part2,$Part3,$Part4And5.Substring(0,4),$Part4And5.Substring(4,12)
}

function Test-TargetKBReference {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $false }
    return ([string]$Value -match '(?i)(?:KB\s*)?5002934')
}

function Get-ClickToRunOffice {
    $Paths = @(
        'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\ClickToRun\Configuration'
    )
    foreach ($Path in $Paths) {
        if (-not (Test-Path -LiteralPath $Path)) { continue }
        $Config = Get-ItemProperty -LiteralPath $Path -ErrorAction SilentlyContinue
        $ProductIDs = Get-SafePropertyValue -InputObject $Config -PropertyName 'ProductReleaseIds'
        $Version = Get-SafePropertyValue -InputObject $Config -PropertyName 'ClientVersionToReport'
        $InstallPath = Get-SafePropertyValue -InputObject $Config -PropertyName 'InstallationPath'
        $Platform = Get-SafePropertyValue -InputObject $Config -PropertyName 'Platform'
        if ($ProductIDs -or $Version -or $InstallPath) {
            return [PSCustomObject]@{ Found=$true; Version=$Version; Platform=$Platform; ProductIDs=$ProductIDs }
        }
    }
    return [PSCustomObject]@{ Found=$false; Version=$null; Platform=$null; ProductIDs=$null }
}

function Get-TargetPatchAssociations {
    $Results = New-Object System.Collections.Generic.List[object]
    if (-not (Test-Path -LiteralPath $PatchRegistryRoot)) { return @() }

    foreach ($Product in (Get-ChildItem -LiteralPath $PatchRegistryRoot -ErrorAction SilentlyContinue)) {
        $PatchesPath = Join-Path $Product.PSPath 'Patches'
        if (-not (Test-Path -LiteralPath $PatchesPath)) { continue }

        foreach ($Patch in (Get-ChildItem -LiteralPath $PatchesPath -ErrorAction SilentlyContinue)) {
            $Properties = Get-ItemProperty -LiteralPath $Patch.PSPath -ErrorAction SilentlyContinue
            if ($null -eq $Properties) { continue }

            $Names = @('DisplayName','PatchName','KBArticle','MoreInfoURL','HelpLink','Comments')
            $Matched = $false
            foreach ($Name in $Names) {
                $Value = Get-SafePropertyValue -InputObject $Properties -PropertyName $Name
                if (Test-TargetKBReference -Value $Value) { $Matched=$true; break }
            }
            if (-not $Matched) { continue }

            try {
                $Results.Add([PSCustomObject]@{
                    DisplayName = Get-SafePropertyValue -InputObject $Properties -PropertyName 'DisplayName'
                    ProductCode = ConvertFrom-PackedGuid -PackedGuid $Product.PSChildName
                    PatchCode   = ConvertFrom-PackedGuid -PackedGuid $Patch.PSChildName
                })
            } catch {
                Write-Output "Warning: Unable to convert Installer GUID at '$($Patch.PSPath)'."
            }
        }
    }
    return @($Results | Sort-Object ProductCode,PatchCode -Unique)
}

try {
    if (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) {
        Write-Output 'Detection error: Configure Intune to run this script in 64-bit PowerShell.'
        exit 0
    }

    $C2R = Get-ClickToRunOffice
    if ($C2R.Found) {
        Write-Output ("Compliant: $TargetKB is not applicable to Click-to-Run Office. Version='{0}'; Platform='{1}'; ProductReleaseIds='{2}'." -f $C2R.Version,$C2R.Platform,$C2R.ProductIDs)
        exit 0
    }

    $Associations = @(Get-TargetPatchAssociations)
    if ($Associations.Count -gt 0) {
        $Details = ($Associations | ForEach-Object { "$($_.ProductCode)/$($_.PatchCode)" }) -join '; '
        Write-Output "Non-compliant: $TargetKB is installed with $($Associations.Count) registered association(s): $Details"
        exit 1
    }

    Write-Output "Compliant: $TargetKB was not detected."
    exit 0
} catch {
    Write-Output "Detection error: $($_.Exception.Message)"
    exit 0
}