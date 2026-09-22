<#
.SYNOPSIS
    Detects whether Intel - Extension - 2.1.10103.24 is being offered
    by Windows Update and is not hidden.

.DESCRIPTION
    Intended for Microsoft Intune Remediations.
    Runs under SYSTEM using Windows PowerShell 5.1.

.EXITCODES
    0 = Compliant - update not applicable/offered or already hidden
    1 = Non-compliant - update is applicable and not hidden
#>

$ErrorActionPreference = 'Stop'

$TargetTitle = 'Intel - Extension - 2.1.10103.24'

try {
    $UpdateSession = New-Object -ComObject 'Microsoft.Update.Session'
    $UpdateSession.ClientApplicationID = 'Intune - Intel Extension Detection'

    $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
    $UpdateSearcher.Online = $true

    # Search applicable, uninstalled updates including hidden updates.
    $SearchResult = $UpdateSearcher.Search("IsInstalled=0")

    $TargetUpdates = @(
        $SearchResult.Updates |
            Where-Object { $_.Title -eq $TargetTitle }
    )

    if ($TargetUpdates.Count -eq 0) {
        Write-Output "Compliant: '$TargetTitle' is not currently applicable/offered."
        exit 0
    }

    $VisibleUpdates = @(
        $TargetUpdates |
            Where-Object { -not $_.IsHidden }
    )

    if ($VisibleUpdates.Count -gt 0) {
        Write-Output "Non-compliant: '$TargetTitle' is currently offered and is not hidden."
        exit 1
    }

    Write-Output "Compliant: '$TargetTitle' is already hidden."
    exit 0
}
catch {
    Write-Output "Detection error: $($_.Exception.Message)"
    exit 1
}