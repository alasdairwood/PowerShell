<#
.SYNOPSIS
    Hides Intel - Extension - 2.1.10103.24 from Windows Update.

.DESCRIPTION
    Intended for Microsoft Intune Remediations.

    Searches Windows Update using the Windows Update Agent COM API
    and sets IsHidden = $true only when the update title exactly matches:

        Intel - Extension - 2.1.10103.24

    No other Windows Update items are modified.

.NOTES
    Recommended execution context:
        - SYSTEM
        - 64-bit PowerShell
        - Windows PowerShell 5.1

.EXITCODES
    0 = Successfully remediated, already hidden, or not applicable
    1 = Remediation failed
#>

$ErrorActionPreference = 'Stop'

$TargetTitle = 'Intel - Extension - 2.1.10103.24'

try {
    Write-Output "Starting remediation for '$TargetTitle'."

    # Create Windows Update Agent session
    $UpdateSession = New-Object -ComObject 'Microsoft.Update.Session'
    $UpdateSession.ClientApplicationID = 'Intune - Intel Extension Remediation'

    $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
    $UpdateSearcher.Online = $true

    Write-Output 'Searching Windows Update...'

    # Include hidden updates so that an already-remediated device can
    # be handled safely if this script is executed more than once.
    $SearchResult = $UpdateSearcher.Search("IsInstalled=0")

    $TargetUpdates = @(
        $SearchResult.Updates |
            Where-Object { $_.Title -eq $TargetTitle }
    )

    if ($TargetUpdates.Count -eq 0) {
        Write-Output "No action required: '$TargetTitle' is not currently applicable/offered."
        exit 0
    }

    $ChangesMade = 0

    foreach ($Update in $TargetUpdates) {

        $UpdateID = $Update.Identity.UpdateID
        $Revision = $Update.Identity.RevisionNumber

        Write-Output "Found target update:"
        Write-Output "  Title:      $($Update.Title)"
        Write-Output "  Update ID:  $UpdateID"
        Write-Output "  Revision:   $Revision"
        Write-Output "  IsHidden:   $($Update.IsHidden)"

        if ($Update.IsHidden) {
            Write-Output 'Update is already hidden. No action required.'
            continue
        }

        Write-Output 'Hiding update...'

        $Update.IsHidden = $true

        # Verify against the object immediately
        if (-not $Update.IsHidden) {
            throw "Windows Update Agent did not report '$TargetTitle' as hidden after setting IsHidden."
        }

        $ChangesMade++
        Write-Output "Successfully hidden: '$TargetTitle'."
    }

    if ($ChangesMade -eq 0) {
        Write-Output "Remediation complete: '$TargetTitle' was already hidden."
    }
    else {
        Write-Output "Remediation complete: $ChangesMade matching update(s) hidden."
    }

    exit 0
}
catch {
    Write-Output "Remediation failed: $($_.Exception.Message)"
    exit 1
}