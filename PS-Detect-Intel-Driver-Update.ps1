# Intel Extension 2.1.10103.24 - Detection
# Exit 0 = Compliant / update is not being offered
# Exit 1 = Non-compliant / update is being offered and needs hidden

$TargetUpdate = "*Intel*Extension*2.1.10103.24*"

try {
    $UpdateSession  = New-Object -ComObject Microsoft.Update.Session
    $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()

    # Search updates which are not currently hidden
    $Updates = @(
        $UpdateSearcher.Search("IsHidden=0").Updates
    )

    $Matched = @(
        $Updates | Where-Object {
            $_.Title -like $TargetUpdate
        }
    )

    if ($Matched.Count -gt 0) {
        foreach ($Update in $Matched) {
            Write-Output "Update requires remediation: $($Update.Title)"
        }

        exit 1
    }

    Write-Output "Intel Extension 2.1.10103.24 is not currently being offered."
    exit 0
}
catch {
    Write-Output "Detection failed: $($_.Exception.Message)"

    # Treat a failed Windows Update scan as non-compliant
    exit 1
}