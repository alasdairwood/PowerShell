# Intel Extension 2.1.10103.24 - Remediation
# Hides the problematic update when Windows Update continues
# to offer it.

$TargetUpdate = "*Intel*Extension*2.1.10103.24*"

try {
    $UpdateSession  = New-Object -ComObject Microsoft.Update.Session
    $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()

    Write-Output "Scanning for Intel Extension 2.1.10103.24..."

    $Updates = @(
        $UpdateSearcher.Search("IsHidden=0").Updates
    )

    $Matched = @(
        $Updates | Where-Object {
            $_.Title -like $TargetUpdate
        }
    )

    if ($Matched.Count -eq 0) {
        Write-Output "Intel Extension 2.1.10103.24 is not currently being offered."
        exit 0
    }

    foreach ($Update in $Matched) {

        Write-Output "Found update: $($Update.Title)"

        try {
            $Update.IsHidden = $true
            Write-Output "Successfully hidden: $($Update.Title)"
        }
        catch {
            Write-Output "Failed to hide update: $($Update.Title)"
            Write-Output "Error: $($_.Exception.Message)"
            exit 1
        }
    }

    Write-Output "Remediation completed successfully."
    exit 0
}
catch {
    Write-Output "Remediation failed: $($_.Exception.Message)"
    exit 1
}