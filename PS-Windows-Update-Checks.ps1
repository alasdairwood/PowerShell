Write-Host "`n=== WINDOWS UPDATE STATUS ===" -ForegroundColor Cyan

# ------------------------------------------------------------
# Windows Update service
# ------------------------------------------------------------
Write-Host "`nWindows Update Service:" -ForegroundColor Yellow

$WUService = Get-Service -Name wuauserv -ErrorAction SilentlyContinue

$WUService |
    Select-Object Name, Status, StartType |
    Format-Table -AutoSize


# ------------------------------------------------------------
# Pending / applicable updates
# ------------------------------------------------------------
Write-Host "`nPending / Applicable Updates:" -ForegroundColor Yellow

$Session = $null
$Searcher = $null

try {
    $Session  = New-Object -ComObject Microsoft.Update.Session
    $Searcher = $Session.CreateUpdateSearcher()

    Write-Host "Scanning Windows Update..." -ForegroundColor DarkGray

    # This performs a scan only.
    # It does NOT download or install updates.
    $SearchResult = $Searcher.Search("IsInstalled=0 and IsHidden=0")

    if ($SearchResult.Updates.Count -eq 0) {

        Write-Host "No applicable updates detected." -ForegroundColor Green

    }
    else {

        Write-Host "$($SearchResult.Updates.Count) applicable update(s) detected." -ForegroundColor Cyan

        $PendingUpdates = @()

        for ($i = 0; $i -lt $SearchResult.Updates.Count; $i++) {

            $Update = $SearchResult.Updates.Item($i)

            $PendingUpdates += [PSCustomObject]@{
                Title        = $Update.Title
                KB           = ($Update.KBArticleIDs -join ", ")
                Downloaded   = $Update.IsDownloaded
                RebootNeeded = $Update.RebootRequired
            }
        }

        $PendingUpdates |
            Format-Table Title, KB, Downloaded, RebootNeeded -AutoSize -Wrap
    }
}
catch {
    Write-Warning "Windows Update scan failed: $($_.Exception.Message)"
}


# ------------------------------------------------------------
# Recent Windows Update history
# ------------------------------------------------------------
Write-Host "`nRecent Windows Update History:" -ForegroundColor Yellow

try {

    # Create session if the previous scan failed
    if ($null -eq $Session) {
        $Session = New-Object -ComObject Microsoft.Update.Session
    }

    $HistorySearcher = $Session.CreateUpdateSearcher()
    $Count = $HistorySearcher.GetTotalHistoryCount()

    if ($Count -gt 0) {

        $HistoryCount = [Math]::Min($Count, 20)

        $History = $HistorySearcher.QueryHistory(0, $HistoryCount)

        $History |
            Select-Object Date,
                Title,
                @{Name='Result';Expression={
                    switch ($_.ResultCode) {
                        2 { 'Succeeded' }
                        3 { 'Succeeded with errors' }
                        4 { 'Failed' }
                        5 { 'Aborted' }
                        default { $_.ResultCode }
                    }
                }} |
            Sort-Object Date -Descending |
            Format-Table -AutoSize -Wrap
    }
    else {
        Write-Host "No Windows Update history found." -ForegroundColor Yellow
    }
}
catch {
    Write-Warning "Unable to retrieve Windows Update history: $($_.Exception.Message)"
}


# ------------------------------------------------------------
# Reboot status
# ------------------------------------------------------------
Write-Host "`nReboot Status:" -ForegroundColor Yellow

$CBSReboot = Test-Path `
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'

$WUReboot = Test-Path `
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'

$PendingFileRename = (
    Get-ItemProperty `
        'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
        -Name PendingFileRenameOperations `
        -ErrorAction SilentlyContinue
).PendingFileRenameOperations

$PendingFileRenameDetected = $null -ne $PendingFileRename

$RebootPending = (
    $CBSReboot -or
    $WUReboot -or
    $PendingFileRenameDetected
)

[PSCustomObject]@{
    RebootPending               = $RebootPending
    ComponentBasedServicing     = $CBSReboot
    WindowsUpdate               = $WUReboot
    FileRenameOperations = $PendingFileRenameDetected
} | Format-List


if ($RebootPending) {

    Write-Host "RESULT: REBOOT REQUIRED" -ForegroundColor Red

}
else {

    Write-Host "RESULT: No pending reboot detected" -ForegroundColor Green

}

Write-Host "`n=== CHECK COMPLETE ===" -ForegroundColor Cyan