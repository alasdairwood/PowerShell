$ComputerName = "D10152"

Invoke-Command -ComputerName $ComputerName -ScriptBlock {
    $Session  = New-Object -ComObject Microsoft.Update.Session
    $Searcher = $Session.CreateUpdateSearcher()

    $Results = $Searcher.Search("IsInstalled=0 and IsHidden=0")

    $Results.Updates | ForEach-Object {
        [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            Title        = $_.Title
            KB           = ($_.KBArticleIDs -join ",")
            IsDownloaded = $_.IsDownloaded
            RebootRequired = $_.RebootRequired
            MsrcSeverity = $_.MsrcSeverity
            Categories   = ($_.Categories | ForEach-Object Name) -join ", "
        }
    }
}