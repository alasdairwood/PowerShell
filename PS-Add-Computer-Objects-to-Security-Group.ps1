Import-Module ActiveDirectory

$CsvPath   = "C:\WorkArea\Win10-LessThan-64GB-Free.csv"
$GroupName = "GG-Lanarkshire-Computers-Administrative-LocalDiskClean"

$group = Get-ADGroup -Identity $GroupName

Import-Csv $CsvPath | ForEach-Object {
    $name = $_.ComputerName.Trim()
    if (-not $name) { return }

    try {
        $comp = Get-ADComputer -Identity $name -ErrorAction Stop
        Add-ADGroupMember -Identity $group -Members $comp -ErrorAction Stop
        Write-Host "Added $name" -ForegroundColor Green
    } catch {
        Write-Warning "Failed for $name : $($_.Exception.Message)"
    }
}