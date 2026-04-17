Import-Module ActiveDirectory

$CsvPath   = "C:\WorkArea\Win10-Excluded.csv"
$GroupName = "GG-Lanarkshire-Computers-Administrative-LocalDiskClean"
$ColumnName = "ComputerName"

$Computers = Import-Csv $CsvPath

foreach ($Item in $Computers) {

    $ComputerName = $Item.$ColumnName

    if (-not $ComputerName) {
        continue
    }

    # Ensure correct computer sAMAccountName format
    $SamAccountName = $ComputerName.TrimEnd('$') + '$'

    try {
        $Computer = Get-ADComputer -Filter "sAMAccountName -eq '$SamAccountName'"
        Remove-ADGroupMember -Identity $GroupName -Members $Computer -Confirm:$false
        Write-Host "Removed $ComputerName from $GroupName"
    }
    catch {
        Write-Warning "Failed to remove $ComputerName"
    }
}