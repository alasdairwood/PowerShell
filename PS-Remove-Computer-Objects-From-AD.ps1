Import-Module ActiveDirectory

$CsvFile = "C:\WorkArea\CSV\DisableComputers.csv"
$LogFile = "C:\WorkArea\CSV\DeletedComputers.log"

Import-Csv $CsvFile | ForEach-Object {

    $ComputerName = $_.ComputerName

    try {
        $ADComputer = Get-ADComputer `
            -Identity $ComputerName `
            -Properties Enabled,ProtectedFromAccidentalDeletion `
            -ErrorAction Stop

        if ($ADComputer.Enabled -eq $false) {

            # Remove accidental deletion protection if enabled
            if ($ADComputer.ProtectedFromAccidentalDeletion) {
                Set-ADObject `
                    -Identity $ADComputer.DistinguishedName `
                    -ProtectedFromAccidentalDeletion $false

                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - REMOVED PROTECTION - $ComputerName" |
                    Out-File $LogFile -Append
            }

            # Count child objects
            $ChildObjects = Get-ADObject `
                -SearchBase $ADComputer.DistinguishedName `
                -SearchScope OneLevel `
                -Filter * `
                -ErrorAction SilentlyContinue

            $ChildCount = @($ChildObjects).Count

            Write-Host "Would delete: $($ADComputer.DistinguishedName)"
            <#Remove-ADObject `
                -Identity $ADComputer.DistinguishedName `
                -Recursive `
                -Confirm:$false `
                -ErrorAction Stop#>

            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - DELETED - $ComputerName - ChildObjects:$ChildCount" |
                Out-File $LogFile -Append
        }
        else {

            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - SKIPPED (Enabled) - $ComputerName" |
                Out-File $LogFile -Append
        }
    }
    catch {

        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - FAILED - $ComputerName - $($_.Exception.Message)" |
            Out-File $LogFile -Append
    }
}