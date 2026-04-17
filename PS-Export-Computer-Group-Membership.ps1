Import-Module ActiveDirectory

$GroupName = "Deny Computer Lockout"

Get-ADGroupMember -Identity $GroupName -Recursive |
    Where-Object {$_.objectClass -eq "computer"} |
    Get-ADComputer -Properties Name,DNSHostName,OperatingSystem,OperatingSystemVersion,Enabled |
    Select-Object Name,DNSHostName,OperatingSystem,OperatingSystemVersion,Enabled |
    Export-Csv "C:\WorkArea\$($GroupName)-ComputerMembers.csv" -NoTypeInformation -Encoding UTF8