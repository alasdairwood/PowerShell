Import-Module ActiveDirectory

$GroupName = "GG - 60092 - Stonelaw Practice - User Accounts"

Get-ADGroupMember -Identity $GroupName |
    Where-Object {$_.objectClass -eq "user"} |
    Get-ADUser -Properties DisplayName,SamAccountName,UserPrincipalName,mail,Enabled,Department,Title |
    Select-Object DisplayName,SamAccountName,UserPrincipalName,mail,Enabled,Department,Title |
    Export-Csv "C:\WorkArea\$($GroupName)-Members.csv" -NoTypeInformation -Encoding UTF8