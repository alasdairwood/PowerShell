# Check_Move_Remove_Partition
# Alasdair Wood
# 22/01/21
# Version: 2.0

#requires -version 2

<#
.SYNOPSIS
    Checks for Resevered System partition and hides it.

.DESCRIPTION
    The script will check for a visible system reserved partition, backup any data stored on it, then hide it from view.

.INPUTS
    None. You cannot pipe objects to this script.

.OUTPUTS
    None.

.EXAMPLE
    PS> .\Check_Move_Remove_Partition.ps1

.NOTES
    Version:                    1.0
    Author:                     Alasdair Wood
    Creation Date:              28th March 2022
    Purpose / Change:           Initial script development

#>

$systemReservedPartition = Get-Volume -FileSystemLabel "System Reserved"
$backupFolder = "C:\Temp\SystemReservedBackup\"

if ($systemReservedPartition.DriveLetter)
{
    $systemReservedDrive = $($systemReservedPartition.DriveLetter) + ":\"
    $userContent         = Get-ChildItem -Path $systemReservedDrive -Recurse

    if ($userContent)
    {
        if(!(Test-Path -Path $backupFolder)) { New-Item -Path $backupFolder -ItemType Container }
        
        foreach ($userItem in $userContent)
        {
         Move-Item -Path $userItem.FullName -Destination $backupFolder 
        } 
    }

    $systemReservedPartition | Get-Partition | Remove-PartitionAccessPath -AccessPath $systemReservedDrive
}

else
{
    Write-Host "System Reserved Drive does not Exist"
}
