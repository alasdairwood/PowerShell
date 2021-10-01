# Main Menu allowing User Selection

# Interactive menu driven system to perform selected Wintel activities.
# Author: Alasdair Wood
# Version: 1.0
# Date Created: 6th September 2021
# Version Control:
#    (Example) v1.01: Added New Activity. Alasdair Wood. 6th Sept 2021
#
#

function Show-Menu
{
     param (
           [string]$Title = 'Interactive Menu'
     )
     Clear-Host
     Write-Host "================ $Title ================"
     Write-Host "`n"    
     Write-Host "1: Automated - Create, Rename, Change Password and Remove User Account"
     Write-Host "2: Automated - Create, Disable, Enable and Remove User Account"
     Write-Host "3: Change a Local User Password"
     Write-Host "4: Delete a Local User Account"
     Write-Host "`n"
     Write-Host "Q: Press 'Q' to quit."
     Write-Host "`n"
}

#Menu Option Functions
Function autouseraccount1
{
     # Create a new local user account.  Prompt for username and perform error check.  Create account if not found otherwise exit to menu.

     #$username = Read-Host "Please enter a username"

     $lclusername="nwglcluser"
     $lclusr = Get-LocalUSer | where-Object Name -eq $lclusername | Measure-Object
      if ($lclusr.Count -eq 0)
      {
           Write-Host "Step 1: Local User Account called $lclusername not found.  Creating account and adding to Administrators Group..."
           New-LocalUser -AccountNeverExpires:$true -Password ( ConvertTo-SecureString -AsPlainText -Force 'S0m3_P4$$w0rd') -Name $lclusername | Add-LocalGroupMember -Group administrators
           Start-Sleep -s 5
           
           $lclnewusername="nwglclnewuser"
           Write-Host "Step 2: Renaming from $lclusername to $lclnewusername..."
           Rename-LocalUser -Name $lclusername -NewName $lclnewusername 
           Start-Sleep -s 5

           Write-Host "Step 3: Changing the password for $lclnewusername..."
           #$userpassword = Read-Host "Please enter new password" -AsSecureString
           #Set-LocalUser -Name $lclnewusername -Password $userpassword -Verbose
           Set-LocalUser -Name $lclnewusername -Password (ConvertTo-SecureString -AsPlainText -Force 'N3w_P4$$w0rd') -Verbose
           Start-Sleep -s 5

           Write-Host "Step 4: Removing the account $lclnewusername..."
           Remove-LocalUser -Name $lclnewusername -Verbose
           Start-Sleep -s 5

           Write-Host "Steps Complete" -BackgroundColor Red -ForegroundColor White
      }
      else
      {
           Write-Host "Local User Account called $lclusername already exists!"
      }
}
Function autouseraccount2
{
     $lclusername="nwglcluser"
     $lclusr = Get-LocalUSer | where-Object Name -eq $lclusername | Measure-Object
      if ($lclusr.Count -eq 0)
      {
           Write-Host "Step 1: Local User Account called $lclusername not found.  Creating account and adding to Administrators Group..."
           New-LocalUser -AccountNeverExpires:$true -Password ( ConvertTo-SecureString -AsPlainText -Force 'somepassword') -Name $lclusername | Add-LocalGroupMember -Group administrators
           Start-Sleep -s 5
           
           Write-Host "Step 2: Disabling user account $lclusername..."
           Disable-LocalUser -Name $lclusername
           Start-Sleep -s 5

           Write-Host "Step 3: Enabling user account $lclusername..."
           Enable-LocalUser -Name $lclusername
           Start-Sleep -s 5

           Write-Host "Step 4: Removing the account $lclusername..."
           Remove-LocalUser -Name $lclusername -Verbose
           Start-Sleep -s 5

           Write-Host "Steps Complete" -BackgroundColor Red -ForegroundColor White
      }
      else
      {
           Write-Host "Local User Account called $lclusername already exists!"
      }
}
Function changepassword
{
     # Change local user account password.  Prompt for username and perform error check.
     # If existing account found, prompt for new password.

     $username = Read-Host "Please enter username"
     $usr = Get-LocalUSer | where-Object Name -eq $username | Measure-Object
      if ($usr.Count -eq 1)
      {
           Write-Host "Local account name $username found."
           $userpassword = Read-Host "Please enter new password" -AsSecureString
           Write-Host "Changing password for $username now..."
           Set-LocalUser -Name $username -Password $userpassword -Verbose
      }
      else
      {
           Write-Host "User Name called $username not found!"
      }
}

Function deletelocaluseraccount
{
     # Delete local user account.  Prompt for username and perform error check.
     # If existing account found, perform action to delete the account.

     $username = Read-Host "Please enter username"
     $delusr = Get-LocalUSer | where-Object Name -eq $username | Measure-Object
      if ($delusr.Count -eq 1)
      {
           Write-Host "Local account name $username found."
           Remove-LocalUser -Name $username -Verbose
           Write-Host "Removing local user account $username now..."
      }
      else
      {
           Write-Host "User Account called $username not found!"
      }
}

#Get User Details and Security Group Membership Check.
#PowerShell AD Module must be installed.

Import-Module Activedirectory

$username = $env:USERNAME
$group = 'group1'
$user = Get-ADGroupMember -Identity $group | Where-Object {$_.name -eq $username}
if($user)
{
    Write-Host "SUCCESS: $username is a member of $group"
}
else
{
    Write-Host "ALERT: $username is NOT a member of $group"
}

#Main Menu Loop
do
{
     Show-Menu
     $menuselection = Read-Host "Please make a selection"
     switch ($menuselection)
     {
           '1'
           {
                Clear-Host
                autouseraccount1
           }
           '2'
           {
                Clear-Host
                autouseraccount2
           }
           '3'
           {
                Clear-Host
                changepassword
           }
           '4'
           {
                Clear-Host
                deletelocaluseraccount
           }
           'q'
           {
                Write-Host "Closing Session..." -BackgroundColor Red -ForegroundColor White
                return
           }
     }
     pause
}
until ($menuselection -eq 'q')