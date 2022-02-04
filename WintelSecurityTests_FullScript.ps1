#region
Main Menu allowing User Selection Script for testing Wintel processes to generate events that are then logged in Splunk.

Author: Alasdair Wood
Version: 1.00
Date-Created: 20th August 2021

Version Control:
     v1.01: Added Notepad execution with black listed account.  Alasdair Wood. 6th Sept 2021
     v1.02: Added Clearing Event Logs.  Alasdair Wood. 28th Oct 2021
     v1.03: Added System Time change and Server reboot.  Alasdair Wood. 9th Nov 2021
     v1.04: Added test using disabled account.  Alasdair Wood, 1st Febraru 2022
#endregion

function Show-Menu
{
     param (
           [string]$Title = "Perform Security Checks on"
     )
     Clear-Host
     Write-Output "================ $Title $env:computername ================"
     Write-Output "`n"   
     Write-Output "1: Run Automated Wintel Tests"
     Write-Output "`n"
     Write-Output "Q: Press 'Q' to quit."
     Write-Output "`n"
}

#Menu Option Functions
Function winteltests
{
     #Define Variables
     $lclapproveduser = "nwgappuser"
     $lclblklistuser = "nwgblkuser"
     $lclnewusername = "nwglclnewuser"

     #Ask for number of seconds to wait between steps
     $seconds = Read-Host "Please enter number of seconds to wait between steps"

     #Create Local Accounts required for testing process
     Write-Output "`n"
     Write-Output "Step 1: Creating Local User Accounts. Please Wait..."
     $null = New-LocalUser  -Name $lclapproveduser -AccountNeverExpires:$true -Password ( ConvertTo-SecureString -AsPlainText -Force 'S0m3_P4$$w0rd')
     $null = New-LocalUser  -Name $lclblklistuser -AccountNeverExpires:$true -Password ( ConvertTo-SecureString -AsPlainText -Force 'S0m3_P4$$w0rd')
     Start-Sleep -s $seconds

     #Modify the APPROVED user account by adding to the local Administrators security group
     Write-Output "`n"
     Write-Output "Step 2: Modify User Account.  Adding $lclapproveduser to local Administrators security group..."
     Add-LocalGroupMember -Group administrators -Member $lclapproveduser
     Start-Sleep -s $seconds

     #Modify the APPROVED user account by changing the user account name.
     Write-Output "`n"
     Write-Output "Step 3: Renaming from $lclapproveduser to $lclnewusername..."
     Rename-LocalUser -Name $lclapproveduser -NewName $lclnewusername
     Start-Sleep -s $seconds
     Write-Output "`n"
     Write-Output "Step 4: Renaming from $lclnewusername to $lclapproveduser..."
     Rename-LocalUser -Name $lclnewusername -NewName $lclapproveduser
     Start-Sleep -s $seconds

     #Modify the APPROVED user account by changing the password.
     Write-Output "`n"
     Write-Output "Step 5: Changing the password for $lclapproveduser..."
     Set-LocalUser -Name $lclapproveduser -Password (ConvertTo-SecureString -AsPlainText -Force 'N3w_P4$$w0rd')
     Start-Sleep -s $seconds

     #Disable the APPROVED user account.
     Write-Output "`n"
     Write-Output "Step 6: Disabling user account $lclapproveduser..."
     Disable-LocalUser -Name $lclapproveduser
     Start-Sleep -s $seconds

     #Enable the APPROVED user account
     Write-Output "`n"
     Write-Output "Step 7: Enabling user account $lclapproveduser..."
     Enable-LocalUser -Name $lclapproveduser
     Start-Sleep -s $seconds

     # Login with a blacklisted account and run the Notepad process.
     # Ensure account used is recorded as blacklisted in AIS_Wintel-Windows-Windows-Windows 20xx-Accounts-Blacklist.

     Write-Output "`n"
     Write-Output "Step 8: Logging in with a Blacklisted Account called NWGBLKUSER..."

     $service = 'seclogon'

     while ((Get-Service $service).Status -eq 'Stopped')
     {
        Set-Service -Name $service -Status running -StartupType automatic
     }

     $username = 'nwgblkuser'
     $password = 'S0m3_P4$$w0rd'
     Add-LocalGroupMember -Group administrators -Member $lclblklistuser
     $credentials = New-Object System.Management.Automation.PSCredential -ArgumentList @($username,(ConvertTo-SecureString -String $password -AsPlainText -Force))
     Start-Process -FilePath 'Notepad.exe' -Credential $credentials -WorkingDirectory 'C:\Windows\System32' -WindowStyle Hidden
     Start-Sleep -s 5
     #Set-Service -Name $service -Status stopped -StartupType Disabled
     Stop-Process -Name "notepad" -force
     Start-Sleep -s $seconds

     #Test Privileged Access
     Write-Output "`n"
     Write-Output "Step 9: Testing Approved Privileged Access using account NWGAPPUSER..."

     $username = 'nwgappuser'
     $password = 'N3w_P4$$w0rd'

     $credentials = New-Object System.Management.Automation.PSCredential -ArgumentList @($username,(ConvertTo-SecureString -String $password -AsPlainText -Force))
     Start-Process -FilePath 'Notepad.exe' -Credential $credentials -WorkingDirectory 'C:\Windows\System32' -WindowStyle Hidden
     Start-Sleep -s 5
     Stop-Process -Name "notepad" -force
     Start-Sleep -s $seconds

     #Check Eventlog for LogonTypes 2 and 10
     #Get-EventLog "Security" | WHERE -FilterScript {$_.EventID -eq 4624 -and $_.ReplacementStrings[8] -eq 2 -or $_.ReplacementStrings[8] -eq 10}
     Start-Sleep -s $seconds

     #Login Default Account
     Write-Output "`n"
     Write-Output "Step 10: Testing Login using Default Approved Account called NWGAPPUSER..."

     $username = 'nwgappuser'
     $password = 'N3w_P4$$w0rd'

     $credentials = New-Object System.Management.Automation.PSCredential -ArgumentList @($username,(ConvertTo-SecureString -String $password -AsPlainText -Force))
     Start-Process -FilePath 'Notepad.exe' -Credential $credentials -WorkingDirectory 'C:\Windows\System32' -WindowStyle Hidden
     Start-Sleep -s 5
     Stop-Process -Name "notepad" -force
     Start-Sleep -s $seconds

     #Attempt Login with Disabled Account...
     Write-Output "`n"
     Write-Output "Step 11: Testing Login using Disabled Account called $lclapproveduser..."
     Disable-LocalUser -Name $lclapproveduser

     $password = 'N3w_P4$$w0rd'
     $credentials = New-Object System.Management.Automation.PSCredential -ArgumentList @($lclapproveduser,(ConvertTo-SecureString -String $password -AsPlainText -Force))

     Start-Process -FilePath 'Notepad.exe' -Credential $credentials -WorkingDirectory 'C:\Windows\System32' -WindowStyle Hidden -ErrorAction SilentlyContinue
     Start-Sleep -s $seconds
     Enable-LocalUser -Name $lclapproveduser

     #Test Failed Logon Attempts
     Write-Output "`n"
     Write-Output "Step 12: Testing failed login attempts with account called NWGAPPUSER..."

     $maxattempts = 5
     $username = 'nwgappuser'
     $password = 'f4ls3p@ssw0rd'
     $computer = $env:COMPUTERNAME

     foreach($i in 1..$maxattempts)
     {
        # Write-Output $i
        if($i -ne $maxattempts)
        {
            Add-Type -AssemblyName System.DirectoryServices.AccountManagement
            $obj = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('machine',$computer)
            $null = $obj.ValidateCredentials($username, $password)
        }
     }
     Start-Sleep -s $seconds

     #Change the System Time
     Write-Output "`n"
     Write-Output "Step 13: Changing the System Time back 30 minutes..."
     $null = Set-Date -Adjust -0:30:00 -DisplayHint Time
     Start-Sleep -s $seconds

     #Remove local user accounts used for testing process
     Write-Output "`n"
     Write-Output "Step 14: Removing all local test accounts being used throughout this process..."
     Remove-LocalUser -Name $lclapproveduser
     Remove-LocalUser -Name $lclblklistuser
     Start-Sleep -s $seconds

     #Clear the Event Logs
     Write-Output "`n"
     Write-Output "Step 15: Clearing the Event Logs on the Local Host..."
     Get-EventLog -Logname * | ForEach-Object { Clear-EventLog $_.log }
     Start-Sleep -s 30

     #Notify All Steps Complete
     Write-Output "`n"
     Write-Host "Steps Complete" -BackgroundColor Red -ForegroundColor White
     Start-Sleep -s 10

     #Restart the Server
     Write-Output "`n"
     Write-Warning "The Server will now be restarted. You will be logged out."
     Start-Sleep -s 10
     Restart-Computer -Force -WhatIf
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
                winteltests
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