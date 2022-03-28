#requires -version 2

<#
.SYNOPSIS
    Performs automated alert and report based Wintel security tasks.

.DESCRIPTION
    A number of automated tasks are performed to check security on WINTEL servers. These tasks log events which ultimately report to SPLUNK.
    Select option 1 and / or 2 from the menu and enter the desired number of seconds to wait between the steps.

.INPUTS
    None. You cannot pipe objects to Splunk-Wintel-Full-Process.ps1

.OUTPUTS
    The Windows Event logs will update with events relating to the tasks being run.

.EXAMPLE
    PS> .\Splunk-Wintel-Full-Process.ps1

.NOTES
    Version:                    1.0
    Author:                     Alasdair Wood
    Creation Date:              25th August 2021
    Purpose / Change:           Initial script development

#>

Function ShowMenu
{
    param (
          [string]$Title = "Perform Wintel Tests on"
    )
    Clear-Host
    Write-Output "================ $Title $env:computername ================`n"    
    Write-Output "1: Run Alert Based Wintel Tests`n"
    Write-Output "2: Run Report Based Wintel Tests`n"
    Write-Output "Q: Press 'Q' to quit`n"
}

#Menu Option Functions
Function splunkalertstests
{
    #Define Variables
    $approveduser = "approveduser"
    $blklistuser = "blklistuser"
    $newusername = "newuser"
    $password = ConvertTo-SecureString -String "P@ssword1" -AsPlainText -Force
    $newpassword = ConvertTo-SecureString -String "N3wP@ssword1" -AsPlainText -Force
    $scriptpath="C:\Scripts\Splunk-Wintel-Full-Process.ps1"

    #Ask for number of seconds to wait between steps
    $seconds = Read-Host "Please enter number of seconds to wait between steps"

    #Wintel_AIS_AMA01AccountCreation_2008_2012_2016
    Clear-Host
    Write-Host "Step 1: Creating Local User Accounts. Please Wait......" -NoNewline
    $null = New-LocalUser  -Name $approveduser -Password $password
    $null = New-LocalUser  -Name $blklistuser -Password $password
    Write-Host "Done !`n" -ForegroundColor Green
    Start-Sleep -s $seconds

    #Wintel_AIS_AMA07OwnAccountModified_2008_2012_2016
    Write-Host "Step 2: Modifying User Account.  Adding $approveduser to local Administrators security group......" -NoNewline
    Add-LocalGroupMember -Group administrators -Member $approveduser
    Write-Host "Done !`n" -ForegroundColor Green
    Start-Sleep -s $seconds
    Write-Host "Step 3: Renaming user account from $approveduser to $newusername......" -NoNewline
    Rename-LocalUser -Name $approveduser -NewName $newusername
    Write-Host "Done !`n" -ForegroundColor Green
    Start-Sleep -s $seconds
    Write-Host "Step 4: Renaming user account from $newusername to $approveduser......" -NoNewline
    Rename-LocalUser -Name $newusername -NewName $approveduser
    Write-Host "Done !`n" -ForegroundColor Green
    Start-Sleep -s $seconds

    #Wintel_AIS_AMA05AccountPasswordUnauthorised_2008_2012_2016
    Write-Host "Step 5: Changing the password for $approveduser......" -NoNewline
    Set-LocalUser -Name $approveduser -Password $newpassword
    Write-Host "Done !`n" -ForegroundColor Green
    Start-Sleep -s $seconds

    #Wintel_AIS_AMA10AccountEnabledOrUnlocked_2008_2012_2016
    Disable-LocalUser -Name $approveduser
    Start-sleep -s 3
    Write-Host "Step 6: Enabling user account $approveduser......" -NoNewline
    Enable-LocalUser -Name $approveduser
    Write-Host "Done !`n" -ForegroundColor Green
    Start-Sleep -s $seconds

    # Wintel_AIS_ESS02BlacklistUserLogin_2008_2012_2016
    # Ensure account used is recorded as blacklisted in AIS_Wintel-Windows-Windows-Windows 20xx-Accounts-Blacklist.
    Write-Host "Step 7: Logging in with a Blacklisted Account called $blklistuser......" -NoNewline

    $service = 'seclogon'
    while ((Get-Service $service).Status -eq 'Stopped') 
    {
       Set-Service -Name $service -Status running -StartupType automatic
    } 

    Add-LocalGroupMember -Group administrators -Member $blklistuser
    $credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $blklistuser, $password
    Start-Process -FilePath 'Notepad.exe' -Credential $credentials -WorkingDirectory 'C:\Windows\System32' -WindowStyle Hidden
    Write-Host "Done !`n" -ForegroundColor Green
    Start-Sleep -s $seconds

    #Wintel_AIS_AMA08AccountRightsModified_2008_2012_2016
    Write-Host "Step 8: Testing Security Rights modification using account $approveduser......" -NoNewline

    $userRight = "SeServiceLogonRight*"

    $code = (Start-Process secedit -ArgumentList "/export /areas USER_RIGHTS /cfg c:\policies.inf" -Wait -PassThru).ExitCode
    if ($code -eq 0)
        {
            $null = Write-Output "Security template exported successfully exit code $code"
        }
    else
        {
            $null = Write-Output "Security template export failed exit code $code"
        }

    $sid = ((Get-LocalUser $approveduser).SID).Value

    $policy = Get-Content C:\policies.inf
    $newpol = @()
    foreach ($line in $policy)
        {
            if ($line -like $userRight)
                {
                    $line = $line + ",*$sid"
                }

            $newpol += $line
        }

    $newpol | Out-File C:\policies.inf -Force

    $code = (Start-Process secedit -ArgumentList "/configure /db secedit.sdb /cfg C:\policies.inf /areas USER_RIGHTS /log C:\policies.log" -Wait -PassThru).ExitCode
    if ($code -eq 0)
        {
            $null = Write-Output "security template imported successfully - exit code $code"
        }
    else
        {
            $null = Write-Output "security template import failed - exit code $code"
        }

    Remove-Item -Path c:\policies.inf -Force
    Remove-Item -Path c:\policies.log -Force
    Write-Host "Done !`n" -ForegroundColor Green
    Start-Sleep -s $seconds

    #Wintel_AIS_MLA05T1ApplicationPrivilegedAccess_2008_2012_2016
    Write-Host "Step 9: Testing Approved Privileged Access using account $approveduser......" -NoNewline
    
    #$username = 'nwgappuser'
    #$password = 'N3w_P4$$w0rd'

    $credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $approveduser, $password
    Start-Process -FilePath 'Notepad.exe' -Credential $credentials -WorkingDirectory 'C:\Windows\System32' -WindowStyle Hidden
    Start-Sleep -s 5
    Stop-Process -Name "notepad" -force
    Write-Host "Done !`n" -ForegroundColor Green
    Start-Sleep -s $seconds

    #Wintel_AIS_MLA07T01LoginDefaultAccount_2008_2012_2016
    Write-Host "Step 10: Testing Login using Default Approved Account called $approveduser......" -NoNewline
    
    #$username = 'nwgappuser'
    #$password = 'N3w_P4$$w0rd'

    $credentials = New-Object System.Management.Automation.PSCredential -ArgumentList @($approveduser,(ConvertTo-SecureString -String $password -AsPlainText -Force))
    Start-Process -FilePath 'Notepad.exe' -Credential $credentials -WorkingDirectory 'C:\Windows\System32' -WindowStyle Hidden
    Start-Sleep -s 5
    Stop-Process -Name "notepad" -force
    Write-Host "Done !`n" -ForegroundColor Green
    Start-Sleep -s $seconds

    #Wintel_AIS_MLA08T01LoginDisabledAccount_2008_2012_2016 
    Write-Host "Step 11: Testing Login using Disabled Account called $approveduser......" -NoNewline
    Disable-LocalUser -Name $approveduser
    
    #$password = 'N3w_P4$$w0rd'

    $credentials = New-Object System.Management.Automation.PSCredential -ArgumentList @($approveduser,(ConvertTo-SecureString -String $password -AsPlainText -Force))
    Start-Process -FilePath 'Notepad.exe' -Credential $credentials -WorkingDirectory 'C:\Windows\System32' -WindowStyle Hidden -ErrorAction SilentlyContinue
    Write-Host "Done !`n" -ForegroundColor Green
    Start-Sleep -s $seconds
    Enable-LocalUser -Name $approveduser

    #Wintel_AIS_MLA01MultipleFailedLogons_2008_2012_2016
    Write-Host "Step 12: Testing failed login attempts with account called $approveduser......" -NoNewline

    $maxattempts = 5
    $falsepassword = 'f4ls3p@ssw0rd'

    $computer = $env:COMPUTERNAME

    foreach($i in 1..$maxattempts)
    {
       # Write-Output $i
       if($i -ne $maxattempts)
       {
           Add-Type -AssemblyName System.DirectoryServices.AccountManagement
           $obj = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('machine',$computer)
           $null = $obj.ValidateCredentials($approveduser, $falsepassword) 
       }
    }
    Write-Host "Done !`n" -ForegroundColor Green
    Start-Sleep -s $seconds

    #Wintel_AIS_MAL01TimeChanged_2008_2012_2016
    Write-Host "Step 13: Changing the System Time back 15 minutes......" -NoNewline
    $null = Set-Date -Adjust -0:15:00 -DisplayHint Time
    Write-Host "Done !`n" -ForegroundColor Green
    Start-Sleep -s $seconds

    #Wintel_AIS_AMA03AccountDeletion_2008_2012_2016
    Write-Host "Step 14: Removing all local test accounts being used throughout this process......" -NoNewline
    Remove-LocalUser -Name $approveduser
    Remove-LocalUser -Name $blklistuser
    Write-Host "Done !`n" -ForegroundColor Green
    Start-Sleep -s $seconds

    #Wintel_AIS_ESS01EventLogCleared_2008_2012_2016
    Write-Host "Step 15: Clearing the Event Logs on the Local Host......" -NoNewline
    Get-EventLog -Logname * | ForEach-Object { Clear-EventLog $_.log } -WhatIf
    Write-Host "Done !`n" -ForegroundColor Green
    Start-Sleep -s 10

    #Notify All Steps Complete
    Write-Host "Steps Complete" -BackgroundColor Red -ForegroundColor White
    Start-Sleep -s 10

    #Create a RunOnce item to rerun tis script upon server reboot and login
    #$scriptpath
    $runoncekey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    Set-ItemProperty $runoncekey "NextRun" ('C:\Windows\System32\WindowsPowerShell\v1.0\PowerShell.exe -executionPolicy Unrestricted ' + "`"$scriptpath`"")

    #Restart the Server
    Write-Warning "Server restarting. You will be logged out. This script will continue running after login."
    Start-Sleep -s 10
    Restart-Computer -Force -WhatIf
}

Function splunkreportstests
{
    #Define Variables
    $user="reportsuser"
    $password="P@ssword1"
    $newpassword="N3wP@ssword1"
    $scriptpath="C:\Scripts\Splunk-Wintel-Full-Process.ps1"

    #Ask for number of seconds to wait between steps
    $seconds = Read-Host "Please enter number of seconds to wait between steps"

    #Create Local Accounts required for testing process.
    Clear-Host
    Write-Host "Pre-Requisite Step: Creating Local User Accounts. Please Wait......" -NoNewline
    $null = New-LocalUser -Name $user -Password (ConvertTo-SecureString $password -AsPlainText -Force)
    Start-Sleep -s 3
    Write-Host "Done !`n" -ForegroundColor Green
    Start-Sleep -s $seconds

    #Wintel AIS Sox 1d AMA06 Account Modified Password 2008_2012_2016
    Write-Host "Step 1: Modifying password for $user......" -NoNewline
    Set-LocalUser -Name $user -Password (ConvertTo-SecureString $newpassword -AsPlainText -Force)
    Start-Sleep -s 3
    Write-Host "Done !`n" -ForegroundColor Green
    Start-Sleep -s $seconds

    #Wintel AIS Sox 1d AMA11 Unlock or Enable Account 2008_2012_2016
    Disable-LocalUser -Name $user
    Start-Sleep -s 5
    Write-Host "Step 2: Enabling user account $user......" -NoNewline
    Enable-LocalUser -Name $user
    Start-Sleep -s 3
    Write-Host "Done !`n" -ForegroundColor Green
    Start-Sleep -s $seconds

    #Wintel AIS Sox 1d AUS01 Device Shutdown or Reboot 2008_2012_2016
    $runoncekey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    Set-ItemProperty $runoncekey "NextRun" ('C:\Windows\System32\WindowsPowerShell\v1.0\PowerShell.exe -executionPolicy Unrestricted ' + "`"$scriptpath`"")
    Write-Host "Step 3: Server restarting. You will be logged out. This script will continue running after login." -ForegroundColor Red
    Start-Sleep -s 5
    Restart-Computer -Force

    #Wintel AIS Sox 1d MLA06 Login Privileged Account Authorised 2008_2012_2016
    Write-Host "Step 4: Testing Approved Privileged Access using account $user......" -NoNewline
    $credentials = New-Object System.Management.Automation.PSCredential -ArgumentList @($user,(ConvertTo-SecureString -String $password -AsPlainText -Force))
    Start-Process -FilePath 'Notepad.exe' -Credential $credentials -WorkingDirectory 'C:\Windows\System32' -WindowStyle Hidden
    Start-Sleep -s 3
    Stop-Process -Name "notepad" -force
    Start-Sleep -s 3
    Write-Host "Done !`n" -ForegroundColor Green
    Start-Sleep -s $seconds

    #Wintel AIS Sox 1d AMA09 Account Modified Rights 2008_2012_2016

    #Wintel AIS Sox 1d AMA04 Account Deletion 2008_2012_2016
    Write-Host "Step 6: Removing all local accounts used......" -NoNewline
    Remove-LocalUser -Name $user
    Start-Sleep -s 3
    Write-Host "Done !`n" -ForegroundColor Green
    Start-Sleep -s $seconds
}

#Main Menu Loop
do
{
    ShowMenu
    $menuselection = Read-Host "Please make a selection"
    switch ($menuselection)
    {
          '1'
          {
               Clear-Host
               splunkalertstests
          }
          '2'
          {
               Clear-Host
               splunkreportstests
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