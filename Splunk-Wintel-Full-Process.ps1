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
    $user = "alertsuser"
    $baduser = "baduser"
    $newuser = "newuser"
    $password = ConvertTo-SecureString -String "P@ssword1" -AsPlainText -Force
    $newpassword = ConvertTo-SecureString -String "N3wP@ssword1" -AsPlainText -Force
    $scriptpath = "C:\Scripts\Splunk-Wintel-Full-Process.ps1"
    $outputfile = "C:\Scripts\Output.txt"
    $count = 0

    #Ask for number of seconds to wait between steps
    $seconds = Read-Host "Please enter number of seconds to wait between steps"

    #Wintel_AIS_AMA01AccountCreation_2008_2012_2016
    #Checking for Event Code 4720
    Clear-Host
    try {
        Write-Host "Creating Local User Accounts. Please Wait......" -NoNewline
        New-LocalUser -Name $user -Password $password | Out-File -FilePath $outputfile
        New-LocalUser  -Name $baduser -Password $password | Out-File -FilePath $outputfile -Append
        Write-Host "Done !`n" -ForegroundColor Green
        $count = $count + 1
        Start-Sleep -s $seconds
    }
    catch {
        Write-Host "Failed: $($error[0])" -ForegroundColor Red
    }

    #Wintel_AIS_AMA05AccountPasswordUnauthorised_2008_2012_2016
    #Checking for Event Code 4723 or 4724
    Write-Host "Changing the password for $user......" -NoNewline
    Set-LocalUser -Name $user -Password $newpassword
    Write-Host "Done !`n" -ForegroundColor Green
    Start-Sleep -s $seconds

    #Wintel_AIS_AMA07OwnAccountModified_2008_2012_2016 (Needs reviewed)
    #Checking for Event Code 4704 or 4705 (need to add 4732, and drop 4704 and 4705)
    Write-Host "Modifying User Account.  Adding $user to local Administrators security group......" -NoNewline
    Add-LocalGroupMember -Group administrators -Member $user
    Write-Host "Done !`n" -ForegroundColor Green
    Start-Sleep -s $seconds
    Write-Host "Renaming user account from $user to $newuser......" -NoNewline
    Rename-LocalUser -Name $user -NewName $newuser
    Write-Host "Done !`n" -ForegroundColor Green
    Start-Sleep -s $seconds
    Write-Host "Renaming user account from $newuser to $user......" -NoNewline
    Rename-LocalUser -Name $newuser -NewName $user
    Write-Host "Done !`n" -ForegroundColor Green
    Start-Sleep -s $seconds

    #Wintel_AIS_AMA08AccountRightsModified_2008_2012_2016 (Needs reviewed)
    #Checking for Event Code 4704 or 4705 or 4732 (need to drop 4732 from this check)
    Write-Host "Testing Security Rights modification using account $user......" -NoNewline

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

    $sid = ((Get-LocalUser $user).SID).Value

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


    #Wintel_AIS_AMA10AccountEnabledOrUnlocked_2008_2012_2016
    #Checking for 4722 or 4767
    Disable-LocalUser -Name $user
    Write-Host "Enabling user account $user......" -NoNewline
    Enable-LocalUser -Name $user
    Write-Host "Done !`n" -ForegroundColor Green
    Start-Sleep -s $seconds

    # Wintel_AIS_ESS02BlacklistUserLogin_2008_2012_2016
    #Checking for Event Code 4624
    # Ensure account used is recorded as blacklisted in AIS_Wintel-Windows-Windows-Windows 20xx-Accounts-Blacklist.
    Write-Host "Logging in with a Blacklisted Account called $baduser......" -NoNewline

    $service = 'seclogon'
    while ((Get-Service $service).Status -eq 'Stopped') 
    {
       Set-Service -Name $service -Status running -StartupType automatic
    } 

    Add-LocalGroupMember -Group administrators -Member $baduser
    $credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $baduser, $password
    Start-Process -FilePath 'Notepad.exe' -Credential $credentials -WorkingDirectory 'C:\Windows\System32' -WindowStyle Hidden
    Write-Host "Done !`n" -ForegroundColor Green
    Start-Sleep -s $seconds

    #Wintel_AIS_MLA05T1ApplicationPrivilegedAccess_2008_2012_2016
    #Checking for Event Code 4624
    Write-Host "Testing Approved Privileged Access using account $user......" -NoNewline
    $credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $user, $newpassword
    Start-Process -FilePath 'Notepad.exe' -Credential $credentials -WorkingDirectory 'C:\Windows\System32' -WindowStyle Hidden
    Start-Sleep -s 5
    Stop-Process -Name "notepad" -force
    Write-Host "Done !`n" -ForegroundColor Green
    Start-Sleep -s $seconds

    #Wintel_AIS_MLA07T01LoginDefaultAccount_2008_2012_2016
    #Checking for Event Code 4624
    Write-Host "Testing Login using Default Approved Account called $user......" -NoNewline
    $credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $user, $newpassword
    Start-Process -FilePath 'Notepad.exe' -Credential $credentials -WorkingDirectory 'C:\Windows\System32' -WindowStyle Hidden
    Start-Sleep -s 5
    Stop-Process -Name "notepad" -force
    Write-Host "Done !`n" -ForegroundColor Green
    Start-Sleep -s $seconds

    #Wintel_AIS_MLA08T01LoginDisabledAccount_2008_2012_2016
    #Checking for Event Code 4625
    Write-Host "Testing Login using Disabled Account called $user......" -NoNewline
    Disable-LocalUser -Name $user
    $creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $user, $newpassword
    Start-Process -FilePath 'C:\Windows\System32\Notepad.exe' -Credential $creds -WindowStyle Hidden
    Write-Host "Done !`n" -ForegroundColor Green
    Start-Sleep -s $seconds
    Enable-LocalUser -Name $user

    #Wintel_AIS_MLA01MultipleFailedLogons_2008_2012_2016
    #Checking for Event Code 4625
    Write-Host "Testing failed login attempts with account called $user......" -NoNewline

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
           $null = $obj.ValidateCredentials($user, $falsepassword) 
       }
    }
    Write-Host "Done !`n" -ForegroundColor Green
    Start-Sleep -s $seconds

    #Wintel_AIS_MAL01TimeChanged_2008_2012_2016
    #Checking for Event Code 4616
    Write-Host "Changing the System Time back 15 minutes......" -NoNewline
    $null = Set-Date -Adjust -0:15:00 -DisplayHint Time
    Write-Host "Done !`n" -ForegroundColor Green
    Start-Sleep -s $seconds

    #Wintel_AIS_AMA03AccountDeletion_2008_2012_2016
    #Checking for Event Code 4726
    Write-Host "Removing all local test accounts being used throughout this process......" -NoNewline
    Remove-LocalUser -Name $user
    Remove-LocalUser -Name $baduser
    Write-Host "Done !`n" -ForegroundColor Green
    Start-Sleep -s $seconds

    #Wintel_AIS_ESS01EventLogCleared_2008_2012_2016
    #Checking for Event Code 1102
    Write-Host "Clearing the Event Logs on the Local Host......" -NoNewline
    Get-EventLog -Logname * | ForEach-Object { Clear-EventLog $_.log }
    Write-Host "Done !`n" -ForegroundColor Green
    Start-Sleep -s 5

    #Notify All Steps Complete
    Write-Host "Steps Complete" -BackgroundColor Red -ForegroundColor White
    Start-Sleep -s 5

    #Create a RunOnce item to rerun tis script upon server reboot and login
    #$scriptpath
    $runoncekey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    Set-ItemProperty $runoncekey "NextRun" ('C:\Windows\System32\WindowsPowerShell\v1.0\PowerShell.exe -executionPolicy Unrestricted ' + "`"$scriptpath`"")

    #Restart the Server
    Write-Warning "Server restarting. You will be logged out. This script will continue running after login."
    Start-Sleep -s 5
    Restart-Computer -Force -WhatIf
}

Function splunkreportstests
{
    #Define Variables
    $user="reportsuser"
    $password = ConvertTo-SecureString -String "P@ssword1" -AsPlainText -Force
    $newpassword = ConvertTo-SecureString -String "N3wP@ssword1" -AsPlainText -Force
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
    #Checking for Event Code 4723 or 4724
    Write-Host "Modifying password for $user......" -NoNewline
    Set-LocalUser -Name $user -Password $newpassword
    Start-Sleep -s 3
    Write-Host "Done !`n" -ForegroundColor Green
    Start-Sleep -s $seconds

    #Wintel AIS Sox 1d AMA11 Unlock or Enable Account 2008_2012_2016
    #Checking for Event Code 4722 or 4767
    Disable-LocalUser -Name $user
    Write-Host "Enabling user account $user......" -NoNewline
    Enable-LocalUser -Name $user
    Start-Sleep -s 3
    Write-Host "Done !`n" -ForegroundColor Green
    Start-Sleep -s $seconds

    #Wintel AIS Sox 1d AUS01 Device Shutdown or Reboot 2008_2012_2016
    #Checking for Event Code 4608 or 4609
    $runoncekey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    Set-ItemProperty $runoncekey "NextRun" ('C:\Windows\System32\WindowsPowerShell\v1.0\PowerShell.exe -executionPolicy Unrestricted ' + "`"$scriptpath`"")
    Write-Host "Server restarting. You will be logged out. This script will continue running after login." -ForegroundColor Red
    Start-Sleep -s 5
    Restart-Computer -Force -WhatIf

    #Wintel AIS Sox 1d MLA06 Login Privileged Account Authorised 2008_2012_2016
    #Checking for Event Code 4624
    Write-Host "Testing Approved Privileged Access using account $user......" -NoNewline
        $service = 'seclogon'
    while ((Get-Service $service).Status -eq 'Stopped') 
    {
       Set-Service -Name $service -Status running -StartupType automatic
    } 
    Add-LocalGroupMember -Group administrators -Member $user
    $credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $user, $newpassword
    Start-Process -FilePath 'Notepad.exe' -Credential $credentials -WorkingDirectory 'C:\Windows\System32' -WindowStyle Hidden
    Start-Sleep -s 3
    Stop-Process -Name "notepad" -force
    Start-Sleep -s 3
    Write-Host "Done !`n" -ForegroundColor Green
    Start-Sleep -s $seconds

    #Wintel AIS Sox 1d AMA09 Account Modified Rights 2008_2012_2016
    #Checking for 4704 or 4705 or 4732 (need to drop 4704 and 4705)
    Write-Host "Modifying User Account.  Adding $user to local Administrators security group......" -NoNewline
    Add-LocalGroupMember -Group administrators -Member $user
    Write-Host "Done !`n" -ForegroundColor Green
    Start-Sleep -s $seconds

    #Wintel AIS Sox 1d AMA04 Account Deletion 2008_2012_2016
    #Checking for Event Code 4726
    Write-Host "Removing all local accounts used......" -NoNewline
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
