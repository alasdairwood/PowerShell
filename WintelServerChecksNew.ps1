# Define the menu items
$menuitems = @("Option 1", "Option 2", "Quit")

# Display the menu
while ($true) {
    Write-Output "Menu:"
    for ($i = 0; $i -lt $menuitems.Length; $i++) {
        Write-Output "$($i+1). $($menuitems[$i])"
    }

    # Prompt the user to select an option
    $menuselection = Read-Host "Select an option (1-$($menuitems.Length)) or press 'Q' to quit"

    # Check if the user selected an option or quit
    if ($menuselection -eq "1") {
        Write-Output "Running task for option 1..."
        # Replace this with the task to run for option 1
        # Define the usernames of the new user accounts to create
        $usernames = @("user1", "user2", "user3")

        # Create the new user accounts
        foreach ($username in $usernames) {
            $password = ConvertTo-SecureString "Password123!" -AsPlainText -Force
            New-LocalUser -Name $username -Password $password -FullName $username -Description "New local user account"
            Write-Output "Created user account '$username'"
        }

        # Define the username and new password
        $username = "user1"
        $newPassword = "NewPassword123!"

        # Change the password for the user account
        $password = ConvertTo-SecureString $newPassword -AsPlainText -Force
        Set-LocalUser -Name $username -Password $password
        Write-Output "Changed password for user account '$username' to '$newPassword'"

        # Define the username of the user account to add to the admin group
        $username = "user1"

        # Add the user account to the local admin security group
        Add-LocalGroupMember -Group "Administrators" -Member $username
        Write-Output "Added user account '$username' to the local admin security group"

        # Define the current and new usernames
        $currentUsername = "user1"
        $newUsername = "newuser1"

        # Rename the user account
        Rename-LocalUser -Name $currentUsername -NewName $newUsername
        Write-Output "Renamed user account '$currentUsername' to '$newUsername'"

        # Define the username of the user account to modify
        $username = "user1"

        # Define the rights assignment for the user account
        $rights = "SeBatchLogonRight", "SeServiceLogonRight"

        # Modify the rights assignment for the user account
        $account = Get-LocalUser -Name $username
        $account.UserRightAssignments = $rights
        Set-LocalUser -InputObject $account
        Write-Output "Modified rights assignment for user account '$username'"

        # Define the username of the user account to disable and enable
        $username = "testuser"

        # Disable the user account
        Disable-LocalUser -Name $username

        # Check if the account is disabled
        $account = Get-LocalUser -Name $username
        if ($account.Enabled -eq $false) {
            Write-Output "User account '$username' has been disabled"
        }
        else {
            Write-Output "Failed to disable user account '$username'"
        }

        # Enable the user account
        Enable-LocalUser -Name $username

        # Check if the account is enabled
        $account = Get-LocalUser -Name $username
        if ($account.Enabled -eq $true) {
            Write-Output "User account '$username' has been enabled"
        }
        else {
            Write-Output "Failed to enable user account '$username'"
        }

        # Define the logon credentials
        $username = "testuser"
        $password = ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($username, $password)

        # Define the logon type and logon process
        $logonType = 2 # Interactive logon
        $logonProcess = "User32" # Windows logon process

        # Simulate the logon event and generate Event ID 4624
        $eventID = 4624
        $eventName = "Logon"
        $eventMessage = "An account was successfully logged on."
        New-EventLog -LogName Security -Source PowerShell
        $eventData = @{
            "TargetUserName" = $username
            "LogonType" = $logonType
            "LogonProcessName" = $logonProcess
        }
        Write-EventLog -LogName Security -Source PowerShell -EventId $eventID -EntryType Information -Message $eventMessage -Category  Logon/Logoff -ReplacementStrings $username,$logonProcess,$logonType,$eventName -Data $eventData
        Write-Output "Generated event ID $eventID for user '$username'"

        # Define the username and password of the user account to log in with
        $username = "testuser"
        $password = "P@ssw0rd"

        # Check if the account is enabled
        $account = Get-LocalUser -Name $username
        if ($account.Enabled -eq $false) {
            Write-Output "User account '$username' is disabled. Cannot log in."
        }
        else {
            # Attempt to log in with the specified credentials
            $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
            $credential = New-Object System.Management.Automation.PSCredential($username, $securePassword)
            try {
                $result = Enter-PSSession -ComputerName localhost -Credential $credential
                Write-Output "User '$username' logged in successfully"
                Exit-PSSession
            }
            catch {
                Write-Output "Failed to log in with user '$username'"
            }
        }

        # Define the username and password of the user account to log in with
        $username = "testuser"
        $password = "P@ssw0rd"

        # Define the number of login attempts to make
        $attempts = 5

        # Loop through the login attempts
        for ($i=1; $i -le $attempts; $i++) {
            # Attempt to log in with the specified credentials
            $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
            $credential = New-Object System.Management.Automation.PSCredential($username, $securePassword)
            try {
                $result = Enter-PSSession -ComputerName localhost -Credential $credential -ErrorAction Stop
            }
            catch {
                Write-Output "Failed to log in with user '$username' (Attempt $i)"
            }
        }
        # Output a message indicating that the login attempts have completed
        Write-Output "Login attempts complete"

        # Get the current system time
        $currentTime = Get-Date

        # Subtract 15 minutes from the current time
        $newTime = $currentTime.AddMinutes(-15)

        # Set the system time to the new time
        Set-Date $newTime

        # Enter the names of the user accounts to be removed
        $userNames = @("user1", "user2", "user3")

        # Loop through the user names and remove the corresponding user accounts
        foreach ($userName in $userNames) {
            Remove-LocalUser -Name $userName -ErrorAction SilentlyContinue
            Write-Output "User account '$userName' has been removed."
        }
        # Output a message indicating that all specified user accounts have been removed
        Write-Output "All specified user accounts have been removed."

        # Enter the names of the event logs to be backed up and cleared
        $logNames = @("Application", "System", "Security")

        # Set the backup path for the event logs
        $backupPath = "C:\EventLogsBackup"

        # Create the backup directory if it doesn't exist
        if (-not (Test-Path $backupPath)) {
            New-Item -ItemType Directory -Path $backupPath
            Write-Output "Backup directory '$backupPath' created."
        }

        # Loop through the log names, back up each log, and clear the corresponding event logs
        foreach ($logName in $logNames) {
            # Set the backup file name
            $backupFileName = "$backupPath\$logName-$(Get-Date -Format yyyyMMdd-HHmmss).evtx"
    
            # Back up the event log to the backup file
            Export-EventLog -LogName $logName -Path $backupFileName
            Write-Output "Event log '$logName' backed up to '$backupFileName'."
    
            # Clear the event log
            Clear-EventLog -LogName $logName
            Write-Output "Event log '$logName' has been cleared."
        }

        # Output a message indicating that all specified event logs have been backed up and cleared
        Write-Output "All specified event logs have been backed up and cleared."

        # Check if there are any logged on users
        $loggedOnUsers = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName
        if ($loggedOnUsers) {
            Write-Host "There are currently logged on users. The server will not be restarted."
        } else {
            # Set the path to the script that should be run after reboot
            $scriptPath = "C:\Path\To\Script.ps1"

            # Set the RunOnce registry key to execute the script after the next reboot
            $runOnceKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
            New-ItemProperty -Path $runOnceKey -Name "MyScript" -Value $scriptPath -PropertyType String

            # Restart the server
            Restart-Computer
        }


    } elseif ($menuselection -eq "2") {
        Write-Output "Running task for option 2..."
        # Replace this with the task to run for option 2
    } elseif ($menuselection -eq "Q" -or $menuselection -eq "q") {
        Write-Output "Exiting menu..."
        break
    } else {
        Write-Output "Invalid selection '$menuselection'"
    }
}
