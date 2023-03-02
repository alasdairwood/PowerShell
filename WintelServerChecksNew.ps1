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
