<#
.SYNOPSIS
    Proaction Remediation script for cleaning up the local harddrive.

.DESCRIPTION
    This is the remediation script for a Proactive Remediation in Endpoint Analytics used by the Disk Cleanup solution.

.EXAMPLE
    .\Remediation.ps1

.NOTES
    FileName:    Remediation.ps1
    Author:      Nickolaj Andersen (original)
    Updated:     Alasdair Wood (additional detection logic and improvements)
    Contact:     @NickolajA
    Created:     2024-11-25
    Updated:     2026-04-27

    Version history:
    1.0.0 - (2024-11-25) Script created
    1.1.0 - (2026-04-23) Added:
            - Clean user profile temp folder content immediately
            - Clean Windows\Temp folder content immediately
            - Clean SCCM client cache content older than 7 days (COM API with folder fallback)
            - Removed unused variable $RegistryValue
    1.2.0 - (2026-04-27) Added:
            - Detect and remove Windows dump files (retain last 7 days by default)
#>
Begin {
    # Define the proactive remediation name
    $ProactiveRemediationName = "DiskCleanup"

    # Enable TLS 1.2 support for downloading modules from PSGallery
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}
Process {
    # Functions
    function Write-LogEntry {
        param (
            [parameter(Mandatory = $true, HelpMessage = "Value added to the log file.")]
            [ValidateNotNullOrEmpty()]
            [string]$Value,

            [parameter(Mandatory = $true, HelpMessage = "Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error.")]
            [ValidateNotNullOrEmpty()]
            [ValidateSet("1", "2", "3")]
            [string]$Severity,

            [parameter(Mandatory = $false, HelpMessage = "Name of the log file that the entry will written to.")]
            [ValidateNotNullOrEmpty()]
            [string]$FileName = "$($ProactiveRemediationName).log"
        )
        # Check if the script is running as SYSTEM, else use the user's temp folder for the log file location
        if ([Security.Principal.WindowsIdentity]::GetCurrent().IsSystem -eq $true) {
            $LogFilePath = Join-Path -Path (Join-Path -Path $env:ProgramData -ChildPath "Microsoft\IntuneManagementExtension\Logs") -ChildPath $FileName
        }
        else {
            $LogFilePath = Join-Path -Path (Join-Path -Path $env:TEMP -ChildPath "RemediationScript\Logs") -ChildPath $FileName
        }

        # Create log folder path if it does not exist
        try {
            $LogFolderPath = Split-Path -Path $LogFilePath -Parent
            if (-not (Test-Path -Path $LogFolderPath)) {
                New-Item -ItemType "Directory" -Path $LogFolderPath -Force -ErrorAction "Stop" | Out-Null
            }
        }
        catch [System.Exception] {
            Write-Warning -Message "An error occurred while attempting to create the log folder path. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
        }

        # Construct time stamp for log entry
        $Time = -join @((Get-Date -Format "HH:mm:ss.fff"), "+", (Get-WmiObject -Class Win32_TimeZone | Select-Object -ExpandProperty Bias))

        # Construct date for log entry
        $Date = (Get-Date -Format "MM-dd-yyyy")

        # Construct context for log entry
        $Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)

        # Construct final log entry
        $LogText = "<![LOG[$($Value)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""$($ProactiveRemediationName)"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"

        # Add value to log file
        try {
            Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Stop
        }
        catch [System.Exception] {
            Write-Warning -Message "Unable to append log entry $($ProactiveRemediationName).log file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
        }
    }

    function Get-OutlookDefaultProfileFilePathAllUserProfiles {
        Begin {
            # Declare list to store user profiles
            $UserProfileList = New-Object -TypeName "System.Collections.Generic.List[System.Object]"

            # Declare variable to store system specific profiles
            $SystemProfiles = "S-1-5-18", "S-1-5-19", "S-1-5-20"

            # Declare variable for reg.exe executable path (fix: ensure available for unload too)
            $RegExecutable = Join-Path -Path $env:Windir -ChildPath "System32\reg.exe"
        }
        Process {
            # Retrieve all user profiles, exclude system specific profiles
            $RegistryUserProfileListKey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
            Write-LogEntry -Value "Reading list of user profiles from: $($RegistryUserProfileListKey)" -Severity 1

            try {
                $UserProfiles = Get-ChildItem -Path $RegistryUserProfileListKey -ErrorAction "Stop"
                foreach ($UserProfile in $UserProfiles) {
                    Write-LogEntry -Value "Found user profile: $($UserProfile.PSChildName)" -Severity 1

                    try {
                        # Convert current user profile SID to NTAccount
                        $NTAccountSID = New-Object -TypeName "System.Security.Principal.SecurityIdentifier" -ArgumentList $UserProfile.PSChildName
                        $NTAccount = $NTAccountSID.Translate([Security.Principal.NTAccount])

                        # Get user profile properties
                        $ProfileProperties = Get-ItemProperty -Path $UserProfile.PSPath | Where-Object { ($PSItem.ProfileImagePath) }

                        # Determine if user profile is a local account
                        $LocalAccount = Get-CimInstance -ClassName "Win32_Account" -Filter "SID like '$($UserProfile.PSChildName)'"

                        # Add user profile to list if it is not a system profile
                        if ($UserProfile.PSChildName -notin $SystemProfiles) {
                            if ($null -eq $LocalAccount) {
                                Write-LogEntry -Value "User profile is not a local account, adding to user list" -Severity 1
                                $UserProfileList.Add([PSCustomObject]@{
                                    SID = $UserProfile.PSChildName
                                    NTAccount = $NTAccount.Value
                                    ProfileImagePath = $ProfileProperties.ProfileImagePath
                                })
                            }
                            else {
                                Write-LogEntry -Value "User profile is a local account, skipping" -Severity 2
                            }
                        }
                    }
                    catch [System.Exception] {
                        Write-LogEntry -Value "Failed to translate and process user profile: $($UserProfile.PSChildName). Error message: $($_.Exception.Message)" -Severity 3
                    }
                }

                Write-LogEntry -Value "User profile list construction completed" -Severity 1
            }
            catch [System.Exception] {
                Write-LogEntry -Value "Failed to construct list of user profiles. Error message: $($_.Exception.Message)" -Severity 3
            }

            if ($UserProfileList.Count -ge 1) {
                Write-LogEntry -Value "Total count of '$($UserProfileList.Count)' user profiles to be processed" -Severity 1

                $OutlookDefaultProfileFilePathList = New-Object -TypeName "System.Collections.Generic.List[System.Object]"

                foreach ($UserProfile in $UserProfileList) {
                    Write-LogEntry -Value "Processing current user profile for account: $($UserProfile.NTAccount)" -Severity 1

                    $UserRegistryHiveFilePath = Join-Path -Path $UserProfile.ProfileImagePath -ChildPath "NTUSER.DAT"
                    Write-LogEntry -Value "User registry hive local file path: $($UserRegistryHiveFilePath)" -Severity 1

                    $UserRegistryPath = "Registry::HKEY_USERS\$($UserProfile.SID)"
                    Write-LogEntry -Value "Check if user registry hive registry path exist: $($UserRegistryPath)" -Severity 1

                    if (Test-Path -Path $UserRegistryPath) {
                        Write-LogEntry -Value "User registry hive is currently loaded: $($UserRegistryPath)" -Severity 1
                        $UserRegistryHiveLoadRequired = $false
                    }
                    else {
                        Write-LogEntry -Value "User registry hive is not currently loaded: $($UserRegistryPath)" -Severity 1
                        $UserRegistryHiveLoadRequired = $true
                    }

                    if ($UserRegistryHiveLoadRequired -eq $true) {
                        if (Test-Path -Path $UserRegistryHiveFilePath -PathType "Leaf") {
                            $RegArguments = "load ""HKEY_USERS\$($UserProfile.SID)"" ""$($UserRegistryHiveFilePath)"""
                            try {
                                Write-LogEntry -Value "Invoking command: $($RegExecutable) $($RegArguments)" -Severity 1
                                Start-Process -FilePath $RegExecutable -ArgumentList $RegArguments -Wait -ErrorAction "Stop"
                                Write-LogEntry -Value "Successfully loaded user registry hive: $($UserRegistryHiveFilePath)" -Severity 1
                            }
                            catch [System.Exception] {
                                Write-LogEntry -Value "Failed to load user registry hive: $($UserRegistryHiveFilePath)" -Severity 3
                            }
                        }
                        else {
                            Write-LogEntry -Value "User registry hive could not be found: $($UserRegistryHiveFilePath)" -Severity 3
                        }
                    }

                    try {
                        Write-LogEntry -Value "Reading Outlook default profile for user: $($UserProfile.NTAccount)" -Severity 1
                        $DefaultProfile = Get-ItemPropertyValue -Path "Registry::HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Office\16.0\Outlook" -Name "DefaultProfile" -ErrorAction "Stop"
                        Write-LogEntry -Value "Outlook default profile value: $($DefaultProfile)" -Severity 1

                        $DefaultProfileSettingsRegistryPath = "Registry::HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Office\16.0\Outlook\Profiles\$($DefaultProfile)"
                        Write-LogEntry -Value "Outlook default profile settings registry path: $($DefaultProfileSettingsRegistryPath)" -Severity 1

                        $DefaultProfileSettingsItem = Get-ChildItem -Path $DefaultProfileSettingsRegistryPath -ErrorAction "Stop" | Where-Object { $PSItem.Property -like "001f6610" }
                        if ($null -ne $DefaultProfileSettingsItem) {
                            $DefaultProfileSettingsPath = Join-Path -Path "Registry::" -ChildPath $DefaultProfileSettingsItem.Name
                            Write-LogEntry -Value "Outlook default profile settings item path: $($DefaultProfileSettingsPath)" -Severity 1

                            if (Test-Path -Path $DefaultProfileSettingsPath) {
                                $OutlookDefaultProfileByteArray = [byte[]](Get-ItemPropertyValue -Path $DefaultProfileSettingsPath -Name "001f6610")
                                $OutlookDefaultProfileFilePath = [System.Text.Encoding]::Unicode.GetString($OutlookDefaultProfileByteArray).TrimEnd([char]0)
                                Write-LogEntry -Value "Outlook default profile file path: $($OutlookDefaultProfileFilePath)" -Severity 1

                                $UserProfileDetails = [PSCustomObject]@{
                                    SID = $UserProfile.SID
                                    NTAccount = $UserProfile.NTAccount
                                    ProfileImagePath = $UserProfile.ProfileImagePath
                                    OutlookDefaultProfileFilePath = $OutlookDefaultProfileFilePath
                                }

                                $OutlookDefaultProfileFilePathList.Add($UserProfileDetails)
                            }
                            else {
                                Write-LogEntry -Value "Outlook default profile settings path could not be found: $($DefaultProfileSettingsPath)" -Severity 3
                            }
                        }
                        else {
                            Write-LogEntry -Value "Registry value '001f6610' could not be found under: $($DefaultProfileSettingsRegistryPath)" -Severity 3
                        }
                    }
                    catch [System.Exception] {
                        Write-LogEntry -Value "Failed to determine Outlook default profile details for user: $($UserProfile.NTAccount). Error: $($_.Exception.Message)" -Severity 3
                    }

                    if ($UserRegistryHiveLoadRequired -eq $true) {
                        try {
                            Write-LogEntry -Value "Initiating garbage collection before user hive unload command" -Severity 1
                            [GC]::Collect()
                            [GC]::WaitForPendingFinalizers()
                            Start-Sleep -Seconds 5

                            $RegArguments = "unload ""HKEY_USERS\$($UserProfile.SID)"""
                            Write-LogEntry -Value "Invoking command: $($RegExecutable) $($RegArguments)" -Severity 1
                            Start-Process -FilePath $RegExecutable -ArgumentList $RegArguments -Wait -ErrorAction "Stop"
                            Write-LogEntry -Value "Successfully unloaded user registry hive: $($UserRegistryHiveFilePath)" -Severity 1
                        }
                        catch [System.Exception] {
                            Write-LogEntry -Value "Failed to unload user registry hive: $($UserRegistryHiveFilePath)" -Severity 3
                        }
                    }
                }

                return $OutlookDefaultProfileFilePathList
            }
            else {
                Write-LogEntry -Value "No user profiles found" -Severity 2
            }
        }
    }

    # --------------------------
    # NEW: Helpers for temp/cache/dump cleanup
    # --------------------------
    function Get-LocalUserProfiles {
        $SystemProfiles = "S-1-5-18","S-1-5-19","S-1-5-20"
        $ProfileListKey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
        $profiles = New-Object System.Collections.Generic.List[object]

        try {
            Write-LogEntry -Value "Reading user profiles for temp cleanup from: $ProfileListKey" -Severity 1
            foreach ($sidKey in (Get-ChildItem -Path $ProfileListKey -ErrorAction Stop)) {
                $sid = $sidKey.PSChildName
                if ($sid -in $SystemProfiles) { continue }

                $p = Get-ItemProperty -Path $sidKey.PSPath -ErrorAction SilentlyContinue
                if ([string]::IsNullOrWhiteSpace($p.ProfileImagePath)) { continue }
                if (-not (Test-Path -Path $p.ProfileImagePath)) { continue }

                $leaf = Split-Path -Path $p.ProfileImagePath -Leaf
                if ($leaf -in @("Default","Default User","Public","All Users")) { continue }

                $profiles.Add([PSCustomObject]@{
                    SID = $sid
                    ProfileImagePath = $p.ProfileImagePath
                })
            }
        }
        catch {
            Write-LogEntry -Value "Failed to enumerate user profiles for temp cleanup. Error: $($_.Exception.Message)" -Severity 3
        }

        return $profiles
    }

    function Clear-UserTempFolders {
        param([int]$MinAgeDays = 0)

        Write-LogEntry -Value "Initiating cleanup of user profile temp folders (MinAgeDays=$MinAgeDays)" -Severity 1
        $profiles = Get-LocalUserProfiles
        if ($null -eq $profiles -or $profiles.Count -eq 0) {
            Write-LogEntry -Value "No user profiles found for user temp cleanup" -Severity 2
            return
        }

        $cutoff = (Get-Date).AddDays(-$MinAgeDays)

        foreach ($userprofile in $profiles) {
            $tempPath = Join-Path -Path $userprofile.ProfileImagePath -ChildPath "AppData\Local\Temp"
            if (-not (Test-Path -Path $tempPath)) {
                Write-LogEntry -Value "User temp path not found, skipping: $tempPath" -Severity 2
                continue
            }

            Write-LogEntry -Value "Cleaning user temp folder: $tempPath" -Severity 1
            $items = Get-ChildItem -Path $tempPath -Force -ErrorAction SilentlyContinue
            if ($null -eq $items) { continue }

            foreach ($item in $items) {
                try {
                    if ($MinAgeDays -gt 0 -and $item.LastWriteTime -gt $cutoff) { continue }
                    Remove-Item -Path $item.FullName -Recurse -Force -Confirm:$false -ErrorAction Stop
                }
                catch {
                    Write-LogEntry -Value "Failed to remove user temp item '$($item.FullName)'. Error: $($_.Exception.Message)" -Severity 2
                }
            }
        }

        Write-LogEntry -Value "Cleanup of user profile temp folders completed" -Severity 1
    }

    function Clear-WindowsTempFolder {
        Write-LogEntry -Value "Initiating cleanup of Windows Temp folder: $($env:WINDIR)\Temp" -Severity 1
        $WindowsTempPath = Join-Path -Path $env:WINDIR -ChildPath "Temp"

        if (-not (Test-Path -Path $WindowsTempPath)) {
            Write-LogEntry -Value "Windows Temp path not found, skipping: $WindowsTempPath" -Severity 2
            return
        }

        $items = Get-ChildItem -Path $WindowsTempPath -Force -ErrorAction SilentlyContinue
        if ($null -eq $items -or ($items | Measure-Object).Count -eq 0) {
            Write-LogEntry -Value "No items found in Windows Temp folder to clean" -Severity 1
            return
        }

        $count = ($items | Measure-Object).Count
        Write-LogEntry -Value "Found '$count' item(s) in Windows Temp. Attempting deletion (best effort)" -Severity 1

        foreach ($item in $items) {
            try {
                Remove-Item -Path $item.FullName -Recurse -Force -Confirm:$false -ErrorAction Stop
            }
            catch {
                Write-LogEntry -Value "Failed to remove Windows Temp item '$($item.FullName)'. Error: $($_.Exception.Message)" -Severity 2
            }
        }

        Write-LogEntry -Value "Cleanup of Windows Temp folder completed (best effort)" -Severity 1
    }

    function Clear-SCCMClientCache {
        param([int]$MinAgeDays = 7)

        Write-LogEntry -Value "Initiating cleanup of SCCM client cache (retain last $MinAgeDays days)" -Severity 1

        $ccmService = Get-Service -Name "CcmExec" -ErrorAction SilentlyContinue
        if ($null -eq $ccmService) {
            Write-LogEntry -Value "CcmExec service not found - SCCM client likely not installed. Skipping SCCM cache cleanup." -Severity 2
            return
        }

        $cutoff = (Get-Date).AddDays(-$MinAgeDays)
        $deletedCount = 0
        $usedComApi = $false

        try {
            $ui = New-Object -ComObject "UIResource.UIResourceMgr"
            $cache = $ui.GetCacheInfo()
            $elements = @($cache.GetCacheElements())

            Write-LogEntry -Value "SCCM cache elements found via COM API: $($elements.Count)" -Severity 1

            foreach ($e in $elements) {
                try {
                    $skip = $false

                    $refTime = $null
                    try {
                        if ($null -ne $e.LastReferenceTime -and $e.LastReferenceTime.ToString().Length -gt 0) {
                            $refTime = [datetime]$e.LastReferenceTime
                        }
                    } catch { }

                    if ($null -ne $refTime) {
                        if ($refTime -gt $cutoff) { $skip = $true }
                    }
                    else {
                        if ($null -ne $e.Location -and (Test-Path -Path $e.Location)) {
                            $locItem = Get-Item -Path $e.Location -ErrorAction SilentlyContinue
                            if ($null -ne $locItem -and $locItem.LastWriteTime -gt $cutoff) { $skip = $true }
                        }
                    }

                    if ($skip) {
                        Write-LogEntry -Value "Keeping SCCM cache element (recent): ID=$($e.CacheElementID) Location=$($e.Location)" -Severity 1
                        continue
                    }

                    $cache.DeleteCacheElement($e.CacheElementID)
                    $deletedCount++
                    Write-LogEntry -Value "Deleted SCCM cache element: ID=$($e.CacheElementID) Location=$($e.Location)" -Severity 1
                }
                catch {
                    Write-LogEntry -Value "Failed to delete SCCM cache element. Error: $($_.Exception.Message)" -Severity 2
                }
            }

            $usedComApi = $true
            Write-LogEntry -Value "SCCM cache cleanup via COM API completed. Elements deleted: $deletedCount" -Severity 1
        }
        catch {
            Write-LogEntry -Value "COM API cache cleanup unavailable/failed. Falling back to folder cleanup. Error: $($_.Exception.Message)" -Severity 2
        }

        if (-not $usedComApi) {
            $cachePath = Join-Path -Path $env:Windir -ChildPath "ccmcache"
            if (-not (Test-Path -Path $cachePath)) {
                Write-LogEntry -Value "SCCM cache folder not found: $cachePath" -Severity 2
                return
            }

            Write-LogEntry -Value "Cleaning SCCM cache folder contents older than cutoff: $cachePath" -Severity 1
            $items = Get-ChildItem -Path $cachePath -Force -ErrorAction SilentlyContinue

            foreach ($item in $items) {
                try {
                    if ($item.LastWriteTime -gt $cutoff) {
                        Write-LogEntry -Value "Keeping recent SCCM cache item: $($item.FullName)" -Severity 1
                        continue
                    }

                    Remove-Item -Path $item.FullName -Recurse -Force -Confirm:$false -ErrorAction Stop
                    $deletedCount++
                    Write-LogEntry -Value "Deleted SCCM cache item: $($item.FullName)" -Severity 1
                }
                catch {
                    Write-LogEntry -Value "Failed to remove SCCM cache item '$($item.FullName)'. Error: $($_.Exception.Message)" -Severity 2
                }
            }

            Write-LogEntry -Value "SCCM cache folder cleanup completed. Items deleted: $deletedCount" -Severity 1
        }
    }

    # NEW: Windows dump files cleanup
    function Clear-WindowsDumpFiles {
        param([int]$MinAgeDays = 7)

        $cutoff = (Get-Date).AddDays(-$MinAgeDays)
        Write-LogEntry -Value "Initiating cleanup of Windows dump files (MinAgeDays=$MinAgeDays)" -Severity 1

        $targets = New-Object System.Collections.Generic.List[System.IO.FileInfo]

        # 1) Full memory dump
        $memoryDump = Join-Path -Path $env:WINDIR -ChildPath "MEMORY.DMP"
        if (Test-Path -Path $memoryDump) {
            $fi = Get-Item -Path $memoryDump -ErrorAction SilentlyContinue
            if ($null -ne $fi) {
                if ($MinAgeDays -eq 0 -or $fi.LastWriteTime -lt $cutoff) { $targets.Add($fi) }
                else { Write-LogEntry -Value "Keeping recent dump: $memoryDump (LastWriteTime=$($fi.LastWriteTime))" -Severity 1 }
            }
        }

        # 2) Minidumps
        $miniDir = Join-Path -Path $env:WINDIR -ChildPath "Minidump"
        if (Test-Path -Path $miniDir) {
            Get-ChildItem -Path $miniDir -File -Filter "*.dmp" -ErrorAction SilentlyContinue | ForEach-Object {
                if ($MinAgeDays -eq 0 -or $_.LastWriteTime -lt $cutoff) { $targets.Add($_) }
            }
            Get-ChildItem -Path $miniDir -File -Filter "*.hdmp" -ErrorAction SilentlyContinue | ForEach-Object {
                if ($MinAgeDays -eq 0 -or $_.LastWriteTime -lt $cutoff) { $targets.Add($_) }
            }
        }

        # 3) LiveKernelReports dumps (recursive)
        $liveDir = Join-Path -Path $env:WINDIR -ChildPath "LiveKernelReports"
        if (Test-Path -Path $liveDir) {
            Get-ChildItem -Path $liveDir -File -Recurse -Filter "*.dmp" -ErrorAction SilentlyContinue | ForEach-Object {
                if ($MinAgeDays -eq 0 -or $_.LastWriteTime -lt $cutoff) { $targets.Add($_) }
            }
            Get-ChildItem -Path $liveDir -File -Recurse -Filter "*.hdmp" -ErrorAction SilentlyContinue | ForEach-Object {
                if ($MinAgeDays -eq 0 -or $_.LastWriteTime -lt $cutoff) { $targets.Add($_) }
            }
        }

        if ($targets.Count -eq 0) {
            Write-LogEntry -Value "No dump files found matching the removal criteria" -Severity 1
            return
        }

        # Log total size
        $totalBytes = ($targets | Measure-Object -Property Length -Sum).Sum
        $totalGB = [math]::Round(($totalBytes / 1GB), 2)
        Write-LogEntry -Value "Found '$($targets.Count)' dump file(s) to remove. Total size: $totalGB GB" -Severity 1

        foreach ($t in $targets) {
            try {
                Write-LogEntry -Value "Removing dump file: $($t.FullName)" -Severity 1
                Remove-Item -Path $t.FullName -Force -ErrorAction Stop
            }
            catch {
                Write-LogEntry -Value "Failed to remove dump file '$($t.FullName)'. Error: $($_.Exception.Message)" -Severity 2
            }
        }

        Write-LogEntry -Value "Cleanup of Windows dump files completed (best effort)" -Severity 1
    }

    # --------------------------
    # Configuration for additions
    # --------------------------
    $UserTempMinAgeDays = 0        # Clean immediately
    $SCCMCacheMinAgeDays = 7       # Keep SCCM cache content for 7 days
    $ClearSCCMClientCache = $true  # Toggle SCCM cache cleanup
    $DumpMinAgeDays = 7            # Keep dump files for 7 days (set 0 to remove immediately)

    # Handle initial value for exit code variable
    $ExitCode = 0

    # Initial logging details for remediation script
    Write-LogEntry -Value "[$($ProactiveRemediationName)-Remediation] - Initializing" -Severity 1

    # Retrieve free disk space on system drive
    Write-LogEntry -Value "Retrieving free disk space on system drive from WMI class: Win32_LogicalDisk" -Severity 1
    $FreeDiskSpaceBefore = [math]::Round((Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='$($env:SystemDrive)'" -ErrorAction "Stop" | Select-Object -ExpandProperty FreeSpace) / 1GB, 2)
    Write-LogEntry -Value "Free disk space on system drive: $($FreeDiskSpaceBefore) GB" -Severity 1

    try {
        # Clear existing sage run settings
        Write-LogEntry -Value "Removing existing CleanMgr.exe sage run settings" -Severity 1
        Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\*" -Name "StateFlags0001" -ErrorAction "SilentlyContinue" |
            Remove-ItemProperty -Name "StateFlags0001" -ErrorAction "Stop"

        # Enable sage run settings
        $SageRunSettings = @(
            "Update Cleanup", "Temporary Files", "Delivery Optimization Files", "Previous Installations",
            "Downloaded Program Files", "Recycle Bin", "Internet Cache Files", "Device Driver Packages", "Thumbnail Cache"
        )
        foreach ($SageRunSetting in $SageRunSettings) {
            try {
                Write-LogEntry -Value "Enabling '$($SageRunSetting)' sage run setting" -Severity 1

                # Removed unused $RegistryValue variable assignment
                New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\$($SageRunSetting)" -Name "StateFlags0001" -Value 2 -PropertyType DWord -ErrorAction "Stop" | Out-Null
            }
            catch [System.Exception] {
                Write-LogEntry -Value "Failed to enable '$($SageRunSetting)' sage run setting. Error message: $($_.Exception.Message)" -Severity 3
                $ExitCode = 1
            }
        }

        try {
            $TaskPath = "\"
            $TaskName = "Disk Cleanup"

            $ScheduledTaskExists = Get-ScheduledTask -TaskName $TaskName -ErrorAction "SilentlyContinue"
            if ($null -ne $ScheduledTaskExists) {
                Write-LogEntry -Value "Scheduled task already exists: $($TaskName)" -Severity 1
                try {
                    Write-LogEntry -Value "Unregistering scheduled task: $($TaskName)" -Severity 1
                    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction "Stop"
                }
                catch [System.Exception] {
                    Write-LogEntry -Value "Failed to unregister scheduled task. Error message: $($_.Exception.Message)" -Severity 3
                    $ExitCode = 1
                }
            }

            try {
                $TaskAction = New-ScheduledTaskAction -Execute "CleanMgr.exe" -Argument "/sagerun:1"
                $TaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -Hidden -DontStopIfGoingOnBatteries -Compatibility "Win8" -MultipleInstances "IgnoreNew" -ErrorAction Stop
                $TaskPrincipal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType "ServiceAccount" -RunLevel "Highest" -ErrorAction "Stop"

                try {
                    Write-LogEntry -Value "Registering scheduled task: $($TaskName)" -Severity 1
                    $ScheduledTask = New-ScheduledTask -Action $TaskAction -Principal $TaskPrincipal -Settings $TaskSettings -ErrorAction "Stop"
                    $ScheduledTask = Register-ScheduledTask -InputObject $ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction "Stop"

                    try {
                        Write-LogEntry -Value "Running scheduled task: $($TaskName)" -Severity 1
                        Start-ScheduledTask -TaskName $TaskName -ErrorAction "Stop"

                        $StopWatch = [System.Diagnostics.Stopwatch]::StartNew()
                        $Timeout = 1800

                        Write-LogEntry -Value "Waiting for scheduled task to complete" -Severity 1
                        while ($StopWatch.Elapsed.TotalSeconds -lt $Timeout) {
                            $ScheduledTaskState = Get-ScheduledTask -TaskName $TaskName | Select-Object -ExpandProperty "State"
                            if ($ScheduledTaskState -eq "Ready") {
                                Write-LogEntry -Value "Scheduled task completed" -Severity 1
                                break
                            }
                            else {
                                Start-Sleep -Seconds 1
                            }
                        }

                        $StopWatch.Stop()
                        Write-LogEntry -Value "Disk Cleanup activities completed" -Severity 1
                    }
                    catch [System.Exception] {
                        Write-LogEntry -Value "Failed to run scheduled task. Error message: $($_.Exception.Message)" -Severity 3
                        $ExitCode = 1
                    }
                }
                catch [System.Exception] {
                    Write-LogEntry -Value "Failed to register scheduled task. Error message: $($_.Exception.Message)" -Severity 3
                    $ExitCode = 1
                }
            }
            catch [System.Exception] {
                Write-LogEntry -Value "Failed to construct scheduled task objects. Error message: $($_.Exception.Message)" -Severity 3
                $ExitCode = 1
            }
        }
        catch [System.Exception] {
            Write-LogEntry -Value "Failed to execute Disk Cleanup utility. Error message: $($_.Exception.Message)" -Severity 3
            $ExitCode = 1
        }
    }
    catch [System.Exception] {
        Write-LogEntry -Value "Failed to clear CleanMgr.exe sage run settings. Error message: $($_.Exception.Message)" -Severity 3
        $ExitCode = 1
    }

    try {
        Write-LogEntry -Value "Initiating cleanup of Outlook unused .ost files" -Severity 1
        $OutlookDefaultProfileFilePathList = Get-OutlookDefaultProfileFilePathAllUserProfiles

        if ($null -ne $OutlookDefaultProfileFilePathList) {
            $OutlookOSTFiles = Get-ChildItem -Path "$($env:SystemDrive)\Users\*\AppData\Local\Microsoft\Outlook" -Filter "*.ost" -Recurse -ErrorAction "SilentlyContinue"
            if ($null -ne $OutlookOSTFiles) {
                Write-LogEntry -Value "Found a total of '$($OutlookOSTFiles.Count)' Outlook .ost files in all users' specific Outlook app data folder" -Severity 1

                foreach ($OutlookOSTFile in $OutlookOSTFiles) {
                    Write-LogEntry -Value "Checking if current .ost file '$($OutlookOSTFile.FullName)' is in the list of default profiles" -Severity 1
                    if ($OutlookDefaultProfileFilePathList.OutlookDefaultProfileFilePath -notcontains $OutlookOSTFile.FullName) {
                        $LastAccessTime = (Get-Item -Path $OutlookOSTFile.FullName).LastAccessTime
                        $DaysSinceLastAccess = [math]::Round((New-TimeSpan -Start $LastAccessTime -End (Get-Date)).TotalDays)
                        Write-LogEntry -Value "Last access time for current .ost file: $($LastAccessTime). Days since last access: $($DaysSinceLastAccess)" -Severity 1

                        if ($DaysSinceLastAccess -ge 90) {
                            try {
                                Write-LogEntry -Value "Removing Outlook .ost file: $($OutlookOSTFile.FullName)" -Severity 1
                                Remove-Item -Path $OutlookOSTFile.FullName -Force -ErrorAction "Stop"
                            }
                            catch [System.Exception] {
                                Write-LogEntry -Value "Failed to remove Outlook .ost file '$($OutlookOSTFile.FullName)'. Error message: $($_.Exception.Message)" -Severity 3
                                $ExitCode = 1
                            }
                        }
                        else {
                            Write-LogEntry -Value "Skipping removal of Outlook .ost file '$($OutlookOSTFile.FullName)' since it was last accessed within the 90 day threshold" -Severity 1
                        }
                    }
                    else {
                        Write-LogEntry -Value "Skipping removal of Outlook .ost file: $($OutlookOSTFile.FullName)" -Severity 1
                    }
                }

                Write-LogEntry -Value "Cleanup of Outlook .ost files completed" -Severity 1
            }
            else {
                Write-LogEntry -Value "No Outlook .ost files found in any user's specific Outlook app data folder" -Severity 1
            }
        }
    }
    catch [System.Exception] {
        Write-LogEntry -Value "Failed to process Outlook .ost files. Error message: $($_.Exception.Message)" -Severity 3
        $ExitCode = 1
    }

    try {
        Write-LogEntry -Value "Initiating cleanup of Teams cache folders" -Severity 1
        $TeamsCacheFolders = Get-ChildItem -Path "$($env:SystemDrive)\Users\*\AppData\Roaming\Microsoft\Teams\Cache" -ErrorAction "SilentlyContinue"
        if ($null -ne $TeamsCacheFolders) {
            Write-LogEntry -Value "Found a total of '$($TeamsCacheFolders.Count)' Teams cache folders in all user's specific Teams app data folder" -Severity 1

            foreach ($TeamsCacheFolder in $TeamsCacheFolders) {
                if (Test-Path -Path $TeamsCacheFolder.FullName) {
                    $TeamsCacheFolderItems = Get-ChildItem -Path $TeamsCacheFolder.FullName -Recurse -ErrorAction "SilentlyContinue"
                    $TeamsCacheFoldersItemsCount = ($TeamsCacheFolderItems | Measure-Object).Count
                    Write-LogEntry -Value "Found a total of '$($TeamsCacheFoldersItemsCount)' items in Teams cache folder: $($TeamsCacheFolder.FullName)" -Severity 1

                    Write-LogEntry -Value "Removing items from Teams cache folder: $($TeamsCacheFolder.FullName)" -Severity 1
                    foreach ($TeamsCacheFolderItem in $TeamsCacheFolderItems) {
                        try {
                            Remove-Item -Path $TeamsCacheFolderItem.FullName -Recurse -Force -Confirm:$false -ErrorAction "Stop"
                        }
                        catch [System.Exception] {
                            Write-LogEntry -Value "Failed to remove item from Teams cache folder '$($TeamsCacheFolder.FullName)'. Error message: $($_.Exception.Message)" -Severity 3
                        }
                    }
                }
                else {
                    Write-LogEntry -Value "Teams cache folder '$($TeamsCacheFolder.FullName)' does not exist" -Severity 2
                }
            }

            Write-LogEntry -Value "Cleanup of Teams cache folders completed" -Severity 1
        }
        else {
            Write-LogEntry -Value "No Teams cache folders found in any users' specific Teams app data folder" -Severity 1
        }
    }
    catch [System.Exception] {
        Write-LogEntry -Value "Failed to process Teams cache folders. Error message: $($_.Exception.Message)" -Severity 3
        $ExitCode = 1
    }

    # NEW: User profile temp cleanup
    try {
        Clear-UserTempFolders -MinAgeDays $UserTempMinAgeDays
    }
    catch [System.Exception] {
        Write-LogEntry -Value "Failed to process user profile temp folders. Error message: $($_.Exception.Message)" -Severity 3
        $ExitCode = 1
    }

    # NEW: Windows Temp cleanup
    try {
        Clear-WindowsTempFolder
    }
    catch [System.Exception] {
        Write-LogEntry -Value "Failed to process Windows Temp folder. Error message: $($_.Exception.Message)" -Severity 3
        $ExitCode = 1
    }

    # NEW: Windows dump files cleanup
    try {
        Clear-WindowsDumpFiles -MinAgeDays $DumpMinAgeDays
    }
    catch [System.Exception] {
        Write-LogEntry -Value "Failed to process Windows dump files. Error message: $($_.Exception.Message)" -Severity 3
        $ExitCode = 1
    }

    # NEW: SCCM cache cleanup (retain 7 days)
    if ($ClearSCCMClientCache -eq $true) {
        try {
            Clear-SCCMClientCache -MinAgeDays $SCCMCacheMinAgeDays
        }
        catch [System.Exception] {
            Write-LogEntry -Value "Failed to process SCCM client cache. Error message: $($_.Exception.Message)" -Severity 3
            $ExitCode = 1
        }
    }
    else {
        Write-LogEntry -Value "SCCM cache cleanup disabled by configuration" -Severity 1
    }

    # Retrieve free disk space on system drive after cleanup
    $FreeDiskSpaceAfter = [math]::Round((Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='$($env:SystemDrive)'" -ErrorAction "Stop" | Select-Object -ExpandProperty FreeSpace) / 1GB, 2)
    $CleanedUpDiskSpace = [math]::Round($FreeDiskSpaceAfter - $FreeDiskSpaceBefore, 2)
    Write-LogEntry -Value "Cleanup activities cleaned up a total of: $($CleanedUpDiskSpace) GB" -Severity 1

    Write-LogEntry -Value "[$($ProactiveRemediationName)-Remediation] - Completed" -Severity 1
    Write-Output -InputObject "Cleaned up a total of: $($CleanedUpDiskSpace) GB"
    exit $ExitCode
}