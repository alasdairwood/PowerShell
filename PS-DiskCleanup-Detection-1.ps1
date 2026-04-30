<#
.SYNOPSIS
    Proaction Remediation script for cleaning up the local harddrive.

.DESCRIPTION
    This is the detection script for a Proactive Remediation in Endpoint Analytics used by the Disk Cleanup solution.

    Updated to trigger remediation when any of the following are true:
      - Free space on system drive is below a threshold (default 64GB)
      - SCCM client cache has content older than retention (default 7 days)
      - Windows dump files exist older than retention (default 7 days)
      - Windows\Temp folder size exceeds a threshold (default 1GB) [optional]
      - Combined user profile Temp folders exceed a threshold (default 1GB) [optional]

.EXAMPLE
    .\Detection.ps1

.NOTES
    FileName:    Detection.ps1
    Author:      Nickolaj Andersen (original)
    Updated:     Alasdair Wood (additional detection logic and improvements)
    Updated:     2026-04-27

    Version history:
    1.0.0 - (2024-11-25) Script created
    1.1.0 - (2026-04-23) Updated detection to reflect remediation additions:
            - User Temp cleanup
            - Windows Temp cleanup
            - SCCM cache cleanup (retain 7 days)
    1.2.0 - (2026-04-27) Updated detection to reflect remediation additions:
            - Windows dump file cleanup (retain 7 days)
#>

Begin {
    # Define the proactive remediation name
    $ProactiveRemediationName = "DiskCleanup"

    # Set company name (used for execution history registry path)
    # IMPORTANT: Replace with your org name to avoid "<company_name>" literal keys in HKLM
    $CompanyName = "NHSL"

    # Define if any modules must be present on the device for this proactive remediation to execute properly
    $Modules = @()

    # Enable TLS 1.2 support for downloading modules from PSGallery
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Install required modules for script execution (none by default)
    if ($null -ne $Modules) {
        foreach ($Module in $Modules) {
            try {
                $CurrentModule = Get-InstalledModule -Name $Module -ErrorAction "Stop" -Verbose:$false
                if ($null -ne $CurrentModule) {
                    $LatestModuleVersion = (Find-Module -Name $Module -ErrorAction "Stop" -Verbose:$false).Version
                    if ($LatestModuleVersion -gt $CurrentModule.Version) {
                        Update-Module -Name $Module -Force -AcceptLicense -ErrorAction "Stop" -Confirm:$false -Verbose:$false
                    }
                }
            }
            catch {
                try {
                    Install-PackageProvider -Name "NuGet" -Force -Verbose:$false | Out-Null
                    Install-Module -Name $Module -Force -AcceptLicense -ErrorAction "Stop" -Confirm:$false -Verbose:$false
                }
                catch {
                    Write-Warning -Message "An error occurred while attempting to install $Module. Error: $($_.Exception.Message)"
                }
            }
        }
    }

    # --------------------------
    # Detection configuration
    # --------------------------
    $MinimumFreeSpaceGB      = 64
    $MaxExecutions           = 100

    # Retention days (must match remediation intent)
    $SCCMCacheRetentionDays  = 7
    $DumpRetentionDays       = 7

    # Optional extra triggers (set to $false if you only want the <64GB trigger)
    $EnableWindowsTempCheck  = $true
    $WindowsTempThresholdGB  = 1

    $EnableUserTempCheck     = $true
    $UserTempThresholdGB     = 1

    # If you want to keep the original behaviour (skip remediation on Windows 11), set to $true
    $SkipWindows11           = $false

    # Safety cap to prevent very expensive folder-size enumerations
    $MaxFilesToMeasure       = 50000
}

Process {
    function Write-LogEntry {
        param (
            [parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Value,
            [parameter(Mandatory = $true)][ValidateSet("1", "2", "3")][string]$Severity,
            [parameter(Mandatory = $false)][ValidateNotNullOrEmpty()][string]$FileName = "$($ProactiveRemediationName).log"
        )

        if ([Security.Principal.WindowsIdentity]::GetCurrent().IsSystem -eq $true) {
            $LogFilePath = Join-Path -Path (Join-Path -Path $env:ProgramData -ChildPath "Microsoft\IntuneManagementExtension\Logs") -ChildPath $FileName
        }
        else {
            $LogFilePath = Join-Path -Path (Join-Path -Path $env:TEMP -ChildPath "RemediationScript\Logs") -ChildPath $FileName
        }

        try {
            $LogFolderPath = Split-Path -Path $LogFilePath -Parent
            if (-not (Test-Path -Path $LogFolderPath)) {
                New-Item -ItemType "Directory" -Path $LogFolderPath -Force -ErrorAction "Stop" | Out-Null
            }
        }
        catch {
            Write-Warning -Message "Failed to create log folder. Error: $($_.Exception.Message)"
        }

        $Bias = (Get-CimInstance -ClassName Win32_TimeZone -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Bias)
        if ($null -eq $Bias) { $Bias = 0 }

        $Time = -join @((Get-Date -Format "HH:mm:ss.fff"), "+", $Bias)
        $Date = (Get-Date -Format "MM-dd-yyyy")
        $Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)

        $LogText = "<![LOG[$Value]LOG]!><time=""$Time"" date=""$Date"" component=""$ProactiveRemediationName"" context=""$Context"" type=""$Severity"" thread=""$PID"" file="""">"

        try {
            Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Stop
        }
        catch {
            Write-Warning -Message "Unable to append log entry. Error: $($_.Exception.Message)"
        }
    }

    function Get-WindowsVersion {
        try {
            $build = [int](Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop | Select-Object -ExpandProperty BuildNumber)
            switch ($build) {
                { $_ -in 19000..19045 } { return "Windows 10" }
                { $_ -ge 22000 }        { return "Windows 11" }
                default                 { return "Unknown" }
            }
        }
        catch {
            Write-LogEntry -Value "Failed to retrieve Windows build number. Error: $($_.Exception.Message)" -Severity 3
            return "Unknown"
        }
    }

    function Get-FreeSpaceGB {
        try {
            $FreeDiskSpace = [math]::Round((Get-CimInstance -Class Win32_LogicalDisk -Filter "DeviceID='$($env:SystemDrive)'" -ErrorAction Stop | Select-Object -ExpandProperty FreeSpace) / 1GB)
            return $FreeDiskSpace
        }
        catch {
            Write-LogEntry -Value "Failed to retrieve free disk space. Error: $($_.Exception.Message)" -Severity 3
            return $null
        }
    }

    function Get-LocalUserProfilePaths {
        $SystemProfiles = "S-1-5-18","S-1-5-19","S-1-5-20"
        $ProfileListKey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
        $paths = New-Object System.Collections.Generic.List[string]

        try {
            foreach ($sidKey in (Get-ChildItem -Path $ProfileListKey -ErrorAction Stop)) {
                if ($sidKey.PSChildName -in $SystemProfiles) { continue }

                $p = Get-ItemProperty -Path $sidKey.PSPath -ErrorAction SilentlyContinue
                if ([string]::IsNullOrWhiteSpace($p.ProfileImagePath)) { continue }
                if (-not (Test-Path -Path $p.ProfileImagePath)) { continue }

                $leaf = Split-Path -Path $p.ProfileImagePath -Leaf
                if ($leaf -in @("Default","Default User","Public","All Users")) { continue }

                $paths.Add($p.ProfileImagePath)
            }
        }
        catch {
            Write-LogEntry -Value "Failed to enumerate local user profiles. Error: $($_.Exception.Message)" -Severity 2
        }

        return $paths
    }

    function Get-FolderSizeGB {
        param(
            [Parameter(Mandatory=$true)][string]$Path,
            [int]$FileCap = 50000
        )

        if (-not (Test-Path -Path $Path)) { return 0 }

        try {
            $files = Get-ChildItem -Path $Path -File -Recurse -Force -ErrorAction SilentlyContinue | Select-Object -First $FileCap
            if ($null -eq $files) { return 0 }

            $bytes = ($files | Measure-Object -Property Length -Sum).Sum
            if ($null -eq $bytes) { $bytes = 0 }

            return [math]::Round(($bytes / 1GB), 2)
        }
        catch {
            Write-LogEntry -Value "Failed to calculate folder size for '$Path'. Error: $($_.Exception.Message)" -Severity 2
            return 0
        }
    }

    function Test-OldSCCMCacheContent {
        param([int]$RetentionDays = 7)

        $result = [PSCustomObject]@{
            ClientInstalled = $false
            OldItemCount    = 0
            HasOldContent   = $false
            CachePath       = "$env:WINDIR\ccmcache"
        }

        $svc = Get-Service -Name "CcmExec" -ErrorAction SilentlyContinue
        if ($null -eq $svc) { return $result }

        $result.ClientInstalled = $true

        if (-not (Test-Path -Path $result.CachePath)) { return $result }

        $cutoff = (Get-Date).AddDays(-$RetentionDays)

        try {
            # ccmcache usually contains many subfolders directly under ccmcache
            $items = Get-ChildItem -Path $result.CachePath -Force -ErrorAction SilentlyContinue
            $old = $items | Where-Object { $_.LastWriteTime -lt $cutoff }
            $count = ($old | Measure-Object).Count

            $result.OldItemCount  = $count
            $result.HasOldContent = ($count -gt 0)
        }
        catch {
            Write-LogEntry -Value "Failed to inspect SCCM cache content. Error: $($_.Exception.Message)" -Severity 2
        }

        return $result
    }

    function Test-OldDumpFiles {
        param([int]$RetentionDays = 7)

        $cutoff = (Get-Date).AddDays(-$RetentionDays)
        $found = New-Object System.Collections.Generic.List[System.IO.FileInfo]

        # MEMORY.DMP
        $memoryDump = Join-Path -Path $env:WINDIR -ChildPath "MEMORY.DMP"
        if (Test-Path -Path $memoryDump) {
            $fi = Get-Item -Path $memoryDump -ErrorAction SilentlyContinue
            if ($null -ne $fi -and $fi.LastWriteTime -lt $cutoff) { $found.Add($fi) }
        }

        # Minidump
        $miniDir = Join-Path -Path $env:WINDIR -ChildPath "Minidump"
        if (Test-Path -Path $miniDir) {
            Get-ChildItem -Path $miniDir -File -Filter "*.dmp"  -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $cutoff } | ForEach-Object { $found.Add($_) }
            Get-ChildItem -Path $miniDir -File -Filter "*.hdmp" -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $cutoff } | ForEach-Object { $found.Add($_) }
        }

        # LiveKernelReports
        $liveDir = Join-Path -Path $env:WINDIR -ChildPath "LiveKernelReports"
        if (Test-Path -Path $liveDir) {
            Get-ChildItem -Path $liveDir -File -Recurse -Filter "*.dmp"  -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $cutoff } | ForEach-Object { $found.Add($_) }
            Get-ChildItem -Path $liveDir -File -Recurse -Filter "*.hdmp" -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $cutoff } | ForEach-Object { $found.Add($_) }
        }

        $totalBytes = 0
        if ($found.Count -gt 0) {
            $totalBytes = ($found | Measure-Object -Property Length -Sum).Sum
            if ($null -eq $totalBytes) { $totalBytes = 0 }
        }

        return [PSCustomObject]@{
            OldDumpCount  = $found.Count
            OldDumpSizeGB = [math]::Round(($totalBytes / 1GB), 2)
            HasOldDumps   = ($found.Count -gt 0)
        }
    }

    # --------------------------
    # Start detection
    # --------------------------
    Write-LogEntry -Value "[$ProactiveRemediationName-Detection] - Initializing" -Severity 1

    $ErrorMessage = $null
    $TriggerRemediation = $false
    $TriggerReasons = New-Object System.Collections.Generic.List[string]

    # Execution history registry path/value
    $ExecutionHistoryRegistryPath = "HKLM:\SOFTWARE\$CompanyName\ProactiveRemediations\$ProactiveRemediationName"
    $ExecutionHistoryRegistryValue = "Count"

    # Ensure registry key exists
    if (-not (Test-Path -Path $ExecutionHistoryRegistryPath)) {
        try {
            New-Item -Path $ExecutionHistoryRegistryPath -Force -ErrorAction "Stop" | Out-Null
        }
        catch {
            $ErrorMessage = "Failed to create registry key '$ExecutionHistoryRegistryPath'. Error: $($_.Exception.Message)"
            Write-LogEntry -Value $ErrorMessage -Severity 3
        }
    }

    # Ensure registry value exists
    if ($null -eq (Get-ItemProperty -Path $ExecutionHistoryRegistryPath -Name $ExecutionHistoryRegistryValue -ErrorAction "SilentlyContinue")) {
        try {
            New-ItemProperty -Path $ExecutionHistoryRegistryPath -Name $ExecutionHistoryRegistryValue -Value 0 -PropertyType "String" -Force -ErrorAction "Stop" | Out-Null
        }
        catch {
            $ErrorMessage = "Failed to create registry value '$ExecutionHistoryRegistryValue' at '$ExecutionHistoryRegistryPath'. Error: $($_.Exception.Message)"
            Write-LogEntry -Value $ErrorMessage -Severity 3
        }
    }

    $ExecutionHistoryCount = [int](Get-ItemProperty -Path $ExecutionHistoryRegistryPath -Name $ExecutionHistoryRegistryValue -ErrorAction "SilentlyContinue").$ExecutionHistoryRegistryValue
    Write-LogEntry -Value "Execution history count: $ExecutionHistoryCount / Max: $MaxExecutions" -Severity 1

    if ($ExecutionHistoryCount -ge $MaxExecutions) {
        Write-LogEntry -Value "Maximum number of allowed executions reached ($MaxExecutions). Exiting detection." -Severity 1
        Write-Output "Maximum number of allowed executions reached"
        exit 0
    }

    # OS gate (optional)
    $WindowsVersion = Get-WindowsVersion
    Write-LogEntry -Value "Detected OS: $WindowsVersion" -Severity 1
    if ($SkipWindows11 -eq $true -and $WindowsVersion -eq "Windows 11") {
        Write-LogEntry -Value "SkipWindows11 is enabled. Device is Windows 11. No remediation will be triggered." -Severity 1
        Write-Output "No remediation required (Windows 11 excluded)"
        exit 0
    }

    # Free space trigger
    $FreeDiskSpace = Get-FreeSpaceGB
    if ($null -ne $FreeDiskSpace) {
        Write-LogEntry -Value "Free disk space on system drive: $FreeDiskSpace GB" -Severity 1
        if ($FreeDiskSpace -lt $MinimumFreeSpaceGB) {
            $TriggerRemediation = $true
            $TriggerReasons.Add("FreeSpace<$MinimumFreeSpaceGB GB (Current=$FreeDiskSpace GB)")
        }
    }
    else {
        $ErrorMessage = "Failed to retrieve free disk space."
        Write-LogEntry -Value $ErrorMessage -Severity 3
    }

    # SCCM cache trigger (old items)
    $sccm = Test-OldSCCMCacheContent -RetentionDays $SCCMCacheRetentionDays
    if ($sccm.ClientInstalled -eq $true) {
        Write-LogEntry -Value "SCCM client detected. Old cache items (>$SCCMCacheRetentionDays days): $($sccm.OldItemCount)" -Severity 1
        if ($sccm.HasOldContent -eq $true) {
            $TriggerRemediation = $true
            $TriggerReasons.Add("SCCMCacheOldItems>$SCCMCacheRetentionDays days (Count=$($sccm.OldItemCount))")
        }
    }
    else {
        Write-LogEntry -Value "SCCM client not detected. SCCM cache trigger skipped." -Severity 1
    }

    # Dump files trigger (old dumps)
    $dumps = Test-OldDumpFiles -RetentionDays $DumpRetentionDays
    Write-LogEntry -Value "Old dump files (>$DumpRetentionDays days): $($dumps.OldDumpCount) (Size=$($dumps.OldDumpSizeGB) GB)" -Severity 1
    if ($dumps.HasOldDumps -eq $true) {
        $TriggerRemediation = $true
        $TriggerReasons.Add("OldDumpFiles>$DumpRetentionDays days (Count=$($dumps.OldDumpCount),Size=$($dumps.OldDumpSizeGB)GB)")
    }

    # Windows\Temp size trigger (optional)
    if ($EnableWindowsTempCheck -eq $true) {
        $winTempPath = Join-Path -Path $env:WINDIR -ChildPath "Temp"
        $winTempSizeGB = Get-FolderSizeGB -Path $winTempPath -FileCap $MaxFilesToMeasure
        Write-LogEntry -Value "Windows Temp size: $winTempSizeGB GB (Threshold=$WindowsTempThresholdGB GB, Cap=$MaxFilesToMeasure files)" -Severity 1

        if ($winTempSizeGB -ge $WindowsTempThresholdGB) {
            $TriggerRemediation = $true
            $TriggerReasons.Add("WindowsTempSize>=$WindowsTempThresholdGB GB (Current=$winTempSizeGB GB)")
        }
    }

    # User Temp size trigger (optional, combined)
    if ($EnableUserTempCheck -eq $true) {
        $totalUserTempGB = 0
        $profiles = Get-LocalUserProfilePaths

        foreach ($p in $profiles) {
            $userTempPath = Join-Path -Path $p -ChildPath "AppData\Local\Temp"
            $totalUserTempGB += (Get-FolderSizeGB -Path $userTempPath -FileCap $MaxFilesToMeasure)
            if ($totalUserTempGB -ge $UserTempThresholdGB) { break } # early exit to reduce work
        }

        $totalUserTempGB = [math]::Round($totalUserTempGB, 2)
        Write-LogEntry -Value "Combined user Temp size (approx): $totalUserTempGB GB (Threshold=$UserTempThresholdGB GB)" -Severity 1

        if ($totalUserTempGB -ge $UserTempThresholdGB) {
            $TriggerRemediation = $true
            $TriggerReasons.Add("UserTempCombinedSize>=$UserTempThresholdGB GB (Current=$totalUserTempGB GB)")
        }
    }

    # Output / exit handling for Intune PR
    if ($null -ne $ErrorMessage) {
        Write-Output $ErrorMessage
        Write-LogEntry -Value "[$ProactiveRemediationName-Detection] - Completed (Error -> Exit 1 to be safe)" -Severity 3
        exit 1
    }

    if ($TriggerRemediation -eq $true) {
        # Increment execution history count when remediation is triggered
        $ExecutionHistoryCount++
        Set-ItemProperty -Path $ExecutionHistoryRegistryPath -Name $ExecutionHistoryRegistryValue -Value $ExecutionHistoryCount -ErrorAction "SilentlyContinue"

        $reasonText = ($TriggerReasons -join "; ")
        Write-LogEntry -Value "Triggering remediation. Reasons: $reasonText" -Severity 1
        Write-LogEntry -Value "[$ProactiveRemediationName-Detection] - Completed" -Severity 1

        Write-Output "Remediation required. Reasons: $reasonText"
        exit 1
    }
    else {
        Write-LogEntry -Value "No remediation required." -Severity 1
        Write-LogEntry -Value "[$ProactiveRemediationName-Detection] - Completed" -Severity 1

        Write-Output "Compliant. Free space: $FreeDiskSpace GB. Old SCCM items: $($sccm.OldItemCount). Old dumps: $($dumps.OldDumpCount)."
        exit 0
    }
}