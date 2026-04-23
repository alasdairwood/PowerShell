
<#
.SYNOPSIS
    Proactive Remediation detection script for cleaning up the local harddrive.

.DESCRIPTION
    Detection script for Endpoint Analytics Proactive Remediations used by the Disk Cleanup solution.
    Triggers remediation when:
      - Free space on system drive is below a defined threshold, OR
      - SCCM ccmcache contains content older than a defined retention period

.EXAMPLE
    .\Detection.ps1

.NOTES
    FileName:    Detection.ps1
    Author:      Nickolaj Andersen (original)
    Updated:     2026-04-23 (adapted to include SCCM cache retention trigger and fixed logic)
#>

Begin {
    # Proactive Remediation name
    $ProactiveRemediationName = "DiskCleanup"

    # Company name for execution history registry path (change to suit your org)
    $CompanyName = "NHSLanarkshire"   # e.g. "NHSLanarkshire"

    # Thresholds / toggles
    $MinimumFreeSpaceGB = 64
    $SCCMCacheRetentionDays = 7

    # If you want to keep the original behaviour (skip remediation on Windows 11), set to $true
    $SkipWindows11 = $false

    # Execution limit to avoid repeated runs forever (kept from your original design)
    $MaxExecutions = 100

    # Enable TLS 1.2 (kept for consistency; no module download in this version)
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

Process {

    function Write-LogEntry {
        param (
            [parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Value,
            [parameter(Mandatory = $true)][ValidateSet("1","2","3")][string]$Severity,
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
                New-Item -ItemType Directory -Path $LogFolderPath -Force -ErrorAction Stop | Out-Null
            }
        }
        catch {
            Write-Warning -Message "Failed to create log folder. $($_.Exception.Message)"
        }

        $Bias = (Get-CimInstance -ClassName Win32_TimeZone -ErrorAction SilentlyContinue).Bias
        if ($null -eq $Bias) { $Bias = 0 }

        $Time = -join @((Get-Date -Format "HH:mm:ss.fff"), "+", $Bias)
        $Date = (Get-Date -Format "MM-dd-yyyy")
        $Context = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

        $LogText = "<![LOG[$Value]LOG]!><time=""$Time"" date=""$Date"" component=""$ProactiveRemediationName"" context=""$Context"" type=""$Severity"" thread=""$PID"" file="""">"

        try {
            Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Stop
        }
        catch {
            Write-Warning -Message "Unable to append log entry. $($_.Exception.Message)"
        }
    }

    function Get-WindowsVersionInfo {
        try {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            $build = [int]$os.BuildNumber

            $version = "Unknown"
            if ($build -ge 19000 -and $build -le 19045) { $version = "Windows 10" }
            elseif ($build -ge 22000) { $version = "Windows 11" }

            return [PSCustomObject]@{
                BuildNumber = $build
                Version     = $version
            }
        }
        catch {
            Write-LogEntry -Value "Failed to retrieve Windows build/version. Error: $($_.Exception.Message)" -Severity 3
            return $null
        }
    }

    function Get-FreeSpaceGB {
        param([string]$Drive = $env:SystemDrive)

        try {
            $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$Drive'" -ErrorAction Stop
            return [math]::Round(($disk.FreeSpace / 1GB), 0)
        }
        catch {
            Write-LogEntry -Value "Failed to retrieve free space for drive '$Drive'. Error: $($_.Exception.Message)" -Severity 3
            return $null
        }
    }

    function Test-OldSCCMCacheContent {
        param(
            [int]$RetentionDays = 7
        )

        $result = [PSCustomObject]@{
            ClientInstalled = $false
            CachePath       = $null
            OldItemCount    = 0
            HasOldContent   = $false
        }

        $svc = Get-Service -Name "CcmExec" -ErrorAction SilentlyContinue
        if ($null -eq $svc) {
            return $result
        }

        $result.ClientInstalled = $true
        $cachePath = Join-Path -Path $env:WINDIR -ChildPath "ccmcache"
        $result.CachePath = $cachePath

        if (-not (Test-Path -Path $cachePath)) {
            return $result
        }

        $cutoff = (Get-Date).AddDays(-$RetentionDays)

        # Fast check: folder LastWriteTime is enough to determine "old enough to remove" for detection
        try {
            $items = Get-ChildItem -Path $cachePath -Force -ErrorAction SilentlyContinue
            if ($null -eq $items) { return $result }

            $old = $items | Where-Object { $_.LastWriteTime -lt $cutoff }
            $count = ($old | Measure-Object).Count

            $result.OldItemCount = $count
            $result.HasOldContent = ($count -gt 0)
        }
        catch {
            Write-LogEntry -Value "Failed to inspect SCCM cache folder '$cachePath'. Error: $($_.Exception.Message)" -Severity 2
        }

        return $result
    }

    # ----------------------------
    # Start detection
    # ----------------------------
    Write-LogEntry -Value "[$ProactiveRemediationName-Detection] - Initializing" -Severity 1

    $ErrorMessage = $null
    $TriggerRemediation = $false

    # Execution history key/value
    $ExecutionHistoryRegistryPath  = "HKLM:\SOFTWARE\$CompanyName\ProactiveRemediations\$ProactiveRemediationName"
    $ExecutionHistoryRegistryValue = "Count"

    # Ensure registry key exists
    if (-not (Test-Path -Path $ExecutionHistoryRegistryPath)) {
        try {
            New-Item -Path $ExecutionHistoryRegistryPath -Force -ErrorAction Stop | Out-Null
        }
        catch {
            $ErrorMessage = "Failed to create registry key '$ExecutionHistoryRegistryPath'. Error: $($_.Exception.Message)"
            Write-LogEntry -Value $ErrorMessage -Severity 3
        }
    }

    # Ensure registry value exists
    if ($null -eq (Get-ItemProperty -Path $ExecutionHistoryRegistryPath -Name $ExecutionHistoryRegistryValue -ErrorAction SilentlyContinue)) {
        try {
            New-ItemProperty -Path $ExecutionHistoryRegistryPath -Name $ExecutionHistoryRegistryValue -Value 0 -PropertyType String -Force -ErrorAction Stop | Out-Null
        }
        catch {
            $ErrorMessage = "Failed to create registry value '$ExecutionHistoryRegistryValue' in '$ExecutionHistoryRegistryPath'. Error: $($_.Exception.Message)"
            Write-LogEntry -Value $ErrorMessage -Severity 3
        }
    }

    # Read execution count
    $ExecutionHistoryCount = [int](Get-ItemProperty -Path $ExecutionHistoryRegistryPath -Name $ExecutionHistoryRegistryValue -ErrorAction SilentlyContinue).$ExecutionHistoryRegistryValue
    Write-LogEntry -Value "Execution history count is: $ExecutionHistoryCount (Max allowed: $MaxExecutions)" -Severity 1

    if ($ExecutionHistoryCount -ge $MaxExecutions) {
        Write-LogEntry -Value "Maximum number of allowed executions reached ($MaxExecutions). Exiting detection." -Severity 1
        Write-Output "Maximum number of allowed executions reached"
        exit 0
    }

    # OS version check (optional skip on Win11)
    $osInfo = Get-WindowsVersionInfo
    if ($null -ne $osInfo) {
        Write-LogEntry -Value "Detected OS: $($osInfo.Version) (Build: $($osInfo.BuildNumber))" -Severity 1

        if ($SkipWindows11 -eq $true -and $osInfo.Version -eq "Windows 11") {
            Write-LogEntry -Value "SkipWindows11 is enabled and device is Windows 11. No remediation will be triggered." -Severity 1
            Write-Output "No remediation required (Windows 11 skipped by policy)"
            exit 0
        }
    }

    # Free space trigger
    $FreeDiskSpaceGB = Get-FreeSpaceGB
    if ($null -ne $FreeDiskSpaceGB) {
        Write-LogEntry -Value "Free disk space on system drive is: $FreeDiskSpaceGB GB" -Severity 1
        if ($FreeDiskSpaceGB -lt $MinimumFreeSpaceGB) {
            Write-LogEntry -Value "Free disk space is below threshold ($MinimumFreeSpaceGB GB). Remediation required." -Severity 1
            $TriggerRemediation = $true
        }
    }
    else {
        $ErrorMessage = "Failed to determine free disk space."
        Write-LogEntry -Value $ErrorMessage -Severity 3
    }

    # SCCM cache retention trigger (7 days)
    $sccmCacheCheck = Test-OldSCCMCacheContent -RetentionDays $SCCMCacheRetentionDays
    if ($sccmCacheCheck.ClientInstalled -eq $true) {
        Write-LogEntry -Value "SCCM client detected. Cache path: $($sccmCacheCheck.CachePath). Old items (> $SCCMCacheRetentionDays days): $($sccmCacheCheck.OldItemCount)" -Severity 1

        if ($sccmCacheCheck.HasOldContent -eq $true) {
            Write-LogEntry -Value "SCCM cache contains content older than $SCCMCacheRetentionDays days. Remediation required." -Severity 1
            $TriggerRemediation = $true
        }
    }
    else {
        Write-LogEntry -Value "SCCM client not detected; SCCM cache retention trigger skipped." -Severity 1
    }

    # Output + exit codes for Intune PR:
    # exit 1 => non-compliant => remediation runs
    # exit 0 => compliant => no remediation

    if ($null -ne $ErrorMessage) {
        Write-Output $ErrorMessage
        Write-LogEntry -Value "[$ProactiveRemediationName-Detection] - Completed (Error)" -Severity 3
        exit 1
    }

    if ($TriggerRemediation -eq $true) {
        # Increment execution count when we intentionally trigger remediation
        $ExecutionHistoryCount++
        Set-ItemProperty -Path $ExecutionHistoryRegistryPath -Name $ExecutionHistoryRegistryValue -Value $ExecutionHistoryCount -ErrorAction SilentlyContinue

        Write-LogEntry -Value "Triggering remediation script (Exit 1). New execution count: $ExecutionHistoryCount" -Severity 1
        Write-LogEntry -Value "[$ProactiveRemediationName-Detection] - Completed" -Severity 1

        Write-Output "Remediation required. Free space: $FreeDiskSpaceGB GB. Old SCCM cache items: $($sccmCacheCheck.OldItemCount)."
        exit 1
    }
    else {
        Write-LogEntry -Value "No remediation required (Exit 0)." -Severity 1
        Write-LogEntry -Value "[$ProactiveRemediationName-Detection] - Completed" -Severity 1

        Write-Output "Compliant. Free space: $FreeDiskSpaceGB GB. Old SCCM cache items: $($sccmCacheCheck.OldItemCount)."
        exit 0
    }
}
