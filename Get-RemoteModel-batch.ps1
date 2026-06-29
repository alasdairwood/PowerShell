<#
.SYNOPSIS
Get-RemoteModelReg.ps1 - Fast parallel remote device audit (PS 5.1)

.DESCRIPTION
Queries one or more devices in parallel to retrieve:
- Model
- Logged-on user
- OS (friendly release e.g. Win11 24H2)
- Windows Update targeting state
- Connection method (WSMan/DCOM)
- IPv4 address
- Hostname / reverse DNS mismatch detection (highlighted)

Supports:
- Single or multiple devices
- File-based input
- PassThru for filtering/export

.EXAMPLES

# Single device
.\Get-RemoteModelReg.ps1 -ComputerName D06856

# Multiple devices
.\Get-RemoteModelReg.ps1 -ComputerName D06856,D14516

# From file
.\Get-RemoteModelReg.ps1 -ComputerList devices.txt

# Fast scan (skip ICMP)
.\Get-RemoteModelReg.ps1 -ComputerList devices.txt -NoPing

# Hide offline devices
.\Get-RemoteModelReg.ps1 -ComputerList devices.txt -HideOffline

# Show reboot only devices
.\Get-RemoteModelReg.ps1 -ComputerList devices.txt -RebootOnly

# Show devices with a minimum uptime and require a reboot
.\Get-RemoteModelReg.ps1 -ComputerList devices.txt -RebootOnly -MinUptime 7

# Output objects for filtering
.\Get-RemoteModelReg.ps1 -ComputerList devices.txt -PassThru

# Find WU failures
.\Get-RemoteModelReg.ps1 -ComputerList devices.txt -PassThru | Where-Object { $_.WU_Compliant -eq $false }

# Find unsupported OS
.\Get-RemoteModelReg.ps1 -ComputerList devices.txt -PassThru | Where-Object { $_.OSFlag -eq "UNSUPPORTED" }

# Find reverse DNS mismatches
.\Get-RemoteModelReg.ps1 -ComputerList devices.txt -PassThru | Where-Object { $_.ReverseDnsMatch -eq $false }

# Export results
.\Get-RemoteModelReg.ps1 -ComputerList devices.txt -PassThru | Export-Csv results.csv -NoTypeInformation

# Pipeline input
"PC1","PC2","PC3" | .\Get-RemoteModelReg.ps1

#>

[CmdletBinding()]
param(
    [string]$ComputerList,
    [string[]]$ComputerName,
    [int]$PrecheckBatchSize = 100,
    [int]$PrecheckThrottle = 40,
    [int]$ThrottleLimit = 20,
    [int]$ProgressIntervalMs = 250,
    [switch]$NoPing,
    [switch]$PassThru,
    [switch]$HideOffline,
    
    [switch]$RebootOnly,

    [Alias("MinUptime")]
    [int]$MinUptimeDays = 0,

    [switch]$NoUserOnly,
 
    [string]$ExportCsv,
    [switch]$ExportOnly,

    [switch]$Help
)

# --- Help / Usage ---
if ($Help -or $args -contains '/?' -or $args -contains '-?') {

    Write-Host ''
    Write-Host 'Get-RemoteModelReg.ps1 - Remote device audit (parallel)' -ForegroundColor Cyan
    Write-Host ''

    Write-Host 'Input options:' -ForegroundColor Yellow
    Write-Host '  -ComputerName <name[,name]>   One or more computer names'
    Write-Host '  -ComputerList <file>          Path to file with device names'
    Write-Host ''
    
    Write-Host 'Execution options:' -ForegroundColor Yellow
    Write-Host '  -ThrottleLimit N              Max parallel threads (default: 20)'
    Write-Host '  -NoPing                       Skip ICMP pre-check'
    Write-Host '  -HideOffline                  Suppress offline device output'
    Write-Host '  -PassThru                     Output objects for filtering/export'
    Write-Host ''

    Write-Host 'Filtering options:' -ForegroundColor Yellow
    Write-Host '  -RebootOnly                   Show only devices needing reboot'
    Write-Host '  -NoUserOnly                   Show only ONLINE devices with no logged-on user'
    Write-Host '  -MinUptime N                  Minimum uptime in days (used with -RebootOnly)'
    Write-Host ''

    Write-Host 'Output details:' -ForegroundColor Yellow
    Write-Host '  Shows: Host | IP | OS | WU | BOOT | UP | RB | Model | User'
    Write-Host '  Win11 devices are highlighted in Green'
    Write-Host ''

    Write-Host 'Examples:' -ForegroundColor Yellow
    Write-Host '  .\Get-RemoteModelReg.ps1 -ComputerName D06947'
    Write-Host '  .\Get-RemoteModelReg.ps1 -ComputerList devices.txt'
    Write-Host '  .\Get-RemoteModelReg.ps1 -ComputerList devices.txt -HideOffline'
    Write-Host ''
    Write-Host '  .\Get-RemoteModelReg.ps1 -RebootOnly'
    Write-Host '  .\Get-RemoteModelReg.ps1 -NoUserOnly'
    Write-Host '  .\Get-RemoteModelReg.ps1 -RebootOnly -NoUserOnly'
    Write-Host '  .\Get-RemoteModelReg.ps1 -RebootOnly -MinUptime 7'
    Write-Host ''
    Write-Host '  .\Get-RemoteModelReg.ps1 -ComputerList devices.txt -ExportCsv results.csv'
    Write-Host '  .\Get-RemoteModelReg.ps1 -ComputerList devices.txt -ExportCsv results.csv -ExportOnly'
    Write-Host '  .\Get-RemoteModelReg.ps1 -RebootOnly -NoUserOnly -MinUptime 7 -ExportCsv safe.csv -ExportOnly'
    Write-Host '  .\Get-RemoteModelReg.ps1 -ComputerList devices.txt -RebootOnly -ExportCsv reboot.csv'
    Write-Host '  .\Get-RemoteModelReg.ps1 -RebootOnly -NoUserOnly -MinUptime 7 -ExportCsv safe-reboots.csv'
    Write-Host '  .\Get-RemoteModelReg.ps1 -PassThru | Where-Object { -not $_.WU_Compliant } | Export-Csv fail.csv -NoTypeInformation'
    Write-Host ''

    return
}

# ------------------------------------------------------------
# Color Helper
# ------------------------------------------------------------
function Get-RowColor {
    param(
        [Parameter(Mandatory)]
        $r
    )

    $color = 'Cyan'
    try {
        # ✅ Highest priority
        if ($r.OSDisplay -match '^Win\s*11') { return 'Green' }
        # ✅ Memory pressure (early priority)
        if ($r.TotalRAMGB -ne $null -and $r.TotalRAMGB -lt 6) { return 'Red' }
        # ✅ Disk pressure (early priority)
        if ($r.DriveSizeGB -ne $null -and $r.DriveSizeGB -lt 128) { return 'Red' }
        if ($r.DriveUsedPct -ge 98) { return 'Red' }
        if ($r.DriveUsedPct -ge 90) { return 'Yellow' }

        # ✅ Existing rules
        if ($r.NameMatch -eq $false) { $color = 'DarkYellow' }
        if ($r.ReverseDnsMatch -eq $false) { $color = 'Red' }
        if ($r.OSFlag -eq 'UNSUPPORTED') { $color = 'DarkYellow' }
        if ($r.OSFlag -eq 'UNKNOWN') { $color = 'Magenta' }
        # ✅ NoUser / reboot logic
        if ($r.LoggedOnUser -eq 'NoUser') { $color = 'DarkGray' }
        if ($r.LoggedOnUser -eq 'NoUser' -and $r.NeedsReboot) { $color = 'White' }
    }
    catch { $color = 'Gray' }

    if (-not $color) { $color = 'Gray' }
    return $color

}

# ------------------------------------------------------------
# Input handling (supports both list + names; merges)
# ------------------------------------------------------------
$Computers = @()

if ($ComputerName) {
    $Computers += $ComputerName |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ }
}

if ($ComputerList) {
    $Computers += Get-Content -Path $ComputerList -ErrorAction Stop |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ -and $_ -notmatch '^\s*#' }
}

if (-not $Computers -or $Computers.Count -eq 0) {
    throw "Provide -ComputerName or -ComputerList"
}

$Computers = $Computers | Sort-Object -Unique

# ------------------------------------------------------------
# Helpers (collector-safe)
# ------------------------------------------------------------
function Coalesce {
    param([object]$Value, [string]$Default = "-")
    if ($null -eq $Value) { return $Default }
    $s = [string]$Value
    if ([string]::IsNullOrWhiteSpace($s)) { return $Default }
    return $s.Trim()
}

# ------------------------------------------------------------
# Batching Helpers
# ------------------------------------------------------------
function Split-IntoBatches {
    param(
        [Parameter(Mandatory)]
        [object[]]$InputObject,

        [Parameter(Mandatory)]
        [int]$BatchSize
    )

    $batches = @()

    for ($i = 0; $i -lt $InputObject.Count; $i += $BatchSize) {
        $end = $i + $BatchSize - 1
        if ($end -ge $InputObject.Count) {
            $end = $InputObject.Count - 1
        }

        $batches += , @($InputObject[$i..$end])
    }

    return $batches
}

function Invoke-FastPrecheckBatch {
    param(
        [string[]]$Computers,
        [int]$Throttle = 40
    )

    $results = @()

    $pool = [runspacefactory]::CreateRunspacePool(1, $Throttle)
    $pool.Open()

    $jobs = @()

    foreach ($c in $Computers) {
        $ps = [powershell]::Create()
        $ps.RunspacePool = $pool

        $script = {
            param($ComputerName)

            $reachable = $false
            $method = "None"

            try {
                foreach ($port in @(5985)) {
                    try {
                        $client = New-Object System.Net.Sockets.TcpClient
                        $iar = $client.BeginConnect($ComputerName, $port, $null, $null)

                        if ($iar.AsyncWaitHandle.WaitOne(75, $false)) {
                            $client.EndConnect($iar) | Out-Null
                            $reachable = $true
                            $method = "TCP:$port"
                            $client.Close()
                            break
                        }

                        $client.Close()
                    }
                    catch {}
                }

                if (-not $reachable) {
                    if (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction SilentlyContinue) {
                        $reachable = $true
                        $method = "ICMP"
                    }
                }
            }
            catch {}

            [pscustomobject]@{
                ComputerName = $ComputerName
                Reachable    = $reachable
                Precheck     = $method
                DriveSizeGB  = $null
            }
        }

        $null = $ps.AddScript($script).AddArgument($c)

        $jobs += [pscustomobject]@{
            Computer = $c
            PS       = $ps
            Handle   = $ps.BeginInvoke()
        }
    }

    foreach ($j in $jobs) {
        try {
            $result = $j.PS.EndInvoke($j.Handle)
            if ($result) { $results += $result }
        }
        catch {
            $results += [pscustomobject]@{
                ComputerName = $j.Computer
                Reachable    = $false
                Precheck     = "Error"
            }
        }
        finally {
            try { $j.PS.Dispose() } catch {}
        }
    }

    $pool.Close()
    $pool.Dispose()

    return $results
}



# ------------------------------------------------------------
# Cleanup helpers
# ------------------------------------------------------------
$script:CleanedUp = $false

function Invoke-Cleanup {
    param(
        [System.Collections.Generic.List[object]]$Jobs,
        [System.Management.Automation.Runspaces.RunspacePool]$Pool
    )

    if ($script:CleanedUp) { return }
    $script:CleanedUp = $true

    if ($Jobs) {
        foreach ($job in $Jobs) {
            try {
                if ($job.PowerShell) {
                    try {
                        if ($job.Handle -and -not $job.Handle.IsCompleted) { $job.PowerShell.Stop() }
                    }
                    catch {}
                    try { $job.PowerShell.Dispose() } catch {}
                }
            }
            catch {}
        }
        try { $Jobs.Clear() } catch {}
    }

    if ($Pool) {
        try { $Pool.Close() } catch {}
        try { $Pool.Dispose() } catch {}
    }
}

# ------------------------------------------------------------
# Worker (runspace-safe: ALL helpers inside)
# ------------------------------------------------------------
$Worker = {
    param(
        [string]$Computer,
        [bool]$NoPingCheck
    )

    function Get-ShortName {
        param([string]$Name)
        if ([string]::IsNullOrWhiteSpace($Name)) { return $null }
        $Name = $Name.Trim()
        if ($Name.Contains('.')) { return $Name.Split('.')[0] }
        return $Name
    }

    function Resolve-WindowsRelease {
        param([string]$Caption, [string]$BuildNumber)

        $build = 0
        [void][int]::TryParse([string]$BuildNumber, [ref]$build)

        $win10 = @{
            18362 = "Win10 1903"
            18363 = "Win10 1909"
            19041 = "Win10 2004"
            19042 = "Win10 20H2"
            19043 = "Win10 21H1"
            19044 = "Win10 21H2"
            19045 = "Win10 22H2"
        }

        $win11 = @{
            22000 = "Win11 21H2"
            22621 = "Win11 22H2"
            22631 = "Win11 23H2"
            26100 = "Win11 24H2"
            26200 = "Win11 25H2"
        }

        $server = @{
            17763 = "Server 2019"
            20348 = "Server 2022"
            26100 = "Server 2025"
        }

        $capLower = ([string]$Caption).ToLowerInvariant()

        if ($capLower -match 'windows 11') {
            if ($win11.ContainsKey($build)) { return $win11[$build] }
            return ("Win11 Build {0}" -f $BuildNumber)
        }
        elseif ($capLower -match 'windows 10') {
            if ($win10.ContainsKey($build)) { return $win10[$build] }
            return ("Win10 Build {0}" -f $BuildNumber)
        }
        elseif ($capLower -match 'server') {
            if ($server.ContainsKey($build)) { return $server[$build] }
            return ("Server Build {0}" -f $BuildNumber)
        }

        if ($build -gt 0) { return ("Build {0}" -f $BuildNumber) }
        return "Unknown"
    }

    function Test-TcpPortsParallelFast {
        param(
            [Parameter(Mandatory)][string]$HostName,
            [Parameter(Mandatory)][int[]]$Ports,
            [int]$TimeoutMs = 350
        )

        $clients = New-Object System.Collections.Generic.List[object]
        $entries = New-Object System.Collections.Generic.List[object]
        $handles = New-Object System.Collections.Generic.List[System.Threading.WaitHandle]

        try {
            foreach ($p in $Ports) {
                $client = New-Object System.Net.Sockets.TcpClient
                $iar = $client.BeginConnect($HostName, $p, $null, $null)

                $null = $clients.Add($client)
                $null = $entries.Add([pscustomobject]@{ Client = $client; Async = $iar })
                $null = $handles.Add($iar.AsyncWaitHandle)
            }

            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $remaining = $TimeoutMs

            while ($handles.Count -gt 0 -and $remaining -gt 0) {
                $idx = [System.Threading.WaitHandle]::WaitAny($handles.ToArray(), $remaining, $false)
                if ($idx -eq [System.Threading.WaitHandle]::WaitTimeout) { break }

                $entry = $entries[$idx]

                try { $handles[$idx].Close() } catch {}
                $handles.RemoveAt($idx)
                $entries.RemoveAt($idx)

                try {
                    $entry.Client.EndConnect($entry.Async) | Out-Null
                    return $true
                }
                catch {
                    # continue waiting for other ports
                }

                $remaining = $TimeoutMs - [int]$sw.ElapsedMilliseconds
            }

            return $false
        }
        finally {
            foreach ($entry in $entries) {
                try { if ($entry.Async -and $entry.Async.AsyncWaitHandle) { $entry.Async.AsyncWaitHandle.Close() } } catch {}
            }
            foreach ($handle in $handles) { try { $handle.Close() } catch {} }
            foreach ($client in $clients) { try { $client.Close() } catch {} }
        }
    }

    function New-ProtoSession {
        param(
            [string]$ComputerName,
            [ValidateSet("Wsman", "Dcom")]
            [string]$Protocol
        )
        $opt = New-CimSessionOption -Protocol $Protocol
        New-CimSession -ComputerName $ComputerName -SessionOption $opt -ErrorAction Stop
    }

    # StdRegProv helper (HKLM only, MI_UINT32 safe)
    function Get-RemoteRegistryStringValue {
        param(
            [Microsoft.Management.Infrastructure.CimSession]$Session,
            [string]$SubKey,
            [string]$ValueName
        )

        $args = @{
            hDefKey     = [uint32]2147483650
            sSubKeyName = $SubKey
            sValueName  = $ValueName
        }

        $out = Invoke-CimMethod -CimSession $Session `
            -Namespace "root\default" `
            -ClassName "StdRegProv" `
            -MethodName "GetStringValue" `
            -Arguments $args `
            -ErrorAction Stop

        if ($out -and $out.ReturnValue -eq 0) { return $out.sValue }
        return $null
    }

    function Get-RemoteRegistryMultiStringValue {
        param(
            [Microsoft.Management.Infrastructure.CimSession]$Session,
            [string]$SubKey,
            [string]$ValueName
        )

        $args = @{
            hDefKey     = [uint32]2147483650
            sSubKeyName = $SubKey
            sValueName  = $ValueName
        }

        $out = Invoke-CimMethod -CimSession $Session `
            -Namespace "root\default" `
            -ClassName "StdRegProv" `
            -MethodName "GetMultiStringValue" `
            -Arguments $args `
            -ErrorAction Stop

        if ($out -and $out.ReturnValue -eq 0) { return $out.sValue }
        return $null
    }

    function Remote-KeyExists {
        param(
            [Microsoft.Management.Infrastructure.CimSession]$Session,
            [string]$SubKey
        )

        # Check by enumerating parent key names (StdRegProv has no direct "KeyExists")
        $parent = Split-Path $SubKey -Parent
        $leaf = Split-Path $SubKey -Leaf

        if ([string]::IsNullOrWhiteSpace($parent) -or [string]::IsNullOrWhiteSpace($leaf)) { return $false }

        $args = @{
            hDefKey     = [uint32]2147483650
            sSubKeyName = $parent
        }

        $out = Invoke-CimMethod -CimSession $Session `
            -Namespace "root\default" `
            -ClassName "StdRegProv" `
            -MethodName "EnumKey" `
            -Arguments $args `
            -ErrorAction Stop

        if ($out -and $out.ReturnValue -eq 0 -and $out.sNames) {
            return ($out.sNames -contains $leaf)
        }

        return $false
    }

    function Get-ConnectedIPv4 {
        param([string]$HostName, [Microsoft.Management.Infrastructure.CimSession]$CimSession)

        # DNS first
        try {
            $ips = [System.Net.Dns]::GetHostAddresses($HostName) |
            Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork }
            if ($ips -and $ips.Count -gt 0) { return $ips[0].IPAddressToString }
        }
        catch {}

        # CIM fallback
        try {
            $nics = Get-CimInstance -CimSession $CimSession -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE" -ErrorAction Stop
            foreach ($nic in $nics) {
                if ($nic.IPAddress) {
                    $v4 = $nic.IPAddress | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' } | Select-Object -First 1
                    if ($v4) { return $v4 }
                }
            }
        }
        catch {}

        return $null
    }

    function Get-ReverseDnsShortName {
        param([string]$IPv4)
        try {
            $entry = [System.Net.Dns]::GetHostEntry($IPv4)
            if ($entry -and $entry.HostName) { return (Get-ShortName $entry.HostName) }
        }
        catch {}
        return $null
    }

    function Convert-DmtfToDateTimeSafe {
        param([string]$Dmtf)

        if ([string]::IsNullOrWhiteSpace($Dmtf)) { return $null }

        try {
            return [System.Management.ManagementDateTimeConverter]::ToDateTime($Dmtf)
        }
        catch {
            return $null
        }
    }

    function Convert-LastBootSafe {
        param([object]$Value)

        if ($null -eq $Value) { return $null }

        # If CIM already gave DateTime, keep it
        if ($Value -is [datetime]) { return $Value }

        $s = ([string]$Value)
        if ([string]::IsNullOrWhiteSpace($s)) { return $null }

        # Strip common invisible bidi marks that can break parsing/regex
        $s = $s.Trim() -replace "[\u200E\u200F\u202A-\u202E\u2066-\u2069]", ""

        # Normalise any non-ASCII digits to ASCII digits
        $chars = $s.ToCharArray()
        for ($i = 0; $i -lt $chars.Length; $i++) {
            $ch = $chars[$i]
            if ($ch -ge '0' -and $ch -le '9') { continue }

            $nv = [int][System.Globalization.CharUnicodeInfo]::GetDigitValue($ch)
            if ($nv -ge 0 -and $nv -le 9) {
                $chars[$i] = [char]([int][char]'0' + $nv)
            }
        }
        $s = -join $chars

        # Expect: "dd/MM/yyyy HH:mm:ss" (seconds optional)
        $parts = $s -split '\s+'
        if ($parts.Count -lt 2) { return $null }

        $datePart = $parts[0]
        $timePart = $parts[1]

        $dparts = $datePart -split '/'
        $tparts = $timePart -split ':'

        if ($dparts.Count -ne 3) { return $null }
        if ($tparts.Count -lt 2) { return $null }

        try {
            $day = [int]$dparts[0]
            $month = [int]$dparts[1]
            $year = [int]$dparts[2]

            $hour = [int]$tparts[0]
            $min = [int]$tparts[1]
            $sec = if ($tparts.Count -ge 3) { [int]$tparts[2] } else { 0 }

            # UK-safe heuristic: if month is impossible, swap day/month
            if ($month -gt 12 -and $day -le 12) {
                $tmp = $day
                $day = $month
                $month = $tmp
            }

            return (New-Object DateTime($year, $month, $day, $hour, $min, $sec))
        }
        catch {
            return $null
        }
    }

    function Get-PendingReboot {
        param(
            [Microsoft.Management.Infrastructure.CimSession]$Session,
            [switch]$DebugMode
        )

        $reasons = @()
        $debugLog = @()
        $cosmeticPFRO = $false

        # -------------------------------
        # Windows Update
        # -------------------------------
        try {
            if (Remote-KeyExists -Session $Session -SubKey "SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
                $reasons += "Windows Update"
                if ($DebugMode) { $debugLog += "[WU] RebootRequired key present" }
            }
            else {
                if ($DebugMode) { $debugLog += "[WU] No reboot required" }
            }
        }
        catch {
            if ($DebugMode) { $debugLog += "[WU] Error checking RebootRequired: $($_.Exception.Message)" }
        }

        # -------------------------------
        # Component Servicing
        # -------------------------------
        try {
            if (Remote-KeyExists -Session $Session -SubKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
                $reasons += "Component Servicing"
                if ($DebugMode) { $debugLog += "[CBS] RebootPending key present" }
            }
            else {
                if ($DebugMode) { $debugLog += "[CBS] No reboot pending" }
            }
        }
        catch {
            if ($DebugMode) { $debugLog += "[CBS] Error checking RebootPending: $($_.Exception.Message)" }
        }

        # -------------------------------
        # Pending File Rename Operations
        # -------------------------------
        $filtered = @()

        try {
            $pfroEntries = Get-RemoteRegistryMultiStringValue `
                -Session $Session `
                -SubKey "SYSTEM\CurrentControlSet\Control\Session Manager" `
                -ValueName "PendingFileRenameOperations"

            if ($pfroEntries -and $pfroEntries.Count -gt 0) {

                if ($DebugMode) { $debugLog += "[PFRO] Raw entries detected: $($pfroEntries.Count)" }

                foreach ($entry in $pfroEntries) {

                    $clean = $entry
                    if ($null -ne $clean) { $clean = $clean.Trim() }

                    # Ignore empty
                    if (-not $clean) {
                        if ($DebugMode) { $debugLog += "[PFRO] Ignored empty entry" }
                        continue
                    }

                    if ($DebugMode) { $debugLog += "[PFRO] Raw Entry: $clean" }

                    # Normalise
                    $clean = $clean -replace '^\*\d+', ''
                    $clean = $clean -replace '^\\\?\?\\', ''

                    if ($DebugMode) { $debugLog += "[PFRO] Normalised: $clean" }

                    # Ignore SCCM temp files
                    if ($clean -match '^C:\\Windows\\Temp\\CCM.*\.tmp$') {
                        if ($DebugMode) { $debugLog += "[PFRO] Ignored CCM temp entry" }
                    }
                    else {
                        $filtered += $clean
                    }
                }

                if ($filtered.Count -gt 0) {
                    $reasons += ("Pending File Rename ({0} item(s))" -f $filtered.Count)
                    if ($DebugMode) { $debugLog += "[PFRO] Actionable entries count: $($filtered.Count)" }
                }
                else {
                    $cosmeticPFRO = $true
                    if ($DebugMode) { $debugLog += "[PFRO] Only benign CCM entries detected (ignored)" }
                }
            }
            else {
                if ($DebugMode) { $debugLog += "[PFRO] No entries present" }
            }
        }
        catch {
            if ($DebugMode) { $debugLog += "[PFRO] Error reading PFRO: $($_.Exception.Message)" }
        }

        # -------------------------------
        # Return structured result
        # -------------------------------
        return [pscustomobject]@{
            RebootRequired = ($reasons.Count -gt 0)
            Reasons        = ($reasons -join ", ")
            CosmeticPFRO   = $cosmeticPFRO
            DebugLog       = if ($DebugMode) { $debugLog } else { $null }
        }
    }

    # ------------------------------------------------------------
    # Result object
    # ------------------------------------------------------------
    $r = [ordered]@{
        ComputerName       = $Computer
        ConnectedHostName  = $null
        ConnectedIP        = $null

        ReverseDnsHostName = $null
        ReverseDnsMatch    = $null

        NameMatch          = $null
        Online             = $false
        CimProtocolUsed    = $null

        Model              = $null
        LoggedOnUser       = $null
        SessionState       = $null

        OSRelease          = $null
        OSFlag             = $null
        OSDisplay          = $null

        LastBootRaw        = $null
        LastBootTime       = $null

        NeedsReboot        = $null   # $true/$false/$null
        RebootReason       = $null   # e.g. CBS+WU
        
        CosmeticPFRO       = $null
        RebootDebugLog     = $null

        WU_Compliant       = $null
        Error              = $null


        TotalRAMGB         = $null
        FreeRAMGB          = $null
        RAMUsedPct         = $null

        DriveSizeGB        = $null
        DriveUsedPct       = $null
    }

    # ------------------------------------------------------------
    # Fast pre-check
    # ------------------------------------------------------------
    if (-not $NoPingCheck) {
        $reachable = Test-TcpPortsParallelFast -HostName $Computer -Ports @(5985, 135) -TimeoutMs 350
        if (-not $reachable) {
            if (-not (Test-Connection -ComputerName $Computer -Quiet -Count 1 -ErrorAction SilentlyContinue)) {
                $r.Error = "Offline"
                return [pscustomobject]$r
            }
        }
    }

    # ------------------------------------------------------------
    # CIM connect / query
    # ------------------------------------------------------------
    $cimSession = $null
    $lastError = $null

    foreach ($proto in @("Wsman", "Dcom")) {
        try {
            $cimSession = New-ProtoSession -ComputerName $Computer -Protocol $proto
            $r.CimProtocolUsed = if ($proto -eq "Wsman") { "WSMan" } else { "DCOM" }

            $sys = Get-CimInstance -CimSession $cimSession -ClassName Win32_ComputerSystem -ErrorAction Stop
            $r.Model = $sys.Model
            $r.LoggedOnUser = $sys.UserName

            if ([string]::IsNullOrWhiteSpace($r.LoggedOnUser)) {
                try {
                    $quser = quser /server:$Computer 2>$null

                    if ($quser -and $quser.Count -gt 1) {

                        foreach ($line in ($quser | Select-Object -Skip 1)) {

                            if (-not [string]::IsNullOrWhiteSpace($line)) {

                                # Normalize spaces
                                $clean = ($line -replace '^\s+', '') -replace '\s{2,}', '|'
                                $parts = $clean -split '\|'

                                if ($parts.Count -ge 4) {

                                    $username = $parts[0].Trim()
                                    $session = $parts[1].Trim()
                                    $state = $parts[2].Trim()

                                    # ✅ ONLY take active console session
                                    if ($state -eq "Active" -and $session -eq "console") {

                                        if ($username -notmatch '^(USERNAME|>$)') {
                                            $r.LoggedOnUser = $username
                                            break
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                catch {
                    # leave LoggedOnUser blank if quser fails
                }
            }

            if ([string]::IsNullOrWhiteSpace($r.LoggedOnUser)) {
                $r.LoggedOnUser = "NoUser"
            }

            $r.ConnectedHostName = $sys.Name

            $requestedShort = Get-ShortName $Computer
            $connectedShort = Get-ShortName $sys.Name
            if ($requestedShort -and $connectedShort) {
                $r.NameMatch = ($requestedShort.ToUpperInvariant() -eq $connectedShort.ToUpperInvariant())
            }

            # IPv4 + reverse DNS
            $r.ConnectedIP = Get-ConnectedIPv4 -HostName $sys.Name -CimSession $cimSession
            if ($r.ConnectedIP) {
                $rdns = Get-ReverseDnsShortName -IPv4 $r.ConnectedIP
                $r.ReverseDnsHostName = $rdns
                if ($rdns -and $connectedShort) {
                    $r.ReverseDnsMatch = ($rdns.ToUpperInvariant() -eq $connectedShort.ToUpperInvariant())
                }
            }

            # OS + last boot time
            $os = Get-CimInstance -CimSession $cimSession -ClassName Win32_OperatingSystem -ErrorAction Stop

            # Detect Device Memory 
            try {
                $cs = Get-CimInstance -CimSession $cimSession -ClassName Win32_ComputerSystem
                $os = Get-CimInstance -CimSession $cimSession -ClassName Win32_OperatingSystem

                if ($cs.TotalPhysicalMemory -and $os.FreePhysicalMemory) {
                    $totalGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 0)
                    $freeGB = [math]::Round(($os.FreePhysicalMemory * 1KB) / 1GB, 0)

                    $usedPct = 0
                    if ($totalGB -gt 0) { $usedPct = [math]::Round((($totalGB - $freeGB) / $totalGB) * 100, 0) }

                    $r.TotalRAMGB = $totalGB
                    $r.RAMUsedPct = $usedPct
                }

            }
            catch {}

            $r.PowerState = $null

            try {
                $bat = Get-CimInstance -CimSession $cimSession -ClassName Win32_Battery -ErrorAction Stop

                if ($bat) {
                    if ($bat.BatteryStatus -eq 1) { $r.PowerState = 'Battery' }
                    if ($bat.BatteryStatus -eq 2) { $r.PowerState = 'AC' }
                }
                else {
                    $r.PowerState = 'AC'   # desktop assumption
                }

            }
            catch {}

            # --- Detect locked session (heuristic) ---
            try {
                $logonUI = Get-CimInstance -CimSession $cimSession `
                    -ClassName Win32_Process `
                    -Filter "Name='LogonUI.exe'" `
                    -ErrorAction Stop

                if ($logonUI) {
                    $r.SessionState = "Locked"
                }
                else {
                    $r.SessionState = "Unlocked"
                }
            }
            catch {
                $r.SessionState = $null
            }

            # --- Drive size (total of all fixed disks) ---
            try {
                $disk = Get-CimInstance -CimSession $cimSession -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"

                if ($disk.Size -and $disk.FreeSpace) {
                    $totalGB = [math]::Round($disk.Size / 1GB, 0)
                    $freeGB = [math]::Round($disk.FreeSpace / 1GB, 0)

                    $usedPct = 0
                    if ($totalGB -gt 0) { $usedPct = [math]::Round((($totalGB - $freeGB) / $totalGB) * 100, 0) }

                    $r.DriveSizeGB = $totalGB
                    $r.DriveUsedPct = $usedPct
                }
            }
            catch {}          

            # --- Boot time handling ---

            $r.LastBootRaw = $os.LastBootUpTime
            $r.LastBootTime = $null
            $r.BootParseError = $null
            $r.BootParseStage = "start"

            # ✅ DIRECT assignment (no $dt variable)
            $r.LastBootTime = Convert-LastBootSafe -Value $os.LastBootUpTime

            # ✅ Debug (safe)
            $r.DebugBoot = $r.LastBootTime

            # ✅ Stage must reflect ACTUAL stored value
            if ($r.LastBootTime -is [datetime]) {
                $r.BootParseStage = "ok"
            }
            else {
                $r.BootParseStage = "failed"
            }


            # Pending reboot flags (improved remote logic)
            $pr = Get-PendingReboot -Session $cimSession

            $r.NeedsReboot = $pr.RebootRequired
            $r.RebootReason = $pr.Reasons
            $r.CosmeticPFRO = $pr.CosmeticPFRO
            $r.RebootDebugLog = $pr.DebugLog


            $rel = Resolve-WindowsRelease $os.Caption $os.BuildNumber
            $r.OSRelease = $rel

            # OS support flag
            if ($rel -eq "Unknown" -or $rel -match ' Build ') {
                $r.OSFlag = "UNKNOWN"
                $r.OSDisplay = "Unknown?"
            }
            else {
                $supported = @("Win10 22H2", "Win11 23H2", "Win11 24H2", "Win11 25H2", "Server 2022", "Server 2025")
                if ($supported -contains $rel) {
                    $r.OSFlag = "OK"
                    $r.OSDisplay = $rel
                }
                else {
                    $r.OSFlag = "UNSUPPORTED"
                    $r.OSDisplay = "$rel*"
                }
            }

            # WU targeting compliance (WSMan -> DCOM retry)
            $baseKey = "SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState"
            $tpv = $null; $trv = $null; $wuOk = $true
            try {
                $tpv = Get-RemoteRegistryStringValue -Session $cimSession -SubKey $baseKey -ValueName "TargetProductVersion"
                $trv = Get-RemoteRegistryStringValue -Session $cimSession -SubKey $baseKey -ValueName "TargetReleaseVersion"
            }
            catch { $wuOk = $false }

            if (-not $wuOk -and $r.CimProtocolUsed -eq "WSMan") {
                $dcom = $null
                try {
                    $dcom = New-ProtoSession -ComputerName $Computer -Protocol Dcom
                    $tpv = Get-RemoteRegistryStringValue -Session $dcom -SubKey $baseKey -ValueName "TargetProductVersion"
                    $trv = Get-RemoteRegistryStringValue -Session $dcom -SubKey $baseKey -ValueName "TargetReleaseVersion"
                    $wuOk = $true
                }
                catch { $wuOk = $false }
                finally { if ($dcom) { try { Remove-CimSession -CimSession $dcom -ErrorAction SilentlyContinue } catch {} } }
            }

            if (-not $wuOk) {
                $r.WU_Compliant = $null
            }
            else {
                $r.WU_Compliant = -not ($tpv -eq "Windows 10" -or $trv -eq "22H2")
            }

            $r.Online = $true
            break
        }
        catch {
            $lastError = $_.Exception.Message
        }
        finally {
            if ($cimSession) {
                try { Remove-CimSession -CimSession $cimSession -ErrorAction SilentlyContinue } catch {}
                $cimSession = $null
            }
        }
    }

    if (-not $r.Online) {
        $r.Error = if ($lastError) { $lastError } else { "CIM connection failed" }
    }

    [pscustomobject]$r
}


# ------------------------------------------------------------
# Runspace execution
# ------------------------------------------------------------
$PrecheckOfflineResults = @()

# ✅ Phase 1: fast pre-check batching (skip if -NoPing)
if (-not $NoPing) {

    $reachableDevices = @()
    $PrecheckOfflineResults = @()

    $batches = Split-IntoBatches -InputObject $Computers -BatchSize $PrecheckBatchSize

    #Write-Host "[DEBUG] Starting pre-check phase..." -ForegroundColor Yellow

    $totalPre = $Computers.Count
    $donePre = 0

    foreach ($batch in $batches) {

        # ✅ Safe percent calculation
        $percent = 0
        if ($totalPre -gt 0) {
            $percent = ($donePre / $totalPre) * 100
        }

        Write-Progress `
            -Activity "Phase 1: Pre-check (fast connectivity)" `
            -Status ("Processing {0} of {1} devices" -f $donePre, $totalPre) `
            -PercentComplete $percent

        #Write-Host ("[DEBUG] Processing batch of {0}" -f $batch.Count) -ForegroundColor DarkYellow

        $pre = Invoke-FastPrecheckBatch -Computers $batch -Throttle $PrecheckThrottle

        foreach ($p in $pre) {
            $donePre++

            if ($p.Reachable) {
                $reachableDevices += $p.ComputerName
            }
            else {
                $PrecheckOfflineResults += [pscustomobject]@{
                    ComputerName       = $p.ComputerName
                    ConnectedHostName  = $null
                    ConnectedIP        = $null
                    ReverseDnsHostName = $null
                    ReverseDnsMatch    = $null
                    NameMatch          = $null
                    Online             = $false
                    CimProtocolUsed    = $null
                    Model              = $null
                    LoggedOnUser       = $null
                    OSRelease          = $null
                    OSFlag             = $null
                    OSDisplay          = $null
                    LastBootRaw        = $null
                    LastBootTime       = $null
                    NeedsReboot        = $null
                    WU_Compliant       = $null
                    DriveSizeGB        = $null
                    Error              = "Fast pre-check failed"
                }
            }
        }
    }

    Write-Progress `
        -Activity "Phase 1: Pre-check (fast connectivity)" `
        -Completed

    $Computers = $reachableDevices | Sort-Object -Unique
    $total = $Computers.Count
    $done = 0
}

# ✅ Main scan phase (your existing worker)
$pool = [runspacefactory]::CreateRunspacePool(1, $ThrottleLimit)
$pool.Open()

$jobs = New-Object System.Collections.Generic.List[object]

foreach ($c in $Computers) {
    $ps = [powershell]::Create()
    $ps.RunspacePool = $pool
    $null = $ps.AddScript($Worker.ToString())
    $null = $ps.AddArgument($c)
    $null = $ps.AddArgument([bool]$NoPing)
    $jobs.Add([pscustomobject]@{
            Computer = $c
            PS       = $ps
            Handle   = $ps.BeginInvoke()
        }) | Out-Null
}

# ------------------------------------------------------------
# Console output (aligned; CIM method removed from console ONLY)
# ------------------------------------------------------------

foreach ($r in $PrecheckOfflineResults) {

    if ($RebootOnly -or $NoUserOnly) {
        continue
    }

    if (-not $HideOffline -and -not $ExportOnly) {
        Write-Host ("[OFFLINE] {0} ({1})" -f $r.ComputerName, (Coalesce $r.Error "Unknown")) -ForegroundColor DarkRed
    }

    if ($PassThru) { $r }


    if ($ExportCsv) {
        if (-not $ExportResults) {
            $ExportResults = New-Object System.Collections.Generic.List[object]
        }

        [void]$ExportResults.Add($r)
    }

}

$ModelPadWidth = 40
$total = $Computers.Count
$done = 0
$processed = 0
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$nextTick = 0L
$ExportResults = New-Object System.Collections.Generic.List[object]

try {
    while ($jobs.Count -gt 0) {

        for ($i = $jobs.Count - 1; $i -ge 0; $i--) {

            $job = $jobs[$i]

            if (-not $job.Handle.IsCompleted) { continue }

            $r = $null
            try {
                $out = $job.PS.EndInvoke($job.Handle)
                $r = $out | Select-Object -First 1
            }
            catch {
                $r = [pscustomobject]@{
                    ComputerName = $job.Computer
                    Online       = $false
                    Error        = $_.Exception.Message
                }
            }
            finally {
                try { $job.PS.Dispose() } catch {}
            }

            # ✅ CRITICAL: always remove job immediately after completion
            $jobs.RemoveAt($i)
            $processed++ 
            if (-not $r) {
                continue
            }

            # ✅ NoUserOnly filter
            if ($NoUserOnly) {
                if ($r.Online -ne $true) {
                    continue
                }
                if (-not [string]::IsNullOrWhiteSpace($r.LoggedOnUser) -and $r.LoggedOnUser -ne "NoUser") {
                    continue
                }
            }

            # ✅ RebootOnly filter
            if ($RebootOnly) {

                if ($r.Online -ne $true) {
                    continue
                }

                if ($r.NeedsReboot -ne $true) {
                    continue
                }

                if ($MinUptimeDays -gt 0) {

                    $uptimeDays = $null
                    if ($r.LastBootTime -is [datetime]) {
                        $uptimeDays = [math]::Floor(
                            (New-TimeSpan -Start $r.LastBootTime -End (Get-Date)).TotalDays
                        )
                    }

                    if ($uptimeDays -eq $null -or $uptimeDays -lt $MinUptimeDays) {
                        continue
                    }
                }
            }

            # ✅ ONLY increment AFTER filters
            $done++

            # ✅ Existing output logic unchanged below
            # ✅ Offline handling
            # In normal mode: offline devices respect -HideOffline
            # In -NoUserOnly mode: allow "NoUser" results through to the normal output branch
            if (-not $r.Online) {

                if ($NoUserOnly -and $r.LoggedOnUser -eq "NoUser") {
                    # allow this through to the normal output block below
                }
                else {
                    if (-not $HideOffline) {
                        if (-not $ExportOnly) {
                            Write-Host ("[OFFLINE] {0} ({1})" -f $r.ComputerName, (Coalesce $r.Error "Unknown")) -ForegroundColor DarkRed
                        }

                        if ($PassThru) { $r }

                        if ($ExportCsv) {
                            if (-not $ExportResults) {
                                $ExportResults = New-Object System.Collections.Generic.List[object]
                            }
                            [void]$ExportResults.Add($r)
                        }
                    }

                    continue
                }
            }

            # ✅ Normal output branch (runs for:
            #    - normal online devices
            #    - NoUserOnly devices that were allowed through above)
            $queried = Coalesce $r.ComputerName "Unknown"
            $resolved = Coalesce $r.ConnectedHostName "Unknown"

            $hostBlock = ""
            if ($r.NameMatch -eq $false -and -not [string]::IsNullOrWhiteSpace($resolved)) {
                $hostBlock = ("{0} | {1}" -f $queried, $resolved)
            }
            else {
                $hostBlock = $queried
            }


            $osShort = $r.OSDisplay
            if (-not $osShort) { $osShort = '?' } elseif ($osShort -match 'Win\d+\s+(.*)') { $osShort = $Matches[1] }
            $osPad = ("{0,-4}" -f $osShort)

            $ipPad = ("{0,-15}" -f (Coalesce $r.ConnectedIP '?'))

            $drvPad = "DRV:?".PadRight(13)
            if ($r.DriveSizeGB -ne $null -and $r.DriveUsedPct -ne $null) { $drvPad = ("{0,-13}" -f ("DRV:{0}G/{1}%" -f $r.DriveSizeGB, $r.DriveUsedPct)) }

            $ramPad = "RAM:?".PadRight(12)
            if ($r.TotalRAMGB -ne $null -and $r.RAMUsedPct -ne $null) { $ramPad = ("{0,-12}" -f ("RAM:{0}G/{1}%" -f $r.TotalRAMGB, $r.RAMUsedPct)) }

            $wuFlg = if ($r.WU_Compliant -eq $false) { 'FAIL' } elseif ($r.WU_Compliant) { 'OK' } else { 'UNK' }
            $wuPad = ("WU:{0,-4}" -f $wuFlg)


            $bootStr = '?'
            if ($r.LastBootTime -is [datetime]) { 
                $bootStr = $r.LastBootTime.ToString('yy-MM-dd HH:mm') 
            }
            $uptimeText = ''
            if ($r.LastBootTime -is [datetime]) {
                $uptimeDays = [math]::Floor((New-TimeSpan -Start $r.LastBootTime -End (Get-Date)).TotalDays)
                $uptimeText = if ($uptimeDays -eq 0) { ' (<1d)' } else { " ($uptimeDays`d)" }
            }
            $bootPad = ("{0,-26}" -f ("BOOT:$bootStr$uptimeText"))

            $mdlText = (Coalesce $r.Model '-')
            if ($r.PowerState -eq 'Battery') { $mdlText += ' (on battery)' }

            $mdlPad = ("{0,-58}" -f $mdlText)

            $userText = if ([string]::IsNullOrWhiteSpace($r.LoggedOnUser)) { 'NoUser' } else { $r.LoggedOnUser }
            if ($r.SessionState -eq 'Locked' -and $userText -ne 'NoUser') { $userText += ' (Locked)' }

            # ---- Reboot summary ----
            $rb = "UNK"
            if ($r.NeedsReboot) {
                $reasons = @()
                if ($r.RebootReason -match 'Windows Update') { $reasons += 'WU' }
                if ($r.RebootReason -match 'Component Servicing') { $reasons += 'CBS' }
                if ($r.RebootReason -match 'Pending File Rename') { $reasons += 'PFRO' }

                if ($reasons.Count -gt 0) { 
                    $rb = "Yes (" + ($reasons -join '+') + ")" 
                }
                else { 
                    $rb = "Yes" 
                }
            }
            elseif ($r.NeedsReboot -eq $false) { 
                $rb = "No" 
            }
            $rbPad = ("RB:{0,-17}" -f $rb)

            $rdnsText = ""
            if ($r.ReverseDnsMatch -eq $false) {
                $rdnsText = (" | RDNS:{0,-15}" -f (Coalesce $r.ReverseDnsHostName "?"))
            }

            $line = (
                "{0} | {1} | {2} | {3} | {4} | {5} | {6} | {7} | {8} | {9} " -f `
                    $r.ComputerName,
                $osPad,
                $ipPad,
                $drvPad,
                $ramPad,
                $wuPad,
                $bootPad,
                $rbPad,
                $mdlPad,
                $userText
            )


            $displayColor = Get-RowColor -r $r
            if (-not $displayColor) {
                $displayColor = "Gray"
            }

            if (-not $ExportOnly) {
                Write-Host ($line + $rdnsText) -ForegroundColor $displayColor
            }

            if ($PassThru) { $r }

            if ($ExportCsv) {
                if (-not $ExportResults) {
                    $ExportResults = New-Object System.Collections.Generic.List[object]
                }

                if ($DebugMode) {
                    [void]$ExportResults.Add($r)
                }
                else {
                    $r.PSObject.Properties.Remove("RebootDebugLog")
                    [void]$ExportResults.Add($r)
                }
            }

        }

        if ($ProgressIntervalMs -gt 0 -and $sw.ElapsedMilliseconds -ge $nextTick) {

            $pct = 0

            if ($total -gt 0) {
                $pct = ($processed / $total) * 100
            }

            if ($pct -gt 100) {
                $pct = 100
            }

            Write-Progress -Id 1 `
                -Activity "Scanning devices" `
                -Status   "$processed/$total complete | $done matches" `
                -PercentComplete $pct

            $nextTick = $sw.ElapsedMilliseconds + $ProgressIntervalMs
        }

        Start-Sleep -Milliseconds 50
    }

    # ✅ Export to CSV if requested
    if ($ExportCsv -and $ExportResults.Count -gt 0) {

        try {
            $ExportResults |
            Select-Object ComputerName,
            ConnectedIP,
            OSDisplay,
            WU_Compliant,
            NeedsReboot,
            RebootReason,
            LastBootTime,
            LoggedOnUser,
            Model,
            DriveSizeGB,
            TotalRAMGB |
            Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
            
            if (-not $ExportOnly) {
                Write-Host ("[INFO] Exported {0} devices to {1}" -f $ExportResults.Count, $ExportCsv) -ForegroundColor Green
            }
        }
        catch {
            Write-Host ("[ERROR] Failed to export CSV: {0}" -f $_.Exception.Message) -ForegroundColor Red
        }
    }
}

finally {
    Write-Progress -Id 1 -Activity "Interrogating remote devices" -Completed
    Invoke-Cleanup -Jobs $jobs -Pool $pool
}