<#
PS-BasicFix.ps1

.SYNOPSIS
  Executes a structured set of Windows repair and diagnostic tasks with intelligent
  pre-checks, progress feedback, and optional remediation steps. Outputs a GPResult
  HTML report and summarized findings to the working directory. PowerShell 5.1 safe.

.DESCRIPTION
  Sequentially runs the following stages (with safety checks and structured logging):

    1) CHKDSK C: /scan (non-disruptive online scan with heartbeat/progress visibility)

    2) DISM Component Store Health Assessment:
         - /CheckHealth (quick validation)
         - /ScanHealth (deep validation)
         - /RestoreHealth ONLY runs if corruption is detected and repairable
       (prevents unnecessary failures and console errors)

    3) SFC /scannow
         - Includes live progress capture (Verification %)
         - Heartbeat + stall detection for long-running operations

    4) Local Group Policy reset:
         - Removes GroupPolicy / GroupPolicyUsers (if present)
         - Runs gpupdate /force

    5) Windows Update reset (optional skip via -NoWU):
         - Stops services (wuauserv, bits, cryptsvc)
         - Safely removes:
             %windir%\SoftwareDistribution
             %windir%\System32\catroot2
         - Uses resilient deletion logic with fallback handling

    6) Network stack reset (OPT-IN via -NetReset):
         - Winsock reset
         - TCP/IP stack reset
         - DNS flush + DHCP renewal
       (excluded by default due to disruptive impact)

    7) GPResult report generation:
         - gpresult /h (computer scope)
         - Output saved to script working directory
         - Parsed into structured summary (Domain, OU, GPOs, DC, etc.)

    8) Structured summary output:
         - Consolidated findings from all stages
         - Highlights warnings, failures, and key signals

  All long-running operations include:
    - Heartbeat logging ("Still running...")
    - Stall detection warnings
    - Safe output capture (no console spam)

.PARAMETER Quiet
  Suppresses DEBUG and INFO logging output. Only WARNING, ERROR, and SUMMARY messages are displayed.

.PARAMETER NoWU
  Skips the Windows Update reset stage.

.PARAMETER NetReset
  Enables network stack reset (opt-in due to potential disruption of network/VPN configuration).

.EXAMPLE
  .\PS-BasicFix.ps1

.EXAMPLE
  .\PS-BasicFix.ps1 -Quiet

.EXAMPLE
  .\PS-BasicFix.ps1 -NoWU

.EXAMPLE
  .\PS-BasicFix.ps1 -NetReset

.EXAMPLE
  powershell.exe -ExecutionPolicy Bypass -File .\PS-BasicFix.ps1 -Quiet -NoWU
#>


[CmdletBinding()]
param(
    [switch]$Quiet,
    [switch]$NoWU,
    [switch]$NetReset,

    [switch]$EventScan,
    [int]$EventDays = 1,

    [switch]$GPResult,
    [switch]$DeepWU,

    [switch]$Full,

    [switch]$SkipCHK,

    [switch]$Help
)

# --- Help / Usage ---
if ($Help -or $args -contains '/?' -or $args -contains '-?') {

    Write-Host ''
    Write-Host 'PS-BasicFix.ps1 - Available switches:' -ForegroundColor Cyan
    Write-Host ''

    Write-Host '  -Quiet        Suppress DEBUG/INFO output'
    Write-Host '  -NoWU         Skip Windows Update reset (basic + advanced)'
    Write-Host '  -NetReset     Enable network stack reset (opt-in)'
    Write-Host '  -DeepWU       Enable advanced Windows Update repair actions (opt-in)'
    Write-Host '  -SkipCHK     Skip CHKDSK scan (useful for faster runs or SSD-heavy estates)'
    Write-Host ''
    Write-Host '  -EventScan    Enable event log analysis (defaults to last 24 hours)'
    Write-Host '  -EventDays N  Scan last N days of events (implies EventScan)'
    Write-Host ''
    Write-Host '  -GPResult     Enable GPResult HTML report generation and parsing'
    Write-Host '               Note: gpresult text summary is always collected'
    Write-Host ''
    Write-Host '  -Full         Enable all optional troubleshooting modules'
    Write-Host '               Default behaviour if no switches are provided'
    Write-Host '               Use -Full:$false to force minimal execution'
    Write-Host ''

    Write-Host 'Behaviour:' -ForegroundColor Yellow
    Write-Host '  Default run executes ALL troubleshooting modules except GPResult HTML'
    Write-Host '  Individual switches override defaults where specified'
    Write-Host ''

    Write-Host 'Examples:' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '  .\PS-BasicFix.ps1'
    Write-Host '      Full diagnostic run (default behaviour)'
    Write-Host ''
    Write-Host '  .\PS-BasicFix.ps1 -Full'
    Write-Host '      Explicit full diagnostic run'
    Write-Host ''
    Write-Host '  .\PS-BasicFix.ps1 -Full:$false'
    Write-Host '      Minimal run (core repair only)'
    Write-Host ''
    Write-Host '  .\PS-BasicFix.ps1 -EventScan'
    Write-Host '      Full run with event analysis (24h)'
    Write-Host ''
    Write-Host '  .\PS-BasicFix.ps1 -EventDays 3'
    Write-Host '      Full run with event analysis (3 days)'
    Write-Host ''
    Write-Host '  .\PS-BasicFix.ps1 -DeepWU'
    Write-Host '      Full run with advanced Windows Update repair'
    Write-Host ''
    Write-Host '  .\PS-BasicFix.ps1 -GPResult'
    Write-Host '      Full run including GPResult HTML report'
    Write-Host ''
    Write-Host '  .\PS-BasicFix.ps1 -Quiet -NoWU'
    Write-Host '      Full run with minimal output and no Windows Update actions'
    Write-Host ''

    return
}

# --- Full mode default / override logic ---
$RunFull = $Full

# ✅ If no explicit module switches were provided → assume Full
if (-not $PSBoundParameters.ContainsKey('Full') -and
    -not $PSBoundParameters.ContainsKey('NetReset') -and
    -not $PSBoundParameters.ContainsKey('EventScan') -and
    -not $PSBoundParameters.ContainsKey('EventDays') -and
    -not $PSBoundParameters.ContainsKey('DeepWU') -and
    -not $PSBoundParameters.ContainsKey('GPResult')) {

    $RunFull = $true
}

# ✅ Apply Full behaviour
if ($RunFull) {

    #Write-Log -Level INFO -Stage 'Startup' -Message 'Full mode active (default or explicit) - enabling all optional modules (except GPResult HTML)'

    # Enable modules unless explicitly overridden
    if (-not $PSBoundParameters.ContainsKey('NetReset')) {  $NetReset  = $true }
    if (-not $PSBoundParameters.ContainsKey('EventScan') -and -not $PSBoundParameters.ContainsKey('EventDays')) { $EventScan = $true }
    if (-not $PSBoundParameters.ContainsKey('DeepWU')) { $DeepWU = $true }

    # Default EventDays if needed
    if (($EventScan -or $PSBoundParameters.ContainsKey('EventDays')) -and
        -not $PSBoundParameters.ContainsKey('EventDays')) {
        $EventDays = 1
    }
}

# -----------------------------
#  Structured Logging (Colour)
# -----------------------------
$script:WarnCount = 0
$script:ErrorCount = 0
$script:StartTime = Get-Date
$script:GPResultSummary = $null

function Write-DebugLog {
    param(
        [string]$Message,
        [string]$Level = 'DEBUG',
        [switch]$NoNewLine
    )

    try {
        $ts = Get-Date -Format 'HH:mm:ss'

        $prefix = "[{0}] {1} | {2}" -f $Level.ToUpper(), $ts, $Message

        if ($NoNewLine) {
            Write-Host -NoNewline $prefix
        }
        else {
            Write-Host $prefix
        }

    }
    catch {
        # Fallback (never break script)
        Write-Host "[DEBUG] Logging failure: $Message"
    }
}

function Write-Log {
    param(
        [ValidateSet('INFO', 'OK', 'WARN', 'ERROR', 'DEBUG', 'DONE', 'SUMMARY')]
        [string]$Level,
        [string]$Stage,
        [string]$Message,
        [string]$Detail = ''
    )

    # --- Quiet mode filtering ---
    if ($Level -eq 'DEBUG' -and $Quiet) { return }
    if ($Quiet -and $Level -eq 'INFO') { return }

    switch ($Level) {
        'INFO' { $color = 'Cyan' }
        'OK' { $color = 'Green' }
        'WARN' { $color = 'Yellow' }
        'ERROR' { $color = 'Red' }
        'DEBUG' { $color = 'DarkGray' }
        'DONE' { $color = 'Green' }
        'SUMMARY' { $color = 'Magenta' }
        default { $color = 'White' }
    }

    if ($Level -eq 'WARN') { $script:WarnCount++ }
    if ($Level -eq 'ERROR') { $script:ErrorCount++ }

    $ts = (Get-Date).ToString('HH:mm:ss')

    $line = '{0} | Time={1} | Stage={2} | Message={3}' -f $Level, $ts, $Stage, $Message
    if ($Detail) { $line += ' | Detail=' + $Detail }

    Write-Host $line -ForegroundColor $color
}

# -----------------------------
#  Elevation check
# -----------------------------
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Log -Level ERROR -Stage 'Startup' -Message 'Script must be run as Administrator.'
        exit 1
    }
}
catch {
    Write-Log -Level ERROR -Stage 'Startup' -Message 'Unable to verify elevation' -Detail $_.Exception.Message
    exit 1
}

# -----------------------------
#  Helpers
# -----------------------------
function Invoke-Step {
    param(
        [string]$Name,
        [scriptblock]$ScriptBlock
    )

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Log -Level INFO -Stage $Name -Message 'Starting'

    try {
        & $ScriptBlock
        $sw.Stop()
        Write-Log -Level OK -Stage $Name -Message 'Completed' -Detail ('DurationMs={0}' -f $sw.ElapsedMilliseconds)
    }
    catch {
        $sw.Stop()
        Write-Log -Level ERROR -Stage $Name -Message 'Unhandled exception' -Detail $_.Exception.Message
    }
}

function Invoke-Cmd {
    param(
        [string]$Stage,
        [string]$Command,
        [string]$Description,
        [switch]$TreatNonZeroAsError
    )

    Write-Log -Level INFO -Stage $Stage -Message $Description -Detail ("Command={0}" -f $Command)

    cmd.exe /c $Command 1>$null 2>$null
    $code = $LASTEXITCODE

    if ($code -eq 0) {
        Write-Log -Level OK -Stage $Stage -Message $Description -Detail ("ExitCode={0}" -f $code)
        return $true
    }

    if ($TreatNonZeroAsError) {
        Write-Log -Level ERROR -Stage $Stage -Message $Description -Detail ("ExitCode={0}" -f $code)
    }
    else {
        Write-Log -Level WARN -Stage $Stage -Message $Description -Detail ("ExitCode={0}" -f $code)
    }

    return $false
}

function Invoke-LongRunningCommand {
    param(
        [string]$Stage,
        [string]$FilePath,
        [string]$Arguments,
        [int]$HeartbeatSeconds = 30
    )

    try {
        Write-Log -Level INFO -Stage $Stage -Message 'Starting long-running command' -Detail $Arguments

        $proc = Start-Process -FilePath $FilePath `
            -ArgumentList $Arguments `
            -PassThru

        $lastHeartbeat = Get-Date
        $startTime = Get-Date

        while (-not $proc.HasExited) {

            Start-Sleep -Seconds 5

            $now = Get-Date

            # --- Heartbeat (every X seconds) ---
            if (($now - $lastHeartbeat).TotalSeconds -ge $HeartbeatSeconds) {
                Write-Log -Level INFO -Stage $Stage -Message 'Still running...'
                $lastHeartbeat = $now
            }

            # --- Stall detection (separate timer) ---
            if (($now - $startTime).TotalMinutes -ge 10) {
                Write-Log -Level WARN -Stage $Stage -Message 'Potential stall detected (>10 minutes without completion)'
        
                # Reset timer so it doesn't spam every loop
                $startTime = $now
            }
        }

        $proc.WaitForExit()

        if ($proc.ExitCode -eq 0) {
            Write-Log -Level OK -Stage $Stage -Message 'Completed' -Detail ("ExitCode={0}" -f $proc.ExitCode)
        }
        else {
            Write-Log -Level WARN -Stage $Stage -Message 'Completed with non-zero exit' -Detail ("ExitCode={0}" -f $proc.ExitCode)
        }
    }
    catch {
        Write-Log -Level ERROR -Stage $Stage -Message 'Execution failed' -Detail $_.Exception.Message
    }
}

function Invoke-ProcessWithProgress {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Stage,

        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string[]]$ArgumentList,

        # Regex that captures the numeric percent in group 1
        [Parameter(Mandatory = $true)]
        [string]$ProgressPattern,

        # How often to emit “Still running…” messages
        [int]$HeartbeatSeconds = 30,

        # Warn if no new output/progress for this many minutes
        [int]$StallMinutes = 10
    )

    Write-Log -Level INFO -Stage $Stage -Message 'Starting' -Detail ("File={0}; Args={1}" -f $FilePath, ($ArgumentList -join ' '))

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $psi.Arguments = ($ArgumentList -join ' ')

    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    $p.EnableRaisingEvents = $true

    # Thread-safe buffers
    $stdoutBuf = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $stderrBuf = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))

    $evtOut = Register-ObjectEvent -InputObject $p -EventName OutputDataReceived -Action {
        if ($EventArgs.Data) { [void]$stdoutBuf.Add($EventArgs.Data) }
    }
    $evtErr = Register-ObjectEvent -InputObject $p -EventName ErrorDataReceived -Action {
        if ($EventArgs.Data) { [void]$stderrBuf.Add($EventArgs.Data) }
    }

    $lastHeartbeat = Get-Date
    $lastActivity = Get-Date
    $lastPct = $null

    try {
        $null = $p.Start()
        $p.BeginOutputReadLine()
        $p.BeginErrorReadLine()

        while (-not $p.HasExited) {

            # Drain stdout
            $lines = $null
            [System.Threading.Monitor]::Enter($stdoutBuf.SyncRoot)
            try {
                if ($stdoutBuf.Count -gt 0) {
                    $lines = @($stdoutBuf)
                    $stdoutBuf.Clear()
                }
            }
            finally { [System.Threading.Monitor]::Exit($stdoutBuf.SyncRoot) }

            if ($lines) {
                $lastActivity = Get-Date

                foreach ($line in $lines) {
                    # Extract progress %
                    $pctText = Get-RegexValueSafe -Text $line -Pattern $ProgressPattern
                    if ($pctText) {
                        # Normalise & compare
                        $pct = $null
                        try { $pct = [double]$pctText } catch { $pct = $null }

                        if ($pct -ne $null) {
                            # Only log when progress changes (avoid spam)
                            if ($lastPct -eq $null -or $pct -ne $lastPct) {
                                Write-Log -Level INFO -Stage $Stage -Message 'Progress' -Detail ("Percent={0}" -f $pct)
                                $lastPct = $pct
                            }
                        }
                    }
                }
            }

            # Heartbeat
            $now = Get-Date
            if (($now - $lastHeartbeat).TotalSeconds -ge $HeartbeatSeconds) {
                Write-Log -Level INFO -Stage $Stage -Message 'Still running...'
                $lastHeartbeat = $now
            }

            # Stall detection: no new output for N minutes
            if (($now - $lastActivity).TotalMinutes -ge $StallMinutes) {
                Write-Log -Level WARN -Stage $Stage -Message 'Potential stall detected' -Detail (">{0} minutes with no output/progress" -f $StallMinutes)
                $lastActivity = $now  # reset to avoid log spam
            }

            Start-Sleep -Milliseconds 250
        }

        $p.WaitForExit()

        # Drain any remaining stderr lines for context (optional)
        $errLines = $null
        [System.Threading.Monitor]::Enter($stderrBuf.SyncRoot)
        try {
            if ($stderrBuf.Count -gt 0) {
                $errLines = @($stderrBuf)
                $stderrBuf.Clear()
            }
        }
        finally { [System.Threading.Monitor]::Exit($stderrBuf.SyncRoot) }

        if ($p.ExitCode -eq 0) {
            Write-Log -Level OK -Stage $Stage -Message 'Completed' -Detail ("ExitCode={0}" -f $p.ExitCode)
        }
        else {
            $errPreview = if ($errLines -and $errLines.Count -gt 0) {
                ($errLines | Select-Object -First 3) -join ' | '
            }
            else { 'No stderr captured' }

            Write-Log -Level WARN -Stage $Stage -Message 'Completed with non-zero exit' -Detail ("ExitCode={0}; Err={1}" -f $p.ExitCode, $errPreview)
        }

        return $p.ExitCode
    }
    catch {
        Write-Log -Level ERROR -Stage $Stage -Message 'Execution failed' -Detail $_.Exception.Message
        return 999
    }
    finally {
        # Always clean up event registrations
        if ($evtOut) { Unregister-Event -SourceIdentifier $evtOut.Name -ErrorAction SilentlyContinue }
        if ($evtErr) { Unregister-Event -SourceIdentifier $evtErr.Name -ErrorAction SilentlyContinue }
        if ($p) { $p.Dispose() }
    }
}

function Invoke-NetworkReset {
    Invoke-Step -Name 'NetworkReset' -ScriptBlock {

        $stage = 'NetworkReset'

        Invoke-Cmd -Stage $stage -Description 'Reset Winsock' -Command 'netsh winsock reset' | Out-Null
        Invoke-Cmd -Stage $stage -Description 'Reset TCP/IP' -Command 'netsh int ip reset' | Out-Null
        Invoke-Cmd -Stage $stage -Description 'Flush DNS' -Command 'ipconfig /flushdns' | Out-Null
        Invoke-Cmd -Stage $stage -Description 'Renew DHCP lease' -Command 'ipconfig /renew' | Out-Null
    }
}

function Invoke-EventIntelligence {
    Invoke-Step -Name 'EventIntelligence' -ScriptBlock {

        $stage = 'EventIntelligence'

        Write-Log -Level INFO -Stage $stage -Message 'Collecting recent event signals (last 24h, limited set)'

        try {
            # ✅ Strict limits (fast + safe)
            $events = Get-WinEvent -FilterHashtable @{
                LogName   = 'System'
                StartTime = (Get-Date).AddHours(-24)
                Id        = 20, 31, 34, 35, 1030, 1058, 55, 7, 1001
            } -MaxEvents 200 -ErrorAction Stop
        }
        catch {
            Write-Log -Level WARN -Stage $stage -Message 'Event query failed' -Detail $_.Exception.Message
            return
        }

        if (-not $events -or $events.Count -eq 0) {
            Write-Log -Level OK -Stage $stage -Message 'No relevant events found'
            return
        }

        # ✅ Known mappings (extendable)
        $wuErrorMap = @{
            '0x800f0922' = 'Install failure (often network / servicing stack)'
            '0x8024401c' = 'WSUS / network connectivity issue'
            '0x8024001e' = 'Service stopped / interrupted'
        }

        $seen = 0

        foreach ($ev in $events) {

            $msg = $ev.Message

            if (-not $msg) { continue }

            # ✅ Trim long messages (your pattern)
            if ($msg.Length -gt 160) {
                $msg = $msg.Substring(0, 157) + '...'
            }

            # ✅ Windows Update failures
            if ($ev.Id -in 20, 31, 34, 35) {

                $hint = ''
                foreach ($code in $wuErrorMap.Keys) {
                    if ($msg -match [regex]::Escape($code)) {
                        $hint = " | Hint=$($wuErrorMap[$code])"
                        break
                    }
                }

                Write-Log -Level WARN -Stage $stage -Message 'Windows Update Failure' -Detail ("Id={0} | {1}{2}" -f $ev.Id, $msg, $hint)
                $seen++
                continue
            }

            # ✅ Group Policy failures
            if ($ev.Id -in 1058, 1030) {
                Write-Log -Level WARN -Stage $stage -Message 'Group Policy Failure' -Detail ("Id={0} | {1}" -f $ev.Id, $msg)
                $seen++
                continue
            }

            # ✅ Disk / NTFS errors
            if ($ev.Id -in 55, 7) {
                Write-Log -Level ERROR -Stage $stage -Message 'Disk issue detected' -Detail ("Id={0} | {1}" -f $ev.Id, $msg)
                $seen++
                continue
            }

            # ✅ BugCheck / crash indicator
            if ($ev.Id -eq 1001) {
                Write-Log -Level ERROR -Stage $stage -Message 'System crash detected' -Detail $msg
                $seen++
                continue
            }
        }

        if ($seen -eq 0) {
            Write-Log -Level OK -Stage $stage -Message 'No actionable signals found in events'
        }
        else {
            Write-Log -Level SUMMARY -Stage $stage -Message 'Event signals detected' -Detail ("Count={0}" -f $seen)
        }
    }
}

function Invoke-AdvancedWUReset {
    Invoke-Step -Name 'AdvancedWUReset' -ScriptBlock {

        $stage = 'AdvancedWUReset'
        Write-Log -Level WARN -Stage $stage -Message 'Running ADVANCED Windows Update reset actions'

        # --- 1. Clear BITS queue (qmgr.dat) ---
        try {
            Write-Log -Level INFO -Stage $stage -Message 'Clearing BITS download queue'

            $qmgrPath = "$env:ALLUSERSPROFILE\Application Data\Microsoft\Network\Downloader\qmgr*.dat"
            Remove-Item -Path $qmgrPath -Force -ErrorAction SilentlyContinue

            Write-Log -Level OK -Stage $stage -Message 'BITS queue cleared'
        }
        catch {
            Write-Log -Level WARN -Stage $stage -Message 'Failed to clear BITS queue' -Detail $_.Exception.Message
        }

        # --- 2. Restart Windows Installer service (only if needed) ---
        try {
            $svc = Get-Service -Name msiserver -ErrorAction SilentlyContinue

            if ($svc -and $svc.Status -eq 'Running') {
                Invoke-Cmd -Stage $stage -Description 'Stop Windows Installer' -Command 'net stop msiserver' | Out-Null
            }
            else {
                Write-Log -Level DEBUG -Stage $stage -Message 'Windows Installer already stopped'
            }

            Invoke-Cmd -Stage $stage -Description 'Start Windows Installer' -Command 'net start msiserver' | Out-Null
        }
        catch {
            Write-Log -Level WARN -Stage $stage -Message 'Windows Installer reset failed' -Detail $_.Exception.Message
        }

        # --- 3. Delivery Optimization reset (safe + high-value) ---
        try {
            Write-Log -Level INFO -Stage $stage -Message 'Resetting Delivery Optimization cache'

            $dosvc = Get-Service -Name DoSvc -ErrorAction SilentlyContinue

            if ($dosvc -and $dosvc.Status -eq 'Running') {
                Stop-Service -Name DoSvc -Force -ErrorAction SilentlyContinue
            }

            $doPath = "$env:SystemRoot\SoftwareDistribution\DeliveryOptimization"
            if (Test-Path $doPath) {
                Remove-PathSafe -Stage $stage -Path $doPath | Out-Null
            }

            Start-Service -Name DoSvc -ErrorAction SilentlyContinue

            Write-Log -Level OK -Stage $stage -Message 'Delivery Optimization reset complete'
        }
        catch {
            Write-Log -Level WARN -Stage $stage -Message 'Delivery Optimization reset failed' -Detail $_.Exception.Message
        }

        Write-Log -Level SUMMARY -Stage $stage -Message 'Advanced Windows Update reset completed (production-safe mode)'
    }
}

# Robust delete helper: uses RD (more tolerant of corrupt child paths than Remove-Item)
function Remove-PathSafe {
    param(
        [string]$Stage,
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Log -Level DEBUG -Stage $Stage -Message 'Path not present (skipped)' -Detail ('Path={0}' -f $Path)
        return $true
    }

    Write-Log -Level INFO -Stage $Stage -Message 'Removing path' -Detail ('Path={0}' -f $Path)

    try {
        # --- Primary removal (PowerShell native) ---
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
    }
    catch {
        # --- Fallback to RD (handles stubborn paths) ---
        Write-Log -Level DEBUG -Stage $Stage -Message 'Falling back to RD' -Detail ('Path={0}' -f $Path)

        try {
            $cmd = 'rd /s /q "{0}"' -f $Path
            cmd.exe /c $cmd 1>$null 2>$null
        }
        catch {
            Write-Log -Level WARN -Stage $Stage -Message 'RD fallback failed' -Detail $_.Exception.Message
        }
    }

    # --- Post-check ---
    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Log -Level OK -Stage $Stage -Message 'Removed path' -Detail ('Path={0}' -f $Path)
        return $true
    }
    else {
        Write-Log -Level WARN -Stage $Stage -Message 'Path still present after delete attempt' -Detail ('Path={0}' -f $Path)
        return $false
    }
}

function Stop-ServiceSafe {
    param(
        [string]$Stage,
        [string]$Name
    )

    try {
        $svc = Get-Service -Name $Name -ErrorAction Stop
        if ($svc.Status -ne 'Stopped') {
            Write-Log -Level INFO -Stage $Stage -Message 'Stopping service' -Detail ('Service={0}' -f $Name)
            Stop-Service -Name $Name -Force -ErrorAction Stop
            Write-Log -Level OK -Stage $Stage -Message 'Service stopped' -Detail ('Service={0}' -f $Name)
        }
        else {
            Write-Log -Level DEBUG -Stage $Stage -Message 'Service already stopped' -Detail ('Service={0}' -f $Name)
        }
    }
    catch {
        Write-Log -Level WARN -Stage $Stage -Message 'Could not stop service' -Detail ('Service={0}; Error={1}' -f $Name, $_.Exception.Message)
    }
}

function Start-ServiceSafe {
    param(
        [string]$Stage,
        [string]$Name
    )

    try {
        $svc = Get-Service -Name $Name -ErrorAction Stop
        if ($svc.Status -ne 'Running') {
            Write-Log -Level INFO -Stage $Stage -Message 'Starting service' -Detail ('Service={0}' -f $Name)
            Start-Service -Name $Name -ErrorAction Stop
            Write-Log -Level OK -Stage $Stage -Message 'Service started' -Detail ('Service={0}' -f $Name)
        }
        else {
            Write-Log -Level DEBUG -Stage $Stage -Message 'Service already running' -Detail ('Service={0}' -f $Name)
        }
    }
    catch {
        Write-Log -Level WARN -Stage $Stage -Message 'Could not start service' -Detail ('Service={0}; Error={1}' -f $Name, $_.Exception.Message)
    }
}

# -----------------------------
#  GPResult Parsing Helpers
# -----------------------------
function Get-RegexValue {
    param(
        [string]$Text,
        [string]$Pattern
    )

    try {
        $opts = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
        [System.Text.RegularExpressions.RegexOptions]::Singleline

        $m = [System.Text.RegularExpressions.Regex]::Match($Text, $Pattern, $opts)
        if ($m.Success -and $m.Groups.Count -gt 1) {
            return $m.Groups[1].Value.Trim()
        }
    }
    catch {
        # swallow
    }

    return $null
}

function Get-EventRecordBlocksById {
    param(
        [string]$Text,
        [string]$EventId
    )

    $blocks = @()

    try {
        $opts = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
        [System.Text.RegularExpressions.RegexOptions]::Singleline

        $escaped = [System.Text.RegularExpressions.Regex]::Escape($EventId)
        $pattern = "<EventRecord>.*?<EventId>\s*$escaped\s*</EventId>.*?</EventRecord>"

        $ms = [System.Text.RegularExpressions.Regex]::Matches($Text, $pattern, $opts)
        foreach ($m in $ms) { $blocks += $m.Value }
    }
    catch {
        # swallow
    }

    return $blocks
}

function Extract-GpoListFromEventDescription {
    param(
        [string]$EventDescription
    )

    if (-not $EventDescription) { return @() }

    $lines = ($EventDescription -replace "`r", "") -split "`n"

    $out = New-Object System.Collections.Generic.List[string]
    foreach ($line in $lines) {
        $t = $line.Trim()
        if (-not $t) { continue }

        if ($t -match '^List of applicable Group Policy objects:' ) { continue }
        if ($t -match '^The following Group Policy objects were not applicable' ) { continue }
        if ($t -eq 'None') { continue }

        $out.Add($t)
    }

    # De-dup preserving order
    $seen = @{}
    $final = @()
    foreach ($g in $out) {
        if (-not $seen.ContainsKey($g)) {
            $seen[$g] = $true
            $final += $g
        }
    }

    return $final
}

function Get-RegexValueSafe {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text,

        [Parameter(Mandatory = $true)]
        [string]$Pattern,

        [switch]$SingleLine
    )

    try {
        $options = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase

        if ($SingleLine) {
            $options = $options -bor [System.Text.RegularExpressions.RegexOptions]::Singleline
        }

        $match = [System.Text.RegularExpressions.Regex]::Match($Text, $Pattern, $options)

        if ($match.Success -and $match.Groups.Count -gt 1) {
            return $match.Groups[1].Value.Trim()
        }
    }
    catch {
        # Optional debug hook
        # Write-Host "Regex failure: $Pattern"
    }

    return $null
}

function Get-GPResultSummaryFromHtml {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) { return $null }

    # --- Read HTML (GPResult typically UTF-16) ---
    $raw = $null
    try {
        $raw = Get-Content -LiteralPath $Path -Raw -Encoding Unicode
    }
    catch {
        try {
            $raw = Get-Content -LiteralPath $Path -Raw -Encoding Default
        }
        catch {
            return $null
        }
    }

    if (-not $raw) { return $null }

    # --- Decode HTML entities ---
    $text = [System.Net.WebUtility]::HtmlDecode($raw)

    # --- Extract core fields using helper ---
    $computer = Get-RegexValueSafe -Text $text -Pattern 'Computer name\s*</strong>\s*</td>\s*<td>\s*([^<]+)\s*</td>'
    $domain = Get-RegexValueSafe -Text $text -Pattern 'Domain\s*</strong>\s*</td>\s*<td>\s*([^<]+)\s*</td>'
    $site = Get-RegexValueSafe -Text $text -Pattern 'Site\s*</strong>\s*</td>\s*<td>\s*([^<]+)\s*</td>'
    $ou = Get-RegexValueSafe -Text $text -Pattern 'Organizational Unit\s*</strong>\s*</td>\s*<td>\s*([^<]+)\s*</td>'

    $lastRefresh = Get-RegexValueSafe -Text $text `
        -Pattern 'During last\s*<strong>\s*computer policy\s*</strong>\s*refresh on\s*([^<]+)'

    $dcName = Get-RegexValueSafe -Text $text `
        -Pattern "Data\s+Name=['""]DCName['""]>\s*([^<]+)\s*</Data>"

    # --- Applied GPOs (Event 5312) ---
    $applied = @()

    $event5312 = Get-RegexValueSafe -Text $text `
        -Pattern '<EventId>\s*5312\s*</EventId>.*?<EventDescription>\s*(.*?)\s*</EventDescription>' `
        -SingleLine

    if ($event5312) {
        $lines = ($event5312 -replace "`r", "") -split "`n"

        foreach ($line in $lines) {
            $t = $line.Trim()
            if ($t -and
                $t -ne 'None' -and
                $t -notmatch '^List of applicable') {

                $applied += $t
            }
        }
    }

    # --- Filtered GPOs (Event 5313) ---
    $filtered = @()

    $event5313 = Get-RegexValueSafe -Text $text `
        -Pattern '<EventId>\s*5313\s*</EventId>.*?<EventDescription>\s*(.*?)\s*</EventDescription>' `
        -SingleLine

    if ($event5313) {
        $lines = ($event5313 -replace "`r", "") -split "`n"

        foreach ($line in $lines) {
            $t = $line.Trim()
            if ($t -and
                $t -ne 'None' -and
                $t -notmatch '^The following Group Policy objects were not applicable') {

                $filtered += $t
            }
        }
    }

    # --- Return structured object ---
    return [pscustomobject]@{
        ReportPath          = $Path
        Computer            = $computer
        Domain              = $domain
        Site                = $site
        OU                  = $ou
        LastComputerRefresh = $lastRefresh
        DomainController    = $dcName
        AppliedGpos         = $applied
        FilteredGpos        = $filtered
    }
}

function Get-GPResultTextSections {
    param()

    try {
        $raw = & gpresult.exe /r /scope computer 2>&1 | Out-String
    }
    catch {
        Write-Log -Level WARN -Stage 'GPResultText' -Message 'gpresult /r /scope computer failed' -Detail $_.Exception.Message
        return $null
    }

    if (-not $raw) { return $null }

    $lines = ($raw -replace "`r", "") -split "`n"

    function Get-SectionLines {
        param(
            [string[]]$StartPatterns,
            [string[]]$StopPatterns
        )

        $startIndex = -1
        for ($i = 0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i].Trim()
            foreach ($pat in $StartPatterns) {
                if ($line -match $pat) {
                    $startIndex = $i
                    break
                }
            }
            if ($startIndex -ge 0) { break }
        }

        if ($startIndex -lt 0) { return @() }

        $items = @()

        for ($j = $startIndex + 1; $j -lt $lines.Count; $j++) {
            $current = $lines[$j].TrimEnd()
            $trimmed = $current.Trim()

            # blank line usually terminates the section once we have content
            if (-not $trimmed) {
                if ($items.Count -gt 0) { break }
                continue
            }

            foreach ($stop in $StopPatterns) {
                if ($trimmed -match $stop) {
                    return $items
                }
            }

            if ($trimmed -ne 'N/A' -and $trimmed -ne 'None') {
                $items += $trimmed
            }
        }

        return $items
    }

    $applied = Get-SectionLines `
        -StartPatterns @(
        '^Applied Group Policy Objects'
    ) `
        -StopPatterns @(
        '^The following GPOs were not applied because they were filtered out',
        '^The computer is a part of the following security groups',
        '^Computer Settings',
        '^User Settings'
    )

    $filtered = Get-SectionLines `
        -StartPatterns @(
        '^The following GPOs were not applied because they were filtered out'
    ) `
        -StopPatterns @(
        '^The computer is a part of the following security groups',
        '^Applied Group Policy Objects',
        '^Computer Settings',
        '^User Settings'
    )

    $securityGroups = Get-SectionLines `
        -StartPatterns @(
        '^The computer is a part of the following security groups'
    ) `
        -StopPatterns @(
        '^Applied Group Policy Objects',
        '^The following GPOs were not applied because they were filtered out',
        '^Computer Settings',
        '^User Settings'
    )

    return [pscustomobject]@{
        Raw            = $raw
        AppliedGpos    = $applied
        FilteredGpos   = $filtered
        SecurityGroups = $securityGroups
    }
}

# -----------------------------
#  Repair Steps
# -----------------------------
function Invoke-ChkdskScan {
    param([string]$Drive = 'C:')

    Invoke-Step -Name 'CHKDSK' -ScriptBlock {
        Invoke-LongRunningCommand `
            -Stage 'CHKDSK' `
            -FilePath 'chkdsk.exe' `
            -Arguments ("{0} /scan" -f $Drive)
    }
}

function Invoke-DismRestoreHealth {
    Invoke-Step -Name 'DISM' -ScriptBlock {

        $stage = 'DISM'

        # --- Step 1: Quick check ---
        Write-Log -Level INFO -Stage $stage -Message 'Running CheckHealth'

        $check = & dism.exe /Online /Cleanup-Image /CheckHealth 2>&1 | Out-String

        Write-Log -Level DEBUG -Stage $stage -Message 'DISM CheckHealth output' -Detail $check

        if ($check -match 'No component store corruption detected') {
            Write-Log -Level OK -Stage $stage -Message 'Image healthy - skipping RestoreHealth'
            return
        }

        if ($check -match 'The component store is not repairable') {
            Write-Log -Level ERROR -Stage $stage -Message 'Image is NOT repairable - skipping RestoreHealth'
            return
        }

        # --- Step 2: Deeper scan ---
        Write-Log -Level INFO -Stage $stage -Message 'Running ScanHealth'

        $scan = & dism.exe /Online /Cleanup-Image /ScanHealth 2>&1 | Out-String

        Write-Log -Level DEBUG -Stage $stage -Message 'DISM ScanHealth output' -Detail $s

        if ($scan -match 'No component store corruption detected') {
            Write-Log -Level OK -Stage $stage -Message 'No corruption found - skipping RestoreHealth'
            return
        }

        if ($scan -match 'The component store is not repairable') {
            Write-Log -Level ERROR -Stage $stage -Message 'ScanHealth reports NOT repairable - skipping RestoreHealth'
            return
        }

        # --- Step 3: Safe to run RestoreHealth ---
        Write-Log -Level WARN -Stage $stage -Message 'Corruption detected - running RestoreHealth'

        # Use progress-aware runner if available
        if (Get-Command Invoke-ProcessWithProgress -ErrorAction SilentlyContinue) {
            $exit = Invoke-ProcessWithProgress `
                -Stage $stage `
                -FilePath 'dism.exe' `
                -ArgumentList @('/Online', '/Cleanup-Image', '/RestoreHealth') `
                -ProgressPattern '(\d{1,3}(?:\.\d)?)%' `
                -HeartbeatSeconds 30 `
                -StallMinutes 10

            if ($exit -eq 0) {
                Write-Log -Level OK -Stage $stage -Message 'RestoreHealth completed'
            }
            else {
                Write-Log -Level WARN -Stage $stage -Message 'RestoreHealth returned non-zero' -Detail ('ExitCode={0}' -f $exit)
            }
        }
        else {
            # Fallback if progress runner is not present
            $restore = & dism.exe /Online /Cleanup-Image /RestoreHealth 2>&1 | Out-String

            if ($LASTEXITCODE -eq 0) {
                Write-Log -Level OK -Stage $stage -Message 'RestoreHealth completed'
            }
            else {
                Write-Log -Level WARN -Stage $stage -Message 'RestoreHealth returned non-zero' -Detail ('ExitCode={0}' -f $LASTEXITCODE)
            }
        }
    }
}


function Invoke-SfcScanNow {
    Invoke-Step -Name 'SFC' -ScriptBlock {

        # Capture the integer % from lines like: "Verification 42% complete."
        $progressPattern = 'Verification\s+(\d{1,3})%\s+complete'

        $exit = Invoke-ProcessWithProgress `
            -Stage 'SFC' `
            -FilePath 'sfc.exe' `
            -ArgumentList @('/scannow') `
            -ProgressPattern $progressPattern `
            -HeartbeatSeconds 30 `
            -StallMinutes 10

        # SFC exit codes vary; warn on non-zero
        if ($exit -ne 0) {
            Write-Log -Level WARN -Stage 'SFC' -Message 'SFC returned non-zero' -Detail ("ExitCode={0}" -f $exit)
        }
    }
}

function Invoke-GroupPolicyCleanup {
    Invoke-Step -Name 'GroupPolicyCleanup' -ScriptBlock {

        $stage = 'GroupPolicyCleanup'

        Write-Log -Level INFO -Stage $stage -Message 'Cleaning local Group Policy and SCCM remnants'

        # --- Stop ConfigMgr Client service (if present and running) ---
        try {
            $ccm = Get-Service -Name CcmExec -ErrorAction SilentlyContinue

            if ($ccm) {
                if ($ccm.Status -eq 'Running') {
                    Write-Log -Level INFO -Stage $stage -Message 'Stopping ConfigMgr client (CcmExec)'
                    Stop-Service -Name CcmExec -Force -ErrorAction SilentlyContinue
                }
                else {
                    Write-Log -Level DEBUG -Stage $stage -Message 'CcmExec already stopped'
                }
            }
        }
        catch {
            Write-Log -Level WARN -Stage $stage -Message 'Failed to stop CcmExec' -Detail $_.Exception.Message
        }

        # --- Paths to clean ---
        $PathsToRemove = @(
            "$env:SystemRoot\System32\GroupPolicy",
            "$env:SystemRoot\System32\GroupPolicyUsers",
            "$env:SystemRoot\CCM\Policy",
            "$env:SystemRoot\CCM\PolicyEval",
            "$env:SystemRoot\CCM\Cache"
        )

        foreach ($path in $PathsToRemove) {

            if (Test-Path $path) {
                Write-Log -Level INFO -Stage $stage -Message 'Cleaning path' -Detail $path
                Remove-PathSafe -Stage $stage -Path $path | Out-Null
            }
            else {
                Write-Log -Level DEBUG -Stage $stage -Message 'Path not present' -Detail $path
            }
        }

        # --- Restart ConfigMgr service if installed ---
        try {
            if ($ccm) {
                Write-Log -Level INFO -Stage $stage -Message 'Starting ConfigMgr client (CcmExec)'
                Start-Service -Name CcmExec -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-Log -Level WARN -Stage $stage -Message 'Failed to start CcmExec' -Detail $_.Exception.Message
        }

        # --- Force GP refresh ---
        Invoke-Cmd -Stage $stage -Description 'Group Policy update' -Command 'gpupdate /force' | Out-Null

        Write-Log -Level SUMMARY -Stage $stage -Message 'Group Policy and SCCM cleanup completed'
    }
}

function Invoke-WindowsUpdateReset {
    Invoke-Step -Name 'WindowsUpdateReset' -ScriptBlock {
        $stage = 'WindowsUpdateReset'

        $services = @('wuauserv', 'bits', 'cryptsvc')
        foreach ($svc in $services) { Stop-ServiceSafe -Stage $stage -Name $svc }

        $paths = @(
            "$env:windir\SoftwareDistribution",
            "$env:windir\System32\catroot2"
        )

        foreach ($p in $paths) { Remove-PathSafe -Stage $stage -Path $p | Out-Null }

        foreach ($svc in $services) { Start-ServiceSafe -Stage $stage -Name $svc }
    }
}

function Invoke-GPResultText {
    Invoke-Step -Name 'GPResultText' -ScriptBlock {

        $stage = 'GPResultText'

        Write-Log -Level INFO -Stage $stage -Message 'Running gpresult /r /scope computer'

        try {
            $raw = & gpresult.exe /r /scope computer 2>&1 | Out-String

            if ($raw) {
                Write-Log -Level DEBUG -Stage $stage -Message 'Raw GPResult (text)' -Detail $raw
            }
            else {
                Write-Log -Level WARN -Stage $stage -Message 'No output from gpresult text'
            }
        }
        catch {
            Write-Log -Level WARN -Stage $stage -Message 'gpresult text execution failed' -Detail $_.Exception.Message
        }
    }
}

function Invoke-GPResultReport {
    Invoke-Step -Name 'GPResult' -ScriptBlock {
        $stage = 'GPResult'

        try {
            # Output directory
            $outDir = $PSScriptRoot
            if (-not $outDir) { $outDir = (Get-Location).Path }

            $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            $fileName = 'GPResult_{0}.html' -f $timestamp
            $fullPath = Join-Path $outDir $fileName

            Write-Log -Level INFO -Stage $stage -Message 'Generating GPResult HTML report' -Detail ('Path={0}' -f $fullPath)

            # --- FIXED EXECUTION ---

            $proc = Start-Process -FilePath "gpresult.exe" `
                -ArgumentList @(
                "/h",
                $fullPath,
                "/scope",
                "computer",
                "/f"
            ) `
                -Wait `
                -PassThru `
                -WindowStyle Hidden



            # --- Exit code handling ---
            if ($proc.ExitCode -eq 0) {
                Write-Log -Level OK -Stage $stage -Message 'GPResult completed' -Detail ('ExitCode={0}' -f $proc.ExitCode)
            }
            else {
                Write-Log -Level WARN -Stage $stage -Message 'GPResult returned non-zero' -Detail ('ExitCode={0}' -f $proc.ExitCode)
            }

            # --- File validation + parsing ---
            if (Test-Path -LiteralPath $fullPath) {
                Write-Log -Level OK -Stage $stage -Message 'GPResult report created' -Detail ('Path={0}' -f $fullPath)

                $sum = Get-GPResultSummaryFromHtml -Path $fullPath

                if ($sum) {
                    $script:GPResultSummary = $sum

                    Write-Log -Level DEBUG -Stage $stage -Message 'GPResult parsed into summary object' -Detail (
                        'Applied={0}; Filtered={1}; Alerts={2}' -f `
                            $sum.AppliedGpos.Count,
                        $sum.FilteredGpos.Count,
                        $sum.Alerts.Count
                    )
                }
                else {
                    Write-Log -Level WARN -Stage $stage -Message 'GPResult report exists but parsing returned no data'
                }
            }
            else {
                Write-Log -Level WARN -Stage $stage -Message 'GPResult report not created'
            }
        }
        catch {
            Write-Log -Level ERROR -Stage $stage -Message 'GPResult execution failed' -Detail $_.Exception.Message
        }
    }
}


# -----------------------------
#  MAIN
# -----------------------------
$eventLabel = if ($EventScan -or $PSBoundParameters.ContainsKey('EventDays')) {
    if ($PSBoundParameters.ContainsKey('EventDays')) { $EventDays } else { 'Default(1)' }
} else {
    'Disabled'
}

Write-Log -Level INFO -Stage 'Startup' -Message 'Repair script starting' -Detail (
    'Quiet={0}; NoWU={1}; NetReset={2}; EventScan={3}; GPResult={4}; DeepWU={5}; Full={6}; CHKDSK={7}' -f `
    $Quiet,
    $NoWU,
    $NetReset,
    $eventLabel,
    $(if ($GPResult) { 'Enabled' } else { 'Disabled' }),
    $(if ($DeepWU) { 'Enabled' } else { 'Disabled' }),
    $(if ($Full) { 'Enabled' } else { 'Disabled' }),
    $(if ($SkipCHK) { 'Skipped' } else { 'Enabled' })
)

if (-not $SkipCHK) {
    Invoke-ChkdskScan
}
else {
    Write-Log -Level INFO -Stage 'CHKDSK' -Message 'Skipping CHKDSK scan (SkipCHK switch set)'
}

Invoke-DismRestoreHealth
Invoke-SfcScanNow
Invoke-GroupPolicyCleanup
if ($NetReset) {
    Write-Log -Level WARN -Stage 'NetworkReset' -Message 'Network reset is disruptive (VPN/adapters). Proceeding...'
    Invoke-NetworkReset
}
else {
    Write-Log -Level INFO -Stage 'NetworkReset' -Message 'Skipping network reset (NetReset switch not set)'
}

if (-not $NoWU) {

    Invoke-WindowsUpdateReset

    if ($DeepWU) {
        Invoke-AdvancedWUReset
    }
    else {
        Write-Log -Level INFO -Stage 'AdvancedWUReset' -Message 'Skipping advanced WU reset (DeepWU not set)'
    }
}

if ($EventScan -or $PSBoundParameters.ContainsKey('EventDays')) {
    # ✅ Use default if only switch supplied
    $daysToUse = if ($PSBoundParameters.ContainsKey('EventDays')) {
        $EventDays
    }
    else {
        1
    }
    Invoke-EventIntelligence -Days $daysToUse
}
else {
    Write-Log -Level INFO -Stage 'EventIntelligence' -Message 'Skipping event analysis (EventScan not set)'
}

# ✅ ALWAYS run lightweight text summary (fast)
Invoke-GPResultText

# ✅ Only run HTML report if requested
if ($GPResult) {
    Invoke-GPResultReport
}
else {
    Write-Log -Level INFO -Stage 'GPResult' -Message 'Skipping GPResult HTML report (GPResult switch not set)'
}

# --- GPResult Summary Output (if available) ---
if ($script:GPResultSummary -or $gpText) {

    $gp = $script:GPResultSummary

    $computerSafe = if ($gp.Computer) { $gp.Computer } else { 'Unknown' }
    $domainSafe = if ($gp.Domain) { $gp.Domain } else { 'Unknown' }
    $siteSafe = if ($gp.Site) { $gp.Site } else { 'Unknown' }
    $refreshSafe = if ($gp.LastComputerRefresh) { $gp.LastComputerRefresh } else { 'Unknown' }
    $dcSafe = if ($gp.DomainController) { $gp.DomainController } else { 'Unknown' }

    Write-Log -Level SUMMARY -Stage 'GPResultSummary' -Message 'Computer policy snapshot' -Detail (
        'Computer={0}; Domain={1}; Site={2}; LastRefresh={3}; DC={4}; Applied={5}; Filtered={6}; Alerts={7}; Report={8}' -f `
            $computerSafe,
        $domainSafe,
        $siteSafe,
        $refreshSafe,
        $dcSafe,
        $gp.AppliedGpos.Count,
        $gp.FilteredGpos.Count,
        $gp.Alerts.Count,
        $gp.ReportPath
    )

    $gpText = Get-GPResultTextSections

    if ($gpText) {
        foreach ($item in $gpText.AppliedGpos) {
            Write-Log -Level DEBUG -Stage 'GPResultSummary' -Message 'Applied GPO' -Detail $item
        }

        foreach ($item in $gpText.FilteredGpos) {
            Write-Log -Level DEBUG -Stage 'GPResultSummary' -Message 'Filtered GPO / Reason' -Detail $item
        }

        foreach ($item in $gpText.SecurityGroups) {
            Write-Log -Level DEBUG -Stage 'GPResultSummary' -Message 'Computer Security Group' -Detail $item
        }
    }
    else {
        Write-Log -Level DEBUG -Stage 'GPResultSummary' -Message 'gpresult /r /scope computer returned no parsable text sections'
    }

    # --- Existing "Top X" summary (keep this as your compact view) ---
    $topApplied = if ($gp.AppliedGpos -and $gp.AppliedGpos.Count -gt 0) {
        ($gp.AppliedGpos | Select-Object -First 8) -join "`r`n        "
    }
    else {
        'None'
    }

    $topFiltered = if ($gp.FilteredGpos -and $gp.FilteredGpos.Count -gt 0) {
        ($gp.FilteredGpos | Select-Object -First 8) -join "`r`n        "
    }
    else {
        'None'
    }

    $topAlerts = if ($gp.Alerts -and $gp.Alerts.Count -gt 0) {
        ($gp.Alerts | Select-Object -First 6) -join '; '
    }
    else {
        'None'
    }

    Write-Log -Level DEBUG -Stage 'GPResultSummary' -Message 'Top Applied GPOs'   -Detail $topApplied
    Write-Log -Level DEBUG -Stage 'GPResultSummary' -Message 'Top Filtered GPOs' -Detail $topFiltered
    Write-Log -Level DEBUG -Stage 'GPResultSummary' -Message 'Top Alerts'        -Detail $topAlerts

    if ($gp.DeniedHints -and $gp.DeniedHints.Count -gt 0) {
        Write-Log -Level DEBUG -Stage 'GPResultSummary' -Message 'Denied hints' -Detail (($gp.DeniedHints | Select-Object -First 6) -join '; ')
    }

    if ($gp.OU) {
        Write-Log -Level DEBUG -Stage 'GPResultSummary' -Message 'OU' -Detail $gp.OU
    }
}
else {
    Write-Log -Level DEBUG -Stage 'GPResultSummary' -Message 'No GPResult summary data available (report missing or parse failed)'
}

# --- Final Summary ---
$end = Get-Date
$duration = New-TimeSpan -Start $script:StartTime -End $end

if ($script:ErrorCount -gt 0) {
    $status = 'CompletedWithErrors'
}
elseif ($script:WarnCount -gt 0) {
    $status = 'CompletedWithWarnings'
}
else {
    $status = 'Success'
}

Write-Log -Level SUMMARY -Stage 'Summary' -Message 'Run complete' -Detail ('Status={0}; Warnings={1}; Errors={2}; Duration={3}' -f $status, $script:WarnCount, $script:ErrorCount, $duration.ToString())
Write-Log -Level DONE -Stage 'Finish' -Message 'Repair script completed'
if ($NoWU) {
    Write-Log -Level SUMMARY -Stage 'Config' -Message 'Windows Update reset was skipped (NoWU)'
}
