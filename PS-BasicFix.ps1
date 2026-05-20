param(
    [switch]$DebugMode
)

# -----------------------------
#  Structured Logging (Colour)
# -----------------------------
$script:WarnCount  = 0
$script:ErrorCount = 0
$script:StartTime  = Get-Date

function Write-Log {
    param(
        [ValidateSet("INFO","OK","WARN","ERROR","DEBUG","DONE","SUMMARY")]
        [string]$Level,
        [string]$Stage,
        [string]$Message,
        [string]$Detail = ""
    )

    if ($Level -eq "DEBUG" -and -not $DebugMode) { return }

    switch ($Level) {
        "INFO"    { $color = "Cyan" }
        "OK"      { $color = "Green" }
        "WARN"    { $color = "Yellow" }
        "ERROR"   { $color = "Red" }
        "DEBUG"   { $color = "DarkGray" }
        "DONE"    { $color = "Green" }
        "SUMMARY" { $color = "Magenta" }
        default   { $color = "White" }
    }

    if ($Level -eq "WARN")  { $script:WarnCount++ }
    if ($Level -eq "ERROR") { $script:ErrorCount++ }

    $ts = (Get-Date).ToString("HH:mm:ss")
    $line = "{0} | Time={1} | Stage={2} | Message={3}" -f $Level, $ts, $Stage, $Message
    if ($Detail) { $line += " | Detail=$Detail" }

    Write-Host $line -ForegroundColor $color
}

# -----------------------------
#  Elevation check
# -----------------------------
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal] $identity
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Log -Level ERROR -Stage "Startup" -Message "Script must be run as Administrator."
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
    Write-Log -Level INFO -Stage $Name -Message "Starting"

    try {
        & $ScriptBlock
        $sw.Stop()
        Write-Log -Level OK -Stage $Name -Message "Completed" -Detail ("DurationMs={0}" -f $sw.ElapsedMilliseconds)
    }
    catch {
        $sw.Stop()
        Write-Log -Level ERROR -Stage $Name -Message "Unhandled exception" -Detail $_.Exception.Message
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

    # cmd.exe won't throw on non-zero exit; we check $LASTEXITCODE
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

# Robust delete helper: prefers RD (more tolerant of broken child paths than Remove-Item)
function Remove-PathSafe {
    param(
        [string]$Stage,
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Log -Level DEBUG -Stage $Stage -Message "Path not present (skipped)" -Detail ("Path={0}" -f $Path)
        return $true
    }

    Write-Log -Level INFO -Stage $Stage -Message "Removing path" -Detail ("Path={0}" -f $Path)

    try {
        cmd.exe /c "rd /s /q `"$Path`"" 1>$null 2>$null

        if (-not (Test-Path -LiteralPath $Path)) {
            Write-Log -Level OK -Stage $Stage -Message "Removed path" -Detail ("Path={0}" -f $Path)
            return $true
        }
        else {
            Write-Log -Level WARN -Stage $Stage -Message "Path still present after delete attempt" -Detail ("Path={0}" -f $Path)
            return $false
        }
    }
    catch {
        Write-Log -Level WARN -Stage $Stage -Message "Failed to remove path" -Detail $_.Exception.Message
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
            Write-Log -Level INFO -Stage $Stage -Message "Stopping service" -Detail ("Service={0}" -f $Name)
            Stop-Service -Name $Name -Force -ErrorAction Stop
            Write-Log -Level OK -Stage $Stage -Message "Service stopped" -Detail ("Service={0}" -f $Name)
        }
        else {
            Write-Log -Level DEBUG -Stage $Stage -Message "Service already stopped" -Detail ("Service={0}" -f $Name)
        }
    }
    catch {
        Write-Log -Level WARN -Stage $Stage -Message "Could not stop service" -Detail ("Service={0}; Error={1}" -f $Name, $_.Exception.Message)
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
            Write-Log -Level INFO -Stage $Stage -Message "Starting service" -Detail ("Service={0}" -f $Name)
            Start-Service -Name $Name -ErrorAction Stop
            Write-Log -Level OK -Stage $Stage -Message "Service started" -Detail ("Service={0}" -f $Name)
        }
        else {
            Write-Log -Level DEBUG -Stage $Stage -Message "Service already running" -Detail ("Service={0}" -f $Name)
        }
    }
    catch {
        Write-Log -Level WARN -Stage $Stage -Message "Could not start service" -Detail ("Service={0}; Error={1}" -f $Name, $_.Exception.Message)
    }
}

# -----------------------------
#  Repair Steps
# -----------------------------
function Invoke-ChkdskScan {
    param([string]$Drive = "C:")

    Invoke-Step -Name "CHKDSK" -ScriptBlock {
        # Non-disruptive scan (does not schedule a reboot)
        Invoke-Cmd -Stage "CHKDSK" -Description ("CHKDSK scan on {0}" -f $Drive) -Command ("chkdsk {0} /scan" -f $Drive) | Out-Null
    }
}

function Invoke-DismRestoreHealth {
    Invoke-Step -Name "DISM" -ScriptBlock {
        # DISM failures are meaningful; treat non-zero as ERROR (but continue script)
        Invoke-Cmd -Stage "DISM" -Description "DISM RestoreHealth" -Command "DISM.exe /Online /Cleanup-Image /RestoreHealth" -TreatNonZeroAsError | Out-Null
    }
}

function Invoke-SfcScanNow {
    Invoke-Step -Name "SFC" -ScriptBlock {
        # SFC can return non-zero even when it repaired items; treat as WARN to avoid false “hard fail”
        Invoke-Cmd -Stage "SFC" -Description "SFC ScanNow" -Command "sfc /scannow" | Out-Null
    }
}

function Invoke-GroupPolicyReset {
    Invoke-Step -Name "GroupPolicyReset" -ScriptBlock {
        $stage = "GroupPolicyReset"
        $gpPaths = @(
            "$env:windir\System32\GroupPolicy",
            "$env:windir\System32\GroupPolicyUsers"
        )

        foreach ($p in $gpPaths) {
            Remove-PathSafe -Stage $stage -Path $p | Out-Null
        }

        # gpupdate: treat non-zero as WARN (policy refresh can still partially succeed)
        Invoke-Cmd -Stage $stage -Description "GPUpdate /force" -Command "gpupdate /force" | Out-Null
    }
}

function Invoke-WindowsUpdateReset {
    Invoke-Step -Name "WindowsUpdateReset" -ScriptBlock {
        $stage = "WindowsUpdateReset"
        $services = @("wuauserv","bits","cryptsvc")

        foreach ($svc in $services) { Stop-ServiceSafe -Stage $stage -Name $svc }

        $paths = @(
            "$env:windir\SoftwareDistribution",
            "$env:windir\System32\catroot2"
        )

        foreach ($p in $paths) {
            # This is the hardened delete you wanted (RD /S /Q), tolerant of broken paths
            Remove-PathSafe -Stage $stage -Path $p | Out-Null
        }

        foreach ($svc in $services) { Start-ServiceSafe -Stage $stage -Name $svc }
    }
}

# -----------------------------
#  MAIN
# -----------------------------
Write-Log -Level INFO -Stage "Startup" -Message "Repair script starting" -Detail ("DebugMode={0}" -f $DebugMode)

Invoke-ChkdskScan -Drive "C:"
Invoke-DismRestoreHealth
Invoke-SfcScanNow
Invoke-GroupPolicyReset
Invoke-WindowsUpdateReset

$end = Get-Date
$duration = New-TimeSpan -Start $script:StartTime -End $end
$status = if ($script:ErrorCount -gt 0) { "CompletedWithErrors" } elseif ($script:WarnCount -gt 0) { "CompletedWithWarnings" } else { "Success" }

Write-Log -Level SUMMARY -Stage "Summary" -Message "Run complete" -Detail ("Status={0}; Warnings={1}; Errors={2}; Duration={3}" -f $status, $script:WarnCount, $script:ErrorCount, $duration.ToString())
Write-Log -Level DONE -Stage "Finish" -Message "Repair script completed"