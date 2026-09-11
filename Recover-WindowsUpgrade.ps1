<#
.SYNOPSIS
Safely recovers a Windows device after a failed Windows Installation Assistant or feature upgrade attempt.

.DESCRIPTION
This script performs a controlled cleanup and recovery of Windows Update and setup components following a 
failed or incomplete Windows upgrade (e.g. Windows 10 → Windows 11 via Installation Assistant).

It is designed to:
- Detect and remove failed upgrade artefacts (e.g. $WINDOWS.~BT, $WINDOWS.~WS)
- Safely reset Windows Update components
- Repair system integrity using DISM and SFC
- Restore update services to a clean operational state

The script prioritises safety by:
- Avoiding destructive servicing actions
- Validating service state before cleanup
- Supporting -WhatIf for dry-run execution
- Providing structured error handling with actionable diagnostics

.PARAMETER WhatIf
Simulates all actions without making changes.
Recommended for first run and validation.

.PARAMETER DeepClean
Performs additional cleanup of temporary setup locations such as:
- C:\Windows\Panther
- C:\Windows\Temp

Use only when standard recovery does not resolve upgrade issues.

.PARAMETER SkipDISM
Skips DISM /RestoreHealth step.
Useful if network access or source repair is restricted.

.PARAMETER SkipSFC
Skips System File Checker (sfc /scannow).

.EXAMPLE
.\Recover-WindowsUpgrade.ps1 -WhatIf

Runs the script in simulation mode with no changes applied.

.EXAMPLE
.\Recover-WindowsUpgrade.ps1

Performs full safe recovery.

.EXAMPLE
.\Recover-WindowsUpgrade.ps1 -DeepClean

Performs recovery with extended cleanup for stubborn upgrade failures.

.NOTES
Author: Enterprise IT Support
Environment: PowerShell 5.1 compatible
Use Case: Failed Windows Installation Assistant / Feature Update remediation

Recommended workflow:
1. Run with -WhatIf
2. Execute without -WhatIf
3. Reboot device
4. Re-attempt upgrade

.LINK
Internal: Windows Update Recovery Runbook
#>

# --- Windows Upgrade Recovery (Safe Mode) ---
param(
    [switch]$WhatIf,
    [switch]$DeepClean,     # Optional: removes more logs/cache
    [switch]$SkipDISM,
    [switch]$SkipSFC,
    [switch]$ScanAndInstallUpdates,
    [switch]$AutoRebootAfterUpdates,
    [switch]$Help
)

# --- Help / Usage ---
if ($Help -or $args -contains '/?' -or $args -contains '-?' -or $args -contains '--help') {

    Write-Host ''
    Write-Host 'Recover-WindowsUpgrade.ps1 - Available switches:' -ForegroundColor Cyan
    Write-Host ''

    Write-Host '  -WhatIf        Run in simulation mode (no changes made)'
    Write-Host '  -DeepClean     Perform extended cleanup (Panther, Temp)'
    Write-Host '  -SkipDISM      Skip DISM repair step'
    Write-Host '  -SkipSFC       Skip System File Checker'
    Write-Host ''

    Write-Host 'Behaviour:' -ForegroundColor Yellow
    Write-Host '  - Detects failed upgrade remnants ($WINDOWS.~BT / $WINDOWS.~WS)'
    Write-Host '  - Cleans setup files safely'
    Write-Host '  - Resets Windows Update components (safe delete mode)'
    Write-Host '  - Runs DISM + SFC (unless skipped)'
    Write-Host '  - Restarts update services cleanly'
    Write-Host ''

    Write-Host 'Examples:' -ForegroundColor Yellow
    Write-Host '  .\Recover-WindowsUpgrade.ps1'
    Write-Host '  .\Recover-WindowsUpgrade.ps1 -WhatIf'
    Write-Host '  .\Recover-WindowsUpgrade.ps1 -DeepClean'
    Write-Host '  .\Recover-WindowsUpgrade.ps1 -SkipDISM -SkipSFC'
    Write-Host ''
    
    Write-Host '  -ScanAndInstallUpdates     Trigger native Windows Update scan/install (silent)'

    Write-Host 'Recommended workflow:' -ForegroundColor Yellow
    Write-Host '  1. Run with -WhatIf to validate'
    Write-Host '  2. Run without -WhatIf to remediate'
    Write-Host '  3. Reboot device'
    Write-Host '  4. Retry upgrade'
    Write-Host ''

    return
}

# --- Logging ---
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    Write-Output ("[{0}] {1}" -f $Level, $Message)
}

# --- Safe executor with full diagnostics ---
function Invoke-Safe {
    param(
        [scriptblock]$Script,
        [string]$Action
    )

    try {
        & $Script
    }
    catch {
        $err = $_
        $line = $err.InvocationInfo.ScriptLineNumber
        $cmd = $err.InvocationInfo.Line
        $msg = $err.Exception.Message
        $type = $err.Exception.GetType().FullName

        Write-Output ("ERROR | Action={0} | Msg={1} | Type={2} | Line={3} | Command={4}" -f `
                $Action, $msg, $type, $line, $cmd)
    }
}

$rebootRequired = $false
$regPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
)

foreach ($path in $regPaths) {
    if (Test-Path $path) {
        $rebootRequired = $true
    }
}

if ($rebootRequired) {
    Write-Output "WARN | Pending reboot detected - cleanup may be incomplete until reboot"
    $script:NeedsReboot = $true
}

# --- Stop services (unified hardened method) ---
$services = @("wuauserv", "bits", "cryptsvc", "msiserver")

Write-Log "Stopping update services (hardened unified mode)..."

foreach ($svc in $services) {

    Invoke-Safe -Action "Stop service $svc" -Script {

        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue

        if ($s -and $s.Status -ne "Stopped") {

            # Attempt graceful stop
            Stop-Service $svc -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2

            $s.Refresh()

            # If still not stopped → force kill process
            if ($s.Status -ne "Stopped") {

                $svcObj = Get-WmiObject Win32_Service | Where-Object { $_.Name -eq $svc }

                if ($svcObj -and $svcObj.ProcessId -ne 0) {
                    Stop-Process -Id $svcObj.ProcessId -Force -ErrorAction SilentlyContinue
                }

                Start-Sleep -Seconds 2
                $s.Refresh()
            }

            # Final validation (important)
            if ($s.Status -ne "Stopped") {
                throw "$svc could not be stopped"
            }
        }
    }
    Write-Output ("OK | {0} stopped" -f $svc)
}

Write-Output "OK | All update services stopped (verified)"

# --- Detect failed install remnants ---
$paths = @(
    'C:\$WINDOWS.~BT',
    'C:\$WINDOWS.~WS',
    'C:\$GetCurrent',
    'C:\$WinREAgent'
)

$found = $false
foreach ($p in $paths) {
    if (Test-Path $p) {
        Write-Log "Found leftover upgrade folder: $p" "WARN"
        $found = $true
    }
}

if (-not $found) {
    Write-Log "No failed install artifacts detected"
}

# --- Cleanup upgrade folders (Robust) ---
Write-Log "Cleaning upgrade remnants (robust mode)..."

# Tracks whether another reboot/run is likely required
$script:NeedsReboot = $false

function Invoke-DeleteWithProgress {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    Write-Log "Deleting $Path..."

    $job = Start-Job -ScriptBlock {
        param($p)
        cmd /c "rd /s /q `"$p`""
    } -ArgumentList $Path

    $spinner = @('|', '/', '-', '\')
    $i = 0
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    while ($job.State -eq 'Running') {
        $elapsed = '{0:mm\:ss}' -f $sw.Elapsed
        $line = "[WORKING] Removing {0} {1} {2}" -f $Path, $spinner[$i % $spinner.Count], $elapsed
        Write-Host -NoNewline ("`r{0}{1}" -f $line, (' ' * 10))
        Start-Sleep -Milliseconds 250
        $i++
        $job = Get-Job -Id $job.Id
    }

    $sw.Stop()

    Receive-Job -Id $job.Id -ErrorAction SilentlyContinue | Out-Null
    Remove-Job -Id $job.Id -Force -ErrorAction SilentlyContinue

    Write-Host ("`r[COMPLETE] Removal finished: {0} ({1:mm\:ss})                    " -f $Path, $sw.Elapsed)
}

$paths = @(
    'C:\$WINDOWS.~BT',
    'C:\$WINDOWS.~WS',
    'C:\$GetCurrent',
    'C:\$WinREAgent'
)

$found = $false
foreach ($p in $paths) {
    if (Test-Path $p) {
        Write-Log "Found leftover upgrade folder: $p" "WARN"
        $found = $true
    }
}

if (-not $found) {
    Write-Log "No failed install artifacts detected"
}

# Process WinREAgent last
$orderedPaths = $paths | Sort-Object { if ($_ -like '*WinREAgent*') { 1 } else { 0 } }

foreach ($p in $orderedPaths) {

    if (Test-Path $p) {

        Write-Log "Processing $p" "WARN"

        Invoke-Safe -Action "Force remove $p (fast mode)" -Script {

            # Re-check inside block in case Windows cleaned it up after detection
            if (-not (Test-Path $p)) {
                return
            }

            if (-not $WhatIf) {

                # Kill common upgrade/setup locking processes
                $procs = @('SetupHost', 'CompatTelRunner', 'MoUsoCoreWorker')
                foreach ($proc in $procs) {
                    Get-Process -Name $proc -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
                }

                # Fast top-level ownership and ACL fix
                takeown /f $p /a | Out-Null
                icacls $p /grant Administrators:F /c | Out-Null

                # Remove attributes
                cmd /c "attrib -r -s -h `"$p`" /s /d" | Out-Null

                # Progress-aware delete
                Invoke-DeleteWithProgress -Path $p
            }
        }

        if (Test-Path $p) {
            Write-Output "WARN | Locked or protected: $p (reboot may be required)"
            $script:NeedsReboot = $true
        }
        else {
            Write-Output "OK | Removed: $p"
        }
    }
}

# --- Reset Windows Update cache (Safe Delete Mode) ---
Write-Log "Resetting Windows Update components (safe delete mode)..."

Invoke-Safe -Action "Reset SoftwareDistribution (robocopy purge)" -Script {

    $sd = 'C:\Windows\SoftwareDistribution'

    if (Test-Path $sd) {

        # Validate required services are stopped before touching SoftwareDistribution
        $requiredStopped = @('wuauserv', 'bits')
        foreach ($svcName in $requiredStopped) {
            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -ne 'Stopped') {
                throw "$svcName is not stopped - refusing to reset SoftwareDistribution"
            }
        }

        if (-not $WhatIf) {

            # Create empty temp folder for robocopy mirror purge
            $empty = Join-Path $env:TEMP 'empty_wu'
            if (-not (Test-Path $empty)) {
                New-Item -ItemType Directory -Path $empty -Force | Out-Null
            }

            Write-Log "Purging SoftwareDistribution contents..."
            robocopy $empty $sd /MIR | Out-Null

            # Remove folder after purge (Windows will recreate it)
            Remove-Item $sd -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    if (Test-Path $sd) {
        Write-Output "WARN | SoftwareDistribution still present after reset"
    }
    else {
        Write-Output "OK | SoftwareDistribution reset completed"
    }
}

Invoke-Safe -Action "Remove Catroot2 contents" -Script {

    $cr = 'C:\Windows\System32\catroot2'
    $timestamp = Get-Date -Format yyyyMMddHHmmss
    $backup = "C:\Windows\System32\catroot2.bak_$timestamp"
    $empty = Join-Path $env:TEMP 'empty_catroot2'

    if (-not (Test-Path $cr)) {
        Write-Output "OK | Catroot2 folder not present"
        return
    }

    # --- Safety gate: cryptsvc must be stopped ---
    $svc = Get-Service -Name 'cryptsvc' -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne 'Stopped') {
        throw "cryptsvc is not stopped - refusing to clean catroot2"
    }

    if ($WhatIf) {
        Write-Output "INFO | WhatIf active - catroot2 3-layer reset not executed"
        return
    }

    $layerSucceeded = $false

    # =========================================================
    # Layer 1: Try standard content clean
    # =========================================================
    Write-Log "Catroot2 Layer 1: standard content clean..."

    try {
        # Ownership / ACL / attributes first (helps with stubborn cases)
        takeown /f $cr /a /r | Out-Null
        icacls $cr /grant Administrators:F /t /c | Out-Null
        cmd /c "attrib -r -s -h `"$cr`" /s /d" | Out-Null

        # Delete contents only, preserve folder
        Get-ChildItem -Path $cr -Force -ErrorAction Stop | ForEach-Object {
            Remove-Item $_.FullName -Recurse -Force -ErrorAction Stop
        }

        $remaining = @(Get-ChildItem -Path $cr -Force -ErrorAction SilentlyContinue)
        if ($remaining.Count -eq 0) {
            Write-Output "OK | Catroot2 contents cleared (Layer 1)"
            $layerSucceeded = $true
        }
        else {
            Write-Output "WARN | Catroot2 still contains items after Layer 1"
        }
    }
    catch {
        Write-Output ("WARN | Catroot2 Layer 1 failed: {0}" -f $_.Exception.Message)
    }

    # =========================================================
    # Layer 2: Robocopy purge if Layer 1 did not clear it
    # =========================================================
    if (-not $layerSucceeded) {

        Write-Log "Catroot2 Layer 2: robocopy purge..."

        try {
            if (-not (Test-Path $empty)) {
                New-Item -ItemType Directory -Path $empty -Force | Out-Null
            }

            # /MIR mirrors empty folder into catroot2 (purges contents, preserves root)
            robocopy $empty $cr /MIR | Out-Null

            $remaining = @(Get-ChildItem -Path $cr -Force -ErrorAction SilentlyContinue)
            if ($remaining.Count -eq 0) {
                Write-Output "OK | Catroot2 contents cleared (Layer 2 robocopy purge)"
                $layerSucceeded = $true
            }
            else {
                Write-Output "WARN | Catroot2 still contains items after Layer 2"
            }
        }
        catch {
            Write-Output ("WARN | Catroot2 Layer 2 failed: {0}" -f $_.Exception.Message)
        }
    }

    # =========================================================
    # Layer 3: Rename folder if contents still resist cleanup
    # =========================================================
    if (-not $layerSucceeded) {

        Write-Log "Catroot2 Layer 3: rename fallback..."

        try {
            Rename-Item -Path $cr -NewName ("catroot2.bak_" + $timestamp) -ErrorAction Stop

            if (-not (Test-Path $cr) -and (Test-Path $backup)) {
                Write-Output ("OK | Catroot2 renamed for rebuild: {0}" -f $backup)
                $layerSucceeded = $true
            }
            else {
                Write-Output "WARN | Catroot2 rename did not fully verify"
            }
        }
        catch {
            Write-Output ("WARN | Catroot2 Layer 3 failed: {0}" -f $_.Exception.Message)
        }
    }

    # =========================================================
    # Final result
    # =========================================================
    if (-not $layerSucceeded) {
        Write-Output "WARN | Catroot2 could not be fully reset - reboot may be required"
        $script:NeedsReboot = $true
    }
}

# --- Optional deeper cleanup ---
if ($DeepClean) {
    Write-Log "Running DeepClean..." "WARN"

    $extra = @(
        'C:\Windows\Panther',
        'C:\Windows\Temp'
    )

    foreach ($p in $extra) {
        if (Test-Path $p) {
            Invoke-Safe -Action "Clean $p" -Script {
                if (-not (Test-Path $p)) {
                    return
                }

                if (-not $WhatIf) {
                    Get-ChildItem -Path $p -Force -ErrorAction SilentlyContinue | ForEach-Object {
                        Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }
            }
        }
    }
}

if ($script:NeedsReboot) {
    Write-Output "ACTION | Reboot recommended before re-running cleanup or retrying upgrade"
}

# --- Restart update services ---
Write-Log "Restarting update services..."

$services = @("wuauserv", "bits", "cryptsvc", "msiserver")

foreach ($svc in $services) {

    Invoke-Safe -Action "Start service $svc" -Script {

        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue

        if ($s -and $s.Status -ne "Running") {

            Start-Service -Name $svc -ErrorAction SilentlyContinue

            Start-Sleep -Seconds 1

            $s.Refresh()

            if ($s.Status -ne "Running") {
                throw "$svc failed to start"
            }
        }
    }
}

Write-Output "OK | Update services restarted"
if ($script:NeedsReboot) {
    Write-Output "INFO | Some components may fully recover after reboot"
}

# --- Repair image ---
if (-not $SkipDISM) {
    Write-Log "Running DISM RestoreHealth..."
    Invoke-Safe -Action "DISM Repair" -Script {
        if (-not $WhatIf) {
            DISM /Online /Cleanup-Image /RestoreHealth
        }
    }
}

# --- SFC ---
if (-not $SkipSFC) {
    Write-Log "Running SFC..."
    Invoke-Safe -Action "SFC Scan" -Script {
        if (-not $WhatIf) {
            sfc /scannow
        }
    }
}

# --- Restart services ---
Write-Log "Restarting services..."
foreach ($svc in $services) {
    Invoke-Safe -Action "Start service $svc" -Script {
        Get-Service -Name $svc | Where-Object { $_.Status -ne "Running" } | Start-Service
    }
}

function Invoke-NativeWindowsUpdate {
    Write-Log "Starting native Windows Update scan/install..."

    Invoke-Safe -Action "Trigger Windows Update (scan/install)" -Script {
        if (-not $WhatIf) {
            # Trigger full cycle
            cmd /c "usoclient StartScan"
            Start-Sleep -Seconds 5
            cmd /c "usoclient StartDownload"
            Start-Sleep -Seconds 5
            cmd /c "usoclient StartInstall"
        }
    }

    Write-Output "INFO | Windows Update scan/install triggered (runs silently in background)"

    # Optional: open UI for visibility
    Invoke-Safe -Action "Open Windows Update UI" -Script {
        if (-not $WhatIf) {
            Start-Process "ms-settings:windowsupdate"
        }
    }

    Write-Output "INFO | Use Settings UI or logs to monitor progress"
}


Invoke-Safe -Action "Reinitialise Windows Update components" -Script {
    if (-not $WhatIf) {
        cmd /c "net stop wuauserv" | Out-Null
        cmd /c "net start wuauserv" | Out-Null
    }
}

$remaining = $paths | Where-Object { Test-Path $_ }
if ($remaining.Count -gt 0) {
    Write-Output ("WARN | Remaining upgrade artefacts: {0}" -f ($remaining -join ', '))
    $script:NeedsReboot = $true
}
else {
    Write-Output "OK | All upgrade artefacts cleared"
}

Write-Log "Validating Windows Update state..."
$testWU = Get-Service wuauserv -ErrorAction SilentlyContinue
if ($testWU.Status -eq "Running") {
    Write-Output "OK | Windows Update service running"
}
else {
    Write-Output "WARN | Windows Update service not running"
}

# --- Optional Windows Update scan/install stage ---
if ($ScanAndInstallUpdates) {
    Invoke-NativeWindowsUpdate
}

# --- Final status ---
Write-Host "===== SUMMARY =====" -ForegroundColor Cyan

if ($script:NeedsReboot) {
    Write-Output "STATUS | Remediation incomplete until reboot"
}
else {
    Write-Output "STATUS | Remediation completed successfully"
}