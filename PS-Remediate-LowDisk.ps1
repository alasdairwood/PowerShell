<#
Remediate-LowDisk.ps1
Intune Proactive Remediation - Remediation

Cleans:
- Temp folders (Windows + User profile temp locations visible to SYSTEM)
- Delivery Optimization cache
- Windows Update download cache (SoftwareDistribution\Download)
- Optional DISM component cleanup
- Optional prune CBS/DISM logs older than X days

Logging:
%ProgramData%\Microsoft\IntuneManagementExtension\Logs\DiskCleanup-Remediation.log
#>

# -------------------- CONFIG --------------------
$DriveLetter               = "C:"
$MinFreeGB                 = 15      # Only remediate if below this (GB)
$MinFreePct                = 10      # Or below this (%). Set 0 to disable.
$EnableDISMComponentClean  = $true   # DISM /StartComponentCleanup (safe)
$EnableResetBase           = $false  # WARNING: prevents uninstalling some updates
$PruneLogs                 = $true
$LogRetentionDays          = 14
$CleanupWindowsUpdateCache = $true
$CleanupDeliveryOptCache   = $true
$CleanupTempFolders        = $true

$LogPath = Join-Path $env:ProgramData "Microsoft\IntuneManagementExtension\Logs\DiskCleanup-Remediation.log"
# ------------------------------------------------

function Write-Log {
    param([string]$Message)
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "$timestamp`t$Message"
    Write-Output $line
    try { Add-Content -Path $LogPath -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
}

function Get-FreeSpaceInfo {
    param([string]$Drive = "C:")
    $d = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$Drive'"
    if (-not $d) { return $null }

    $freeBytes = [double]$d.FreeSpace
    $sizeBytes = [double]$d.Size
    if ($sizeBytes -le 0) { return $null }

    [pscustomobject]@{
        Drive    = $Drive
        FreeGB   = [math]::Round($freeBytes / 1GB, 2)
        FreePct  = [math]::Round(($freeBytes / $sizeBytes) * 100, 2)
        FreeBytes= $freeBytes
        SizeBytes= $sizeBytes
    }
}

function Remove-FilesSafe {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [switch] $Recurse
    )
    if (-not (Test-Path $Path)) { return 0 }

    $before = (Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue -Recurse:$Recurse |
               Measure-Object -Property Length -Sum).Sum
    try {
        if ($Recurse) {
            Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue | 
                Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
        } else {
            Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue |
                Remove-Item -Force -ErrorAction SilentlyContinue
        }
    } catch {}

    $after = (Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue -Recurse:$Recurse |
              Measure-Object -Property Length -Sum).Sum

    $before = [double]($before  | ForEach-Object { $_ } )
    $after  = [double]($after   | ForEach-Object { $_ } )

    $freed = [math]::Max(0, ($before - $after))
    return $freed
}

function Stop-Start-ServiceSafe {
    param(
        [Parameter(Mandatory)][string]$Name,
        [ValidateSet("Stop","Start")][string]$Action
    )
    try {
        $svc = Get-Service -Name $Name -ErrorAction Stop
        if ($Action -eq "Stop" -and $svc.Status -ne 'Stopped') {
            Stop-Service -Name $Name -Force -ErrorAction Stop
        }
        if ($Action -eq "Start" -and $svc.Status -ne 'Running') {
            Start-Service -Name $Name -ErrorAction Stop
        }
        return $true
    } catch {
        Write-Log "Service $Action failed for $Name : $($_.Exception.Message)"
        return $false
    }
}

# -------------------- START --------------------
Write-Log "=== Disk Cleanup Remediation started ==="

$beforeInfo = Get-FreeSpaceInfo -Drive $DriveLetter
if (-not $beforeInfo) {
    Write-Log "Could not get disk info for $DriveLetter. Exiting."
    exit 0
}

Write-Log "Before: Drive=$($beforeInfo.Drive) FreeGB=$($beforeInfo.FreeGB) FreePct=$($beforeInfo.FreePct)"

$isLowGB  = ($beforeInfo.FreeGB -lt $MinFreeGB)
$isLowPct = ($MinFreePct -gt 0 -and $beforeInfo.FreePct -lt $MinFreePct)

if (-not ($isLowGB -or $isLowPct)) {
    Write-Log "Disk space is above thresholds. No remediation required."
    exit 0
}

$totalFreedBytes = 0

# 1) Temp cleanup
if ($CleanupTempFolders) {
    Write-Log "Temp cleanup: starting..."

    $tempPaths = @(
        "$env:WINDIR\Temp",
        "$env:TEMP",
        "$env:TMP",
        "$env:LOCALAPPDATA\Temp", # under SYSTEM this will be system profile, still useful
        "C:\Windows\Logs\Temp"
    ) | Where-Object { $_ -and $_.Trim() -ne "" } | Select-Object -Unique

    foreach ($p in $tempPaths) {
        Write-Log "Temp cleanup: $p"
        $freed = Remove-FilesSafe -Path $p -Recurse
        $totalFreedBytes += $freed
        Write-Log ("Freed {0:N2} MB from {1}" -f ($freed/1MB), $p)
    }
}

# 2) Delivery Optimization cache
if ($CleanupDeliveryOptCache) {
    Write-Log "Delivery Optimization cache cleanup: starting..."
    try {
        # Cmdlet exists on most Win10/11 builds
        if (Get-Command Delete-DeliveryOptimizationCache -ErrorAction SilentlyContinue) {
            Delete-DeliveryOptimizationCache -Force -ErrorAction SilentlyContinue | Out-Null
            Write-Log "Delivery Optimization cache: Delete-DeliveryOptimizationCache executed."
        } else {
            # Fallback: remove common cache location
            $doCache = "C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache"
            $freed = Remove-FilesSafe -Path $doCache -Recurse
            $totalFreedBytes += $freed
            Write-Log ("Freed {0:N2} MB from DO cache fallback path" -f ($freed/1MB))
        }
    } catch {
        Write-Log "Delivery Optimization cleanup error: $($_.Exception.Message)"
    }
}

# 3) Windows Update cache (SoftwareDistribution\Download)
if ($CleanupWindowsUpdateCache) {
    Write-Log "Windows Update download cache cleanup: starting..."
    $sdDownload = Join-Path $env:windir "SoftwareDistribution\Download"

    # Stop services needed to release locks
    $servicesToStop = @("wuauserv","bits","dosvc")
    foreach ($s in $servicesToStop) { [void](Stop-Start-ServiceSafe -Name $s -Action Stop) }

    $freed = Remove-FilesSafe -Path $sdDownload -Recurse
    $totalFreedBytes += $freed
    Write-Log ("Freed {0:N2} MB from {1}" -f ($freed/1MB), $sdDownload)

    foreach ($s in $servicesToStop) { [void](Stop-Start-ServiceSafe -Name $s -Action Start) }
}

# 4) DISM component store cleanup
if ($EnableDISMComponentClean) {
    Write-Log "DISM component cleanup: starting..."
    try {
        $dismargs = "/Online /Cleanup-Image /StartComponentCleanup /Quiet"
        if ($EnableResetBase) {
            Write-Log "WARNING: ResetBase enabled. This can prevent uninstalling updates."
            $dismargs = "/Online /Cleanup-Image /StartComponentCleanup /ResetBase /Quiet"
        }
        $p = Start-Process -FilePath "dism.exe" -ArgumentList $dismargs -Wait -PassThru -WindowStyle Hidden
        Write-Log "DISM exit code: $($p.ExitCode)"
    } catch {
        Write-Log "DISM cleanup error: $($_.Exception.Message)"
    }
}

# 5) Prune CBS/DISM logs
if ($PruneLogs) {
    Write-Log "Log pruning: starting (older than $LogRetentionDays days)..."
    $cutoff = (Get-Date).AddDays(-$LogRetentionDays)

    $logPaths = @(
        "C:\Windows\Logs\CBS",
        "C:\Windows\Logs\DISM"
    )

    foreach ($lp in $logPaths) {
        if (Test-Path $lp) {
            try {
                $files = Get-ChildItem -Path $lp -File -Force -ErrorAction SilentlyContinue |
                         Where-Object { $_.LastWriteTime -lt $cutoff -and $_.Length -gt 0 }

                $bytes = ($files | Measure-Object -Property Length -Sum).Sum
                $files | Remove-Item -Force -ErrorAction SilentlyContinue
                $bytes = [double]($bytes | ForEach-Object { $_ })
                $totalFreedBytes += [math]::Max(0,$bytes)

                Write-Log ("Pruned logs in {0}. Freed approx {1:N2} MB" -f $lp, ($bytes/1MB))
            } catch {
                Write-Log "Log prune error in $lp : $($_.Exception.Message)"
            }
        }
    }
}

# -------------------- END --------------------
$afterInfo = Get-FreeSpaceInfo -Drive $DriveLetter
if ($afterInfo) {
    Write-Log "After:  Drive=$($afterInfo.Drive) FreeGB=$($afterInfo.FreeGB) FreePct=$($afterInfo.FreePct)"
    $reclaimedGB = [math]::Round(($afterInfo.FreeBytes - $beforeInfo.FreeBytes)/1GB, 2)
    Write-Log "Estimated reclaimed: $reclaimedGB GB (tracked cleanup bytes: $([math]::Round($totalFreedBytes/1GB,2)) GB)"
} else {
    Write-Log "After: Could not read disk info."
}

Write-Log "=== Disk Cleanup Remediation finished ==="
exit 0