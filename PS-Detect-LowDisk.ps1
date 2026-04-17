<#
Detect-LowDisk.ps1
Intune Proactive Remediation - Detection
Returns exit 1 when disk space is below threshold (trigger remediation).
#>

$DriveLetter = "C:"
$MinFreeGB   = 70          # Trigger remediation if free space < 15 GB
$MinFreePct  = 10          # OR trigger if free space < 10% (set to 0 to disable)

try {
    $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$DriveLetter'"
    if (-not $disk) { 
        Write-Output "Disk $DriveLetter not found."
        exit 0
    }

    $freeBytes = [double]$disk.FreeSpace
    $sizeBytes = [double]$disk.Size

    if ($sizeBytes -le 0) {
        Write-Output "Disk $DriveLetter has invalid size."
        exit 0
    }

    $freeGB  = [math]::Round($freeBytes / 1GB, 2)
    $freePct = [math]::Round(($freeBytes / $sizeBytes) * 100, 2)

    Write-Output "Drive=$DriveLetter FreeGB=$freeGB FreePct=$freePct (Thresholds: <${MinFreeGB}GB OR <${MinFreePct}%)"

    $isLowGB  = ($freeGB -lt $MinFreeGB)
    $isLowPct = ($MinFreePct -gt 0 -and $freePct -lt $MinFreePct)

    if ($isLowGB -or $isLowPct) {
        Write-Output "LOW DISK SPACE detected - remediation required."
        exit 1
    } else {
        Write-Output "Disk space OK - remediation not required."
        exit 0
    }
}
catch {
    Write-Output "Detection error: $($_.Exception.Message)"
    exit 0
}