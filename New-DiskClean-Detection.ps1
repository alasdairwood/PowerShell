<#
.SYNOPSIS
    Detection script for Intune remediation (AppData + system cleanup)

.DESCRIPTION
    Triggers remediation when:
    - SCCM cache is large (>2GB)
    - Windows Temp is large (>2GB)
    - MEMORY.DMP exists and is stale (>7 days old)

    Designed for low overhead in Intune detection cycles.
#>

# -----------------------------
# Thresholds
# -----------------------------

$SCCMSizeThresholdBytes   = 2GB
$TempSizeThresholdBytes   = 2GB
$DumpAgeDays              = 7

$Now = Get-Date
$DumpCutoff = $Now.AddDays(-$DumpAgeDays)

# -----------------------------
# 1. SCCM Cache Size Check
# -----------------------------

try {

    $CCMCachePath = "C:\Windows\ccmcache"

    if (Test-Path $CCMCachePath) {

        $CCMSize = (
            Get-ChildItem -LiteralPath $CCMCachePath -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { -not $_.PSIsContainer } |
            Measure-Object Length -Sum
        ).Sum

        if ($CCMSize -and $CCMSize -gt $SCCMSizeThresholdBytes) {
            Write-Output "Detection: SCCM cache exceeds threshold ($([math]::Round($CCMSize/1GB,2)) GB)"
            exit 1
        }
    }
}
catch { }

# -----------------------------
# 2. Windows Temp Size Check
# -----------------------------

try {

    $TempPath = "C:\Windows\Temp"

    if (Test-Path $TempPath) {

        $TempSize = (
            Get-ChildItem -LiteralPath $TempPath -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { -not $_.PSIsContainer } |
            Measure-Object Length -Sum
        ).Sum

        if ($TempSize -and $TempSize -gt $TempSizeThresholdBytes) {
            Write-Output "Detection: Windows Temp exceeds threshold ($([math]::Round($TempSize/1GB,2)) GB)"
            exit 1
        }
    }
}
catch { }

# -----------------------------
# 3. MEMORY.DMP Age Check
# -----------------------------

try {

    $DumpPath = "C:\Windows\MEMORY.DMP"

    if (Test-Path $DumpPath) {

        $Dump = Get-Item $DumpPath -ErrorAction SilentlyContinue

        if ($Dump -and $Dump.LastWriteTime -lt $DumpCutoff) {
            Write-Output "Detection: MEMORY.DMP older than $DumpAgeDays days"
            exit 1
        }
    }
}
catch { }

# -----------------------------
# No remediation needed
# -----------------------------

Write-Output "Detection: No cleanup required"
exit 0