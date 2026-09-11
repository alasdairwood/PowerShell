<#
.SYNOPSIS
  Troubleshoot why Windows 11 Feature Update is not being offered.

.DESCRIPTION
  Modular, PS 5.1-safe, copy/paste-safe troubleshooting script.

  Includes checks for:
    - Policy & state registry keys (WindowsUpdate + UX pause + scan source)
    - Effective MDM PolicyManager Update settings
    - Hardware baseline signals (RAM/Storage/TPM/Secure Boot/UEFI/GPT)
    - OS baseline (Win10 2004+ build check)
    - CPU support heuristic (non-authoritative; flags likely unsupported generations)
    - Compatibility Appraiser task status (best-effort)
    - Upgrade Experience Indicators (Gated* values)
    - Windows Update service health
    - Windows Update client event log recency + last error (best-effort)

  Output:
    - Top banner summary (single-device mode)
    - Wide fixed-width columns (less truncation)
    - Computer column hidden automatically for single-device mode
    - Troubleshooting summary restored
    - Global error trap prints message + line + code

.NOTES
  - Remote CIM/WinRM is often blocked in enterprise estates. This script degrades gracefully.
  - CPU support is a heuristic only; it does NOT represent Microsoft's official supported CPU list.

.EXAMPLE
  powershell -executionpolicy bypass -file .\Get-Win11UpdateRegistryMap.ps1

.EXAMPLE
  .\Get-Win11UpdateRegistryMap.ps1 -OnlyProblems

.EXAMPLE
  .\Get-Win11UpdateRegistryMap.ps1 -ComputerList (Get-Content .\pcs.txt) -CsvPath .\WU-Win11-Troubleshoot.csv
#>

[CmdletBinding()]
param(
  [string]$ComputerName = $env:COMPUTERNAME,
  [string[]]$ComputerList,

  [switch]$IncludeMissing = $true,
  [switch]$OnlyProblems = $false,
  [switch]$NoColor = $false,

  [string]$CsvPath,
 
  [switch]$PassThru,
  [switch]$Quiet,
  [switch]$Detailed,

  [switch]$Help
)

# --- Help / Usage ---
if ($Help -or $args -contains '/?' -or $args -contains '-?') {

  Write-Host ''
  Write-Host 'Get-Win11UpdateRegistryMap.ps1 - Windows 11 Upgrade Diagnostics Tool' -ForegroundColor Cyan
  Write-Host ''
  Write-Host 'This tool analyses Windows Update, policy, hardware, and compatibility signals'
  Write-Host 'to determine why a Windows 11 upgrade is not being offered or installed.'
  Write-Host ''

  Write-Host 'GENERAL:'
  Write-Host '  -ComputerName <name>     Target a single computer (default = local)'
  Write-Host '  -ComputerList <file>     File containing list of computers'
  #Write-Host '  -PassThru                Output objects to pipeline for filtering/export'
  #Write-Host '  -Quiet                   Suppress DEBUG/INFO output' #unfinished
  Write-Host ''

  #Write-Host 'DIAGNOSTICS (core functions):'
  #Write-Host '  (Enabled by default unless suppressed)'
  #Write-Host '  -CheckUpgrade           Evaluate Windows 11 readiness and blockers'
  #Write-Host '  -CheckWU                Analyse Windows Update state and errors'
  #Write-Host '  -CheckPolicy            Analyse WU-related policies (incl. safeguards)'
  #Write-Host ''

  Write-Host 'ENVIRONMENT / SYSTEM CHECKS:'
  Write-Host '  -GPResult              Collect and parse GPResult (policy troubleshooting)'
  Write-Host '  -SkipCleanup           Skip temp/profile cleanup checks'
  Write-Host ''

  Write-Host 'REPAIR / REMEDIATION (optional):'
  Write-Host '  -NoWU                   Skip Windows Update reset routines'
  Write-Host '  -ForceWUReset           Force full Windows Update reset (use with caution)'
  Write-Host '  -NetReset               Enable network stack reset (opt-in)'
  Write-Host ''

  #Write-Host 'OUTPUT CONTROLS:'
  #Write-Host '  -Detailed               Show full findings (incl. INFO states)' #unfinished
  #Write-Host '  -HideOK                 Suppress OK/healthy results'            #unfinished
  #Write-Host ''

  Write-Host 'OUTPUT STRUCTURE:'
  Write-Host '  DEVICE SUMMARY          High-level system and upgrade status'
  Write-Host '  COMPATIBILITY           Appraiser + upgrade readiness indicators'
  Write-Host '  POLICY                  Windows Update/Feature Update policies'
  Write-Host '  SERVICES                WU-related services state'
  Write-Host '  TROUBLESHOOTING SUMMARY Actionable issues only (warnings/errors)'
  Write-Host ''

  Write-Host 'Upgrade States Explained:' -ForegroundColor Yellow
  Write-Host '  READY           Device evaluated and no blockers found'
  Write-Host '  BLOCKED         Hardware / policy / application blocking upgrade'
  Write-Host '  SAFEGUARDED     Microsoft safeguard hold in place'
  Write-Host '  DELAYED         Windows Update not active or incomplete'
  Write-Host '  NOT EVALUATED   Appraiser missing or has not run (no compatibility data)'
  Write-Host ''

  Write-Host 'Examples:' -ForegroundColor Yellow
  Write-Host '  .\Get-Win11UpdateRegistryMap.ps1'
  Write-Host '  .\Get-Win11UpdateRegistryMap.ps1 -ComputerName PC01'
  Write-Host '  .\Get-Win11UpdateRegistryMap.ps1 -ComputerList devices.txt'
  Write-Host '  .\Get-Win11UpdateRegistryMap.ps1 -EventScan -EventDays 3'
  #Write-Host '  .\Get-Win11UpdateRegistryMap.ps1 -PassThru | Where-Object { $_.UpgradeStatus -ne "Ready" }' #unfinished
  Write-Host ''

  #Write-Host 'Export failing devices to CSV:'
  #Write-Host '  .\Get-Win11UpdateRegistryMap.ps1 -ComputerList problems.txt -PassThru |'
  #Write-Host '    Where-Object { $_.UpgradeStatus -ne "Ready" } |'
  #Write-Host '    Select-Object ComputerName, OSDisplay, UpgradeStatus, Verdict |'
  #Write-Host '    Export-Csv .\Win11_Issues.csv -NoTypeInformation'
  #Write-Host ''

  return
}

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# -------------------------
# Global error trap (basic troubleshooting)
# -------------------------
trap {
  $err = $_

  $message = $null
  $type = $null
  $line = $null
  $command = $null

  try {
    $message = $err.Exception.Message
    $type = $err.Exception.GetType().FullName
    $line = $err.InvocationInfo.ScriptLineNumber
    $command = $err.InvocationInfo.Line
  }
  catch {
    $message = "Unknown error"
    $type = "Unknown"
    $line = "?"
    $command = "Unavailable"
  }

  if ($command) {
    $command = ($command -replace '\r|\n', ' ').Trim()
    if ($command.Length -gt 220) { $command = $command.Substring(0, 217) + '...' }
  }

  Write-Host "" 
  Write-Host "=== SCRIPT ERROR ===" -ForegroundColor Red
  Write-Host ("ERROR  | {0}" -f $message) -ForegroundColor Red
  Write-Host ("TYPE   | {0}" -f $type)
  Write-Host ("LINE   | {0}" -f $line)
  Write-Host ("CODE   | {0}" -f $command)
  Write-Host ""

  continue
}

# -------------------------
# Helpers
# -------------------------
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

function New-Finding {
  param(
    [string]$Computer,
    [string]$Area,
    [string]$Severity, # OK / INFO / WARNING / CRITICAL
    [string]$Setting,
    [object]$Value,
    [string]$Status,
    [string]$Fix,
    [string]$Source
  )

  [pscustomobject]@{
    Computer = $Computer
    Area     = $Area
    Severity = $Severity
    Setting  = $Setting
    Value    = $Value
    Status   = $Status
    Fix      = $Fix
    Source   = $Source
  }
}

function Get-IsLocalTarget {
  param([string]$TargetComputer)
  if (-not $TargetComputer) { return $true }
  $tc = $TargetComputer.Trim()
  return ($tc -eq $env:COMPUTERNAME -or $tc -eq 'localhost' -or $tc -eq '.')
}

function TruncPad {
  param([string]$Text, [int]$Width)
  if ($null -eq $Text) { $Text = '' }
  $t = ($Text -replace '\r|\n', ' ').Trim()
  if ($t.Length -gt $Width -and $Width -gt 10) {
    $t = $t.Substring(0, $Width - 3) + '...'
  }
  return $t.PadRight($Width)
}

function Write-ColoredLine {
  param([string]$Line, [string]$Severity, [switch]$NoColor)

  if ($NoColor) {
    Write-Host $Line
    return
  }

  $color = switch ($Severity) {
    'CRITICAL' { 'Red' }
    'WARNING' { 'Yellow' }
    'INFO' { 'Cyan' }
    default { 'Gray' }
  }

  Write-Host $Line -ForegroundColor $color
}

function Try-ParseIsoUtc {
  param([string]$Text)
  if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
  try {
    return [DateTime]::Parse($Text, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal).ToUniversalTime()
  }
  catch { return $null }
}

function To-Array {
  param([object]$Value)
  return @($Value)
}

# -------------------------
# Registry access (local + remote)
# -------------------------
function Get-RegValueSafe {
  param(
    [string]$TargetComputer,
    [string]$Hive,     # HKLM / HKCU
    [string]$KeyPath,
    [string]$ValueName
  )

  $isLocal = Get-IsLocalTarget $TargetComputer
  $baseKey = $null
  $subKey = $null

  try {
    $hiveEnum = switch ($Hive.ToUpperInvariant()) {
      'HKLM' { [Microsoft.Win32.RegistryHive]::LocalMachine }
      'HKCU' { [Microsoft.Win32.RegistryHive]::CurrentUser }
      default { throw "Unsupported hive: $Hive" }
    }

    if ($isLocal) {
      $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hiveEnum, [Microsoft.Win32.RegistryView]::Registry64)
    }
    else {
      $baseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($hiveEnum, $TargetComputer)
    }

    $subKey = $baseKey.OpenSubKey($KeyPath, $false)
    if ($null -eq $subKey) {
      return [pscustomobject]@{ Present = $false; Value = $null; Kind = $null; Error = $null }
    }

    $val = $subKey.GetValue($ValueName, $null, 'DoNotExpandEnvironmentNames')
    if ($null -eq $val) {
      return [pscustomobject]@{ Present = $false; Value = $null; Kind = $null; Error = $null }
    }

    $kind = $null
    try { $kind = $subKey.GetValueKind($ValueName).ToString() } catch { $kind = $null }

    return [pscustomobject]@{ Present = $true; Value = $val; Kind = $kind; Error = $null }
  }
  catch {
    return [pscustomobject]@{ Present = $null; Value = $null; Kind = $null; Error = $_.Exception.Message }
  }
  finally {
    if ($subKey) { $subKey.Close() }
    if ($baseKey) { $baseKey.Close() }
  }
}

function Get-RegKeyAllValuesSafe {
  param(
    [string]$TargetComputer,
    [string]$Hive,
    [string]$KeyPath
  )

  $isLocal = Get-IsLocalTarget $TargetComputer
  $baseKey = $null
  $subKey = $null

  try {
    $hiveEnum = switch ($Hive.ToUpperInvariant()) {
      'HKLM' { [Microsoft.Win32.RegistryHive]::LocalMachine }
      'HKCU' { [Microsoft.Win32.RegistryHive]::CurrentUser }
      default { throw "Unsupported hive: $Hive" }
    }

    if ($isLocal) {
      $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hiveEnum, [Microsoft.Win32.RegistryView]::Registry64)
    }
    else {
      $baseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($hiveEnum, $TargetComputer)
    }

    $subKey = $baseKey.OpenSubKey($KeyPath, $false)
    if ($null -eq $subKey) {
      return [pscustomobject]@{ Present = $false; Values = @(); Error = $null }
    }

    $names = $subKey.GetValueNames()
    $vals = @()
    foreach ($n in @($names)) {
      $v = $subKey.GetValue($n, $null, 'DoNotExpandEnvironmentNames')
      $k = $null
      try { $k = $subKey.GetValueKind($n).ToString() } catch { $k = $null }
      $vals += [pscustomobject]@{ Name = $n; Value = $v; Kind = $k }
    }

    return [pscustomobject]@{ Present = $true; Values = $vals; Error = $null }
  }
  catch {
    return [pscustomobject]@{ Present = $null; Values = @(); Error = $_.Exception.Message }
  }
  finally {
    if ($subKey) { $subKey.Close() }
    if ($baseKey) { $baseKey.Close() }
  }
}

function Get-RegSubKeyNamesSafe {
  param(
    [string]$TargetComputer,
    [string]$Hive,
    [string]$KeyPath
  )

  $isLocal = Get-IsLocalTarget $TargetComputer
  $baseKey = $null
  $subKey = $null

  try {
    $hiveEnum = switch ($Hive.ToUpperInvariant()) {
      'HKLM' { [Microsoft.Win32.RegistryHive]::LocalMachine }
      'HKCU' { [Microsoft.Win32.RegistryHive]::CurrentUser }
      default { throw "Unsupported hive: $Hive" }
    }

    if ($isLocal) {
      $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hiveEnum, [Microsoft.Win32.RegistryView]::Registry64)
    }
    else {
      $baseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($hiveEnum, $TargetComputer)
    }

    $subKey = $baseKey.OpenSubKey($KeyPath, $false)
    if ($null -eq $subKey) {
      return [pscustomobject]@{ Present = $false; Names = @(); Error = $null }
    }

    $names = $subKey.GetSubKeyNames()
    return [pscustomobject]@{ Present = $true; Names = @($names); Error = $null }
  }
  catch {
    return [pscustomobject]@{ Present = $null; Names = @(); Error = $_.Exception.Message }
  }
  finally {
    if ($subKey) { $subKey.Close() }
    if ($baseKey) { $baseKey.Close() }
  }
}

# -------------------------
# Registry map (policy + state)
# -------------------------
function New-RegMapItem {
  param(
    [string]$Area,
    [string]$Hive,
    [string]$KeyPath,
    [string]$ValueName,
    [string]$ExpectedType,
    [string]$Meaning
  )

  [pscustomobject]@{
    Area         = $Area
    Hive         = $Hive
    KeyPath      = $KeyPath
    ValueName    = $ValueName
    ExpectedType = $ExpectedType
    Meaning      = $Meaning
  }
}

$RegMap = @()

# Targeting / pinning
$RegMap += New-RegMapItem "Policy(Targeting)" "HKLM" "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "TargetReleaseVersion" "REG_DWORD" "Target release pinning enabled when 1 (used with ProductVersion/TargetReleaseVersionInfo)."
$RegMap += New-RegMapItem "Policy(Targeting)" "HKLM" "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "ProductVersion" "REG_SZ" "Target product line for feature updates (commonly 'Windows 10' or 'Windows 11')."
$RegMap += New-RegMapItem "Policy(Targeting)" "HKLM" "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "TargetReleaseVersionInfo" "REG_SZ" "Target feature update version (e.g., '23H2', '24H2'). Can prevent moving to newer releases."

# Deferrals
$RegMap += New-RegMapItem "Policy(Deferral)" "HKLM" "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "DeferFeatureUpdatesPeriodInDays" "REG_DWORD" "Defers feature updates by N days."
$RegMap += New-RegMapItem "Policy(Deferral)" "HKLM" "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "DeferQualityUpdatesPeriodInDays" "REG_DWORD" "Defers quality updates by N days."

# Pause UX timestamps
$RegMap += New-RegMapItem "State(PauseUX)" "HKLM" "SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" "PauseFeatureUpdatesStartTime" "REG_SZ" "Feature updates pause start time (UTC)."
$RegMap += New-RegMapItem "State(PauseUX)" "HKLM" "SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" "PauseFeatureUpdatesEndTime" "REG_SZ" "Feature updates pause end time (UTC)."
$RegMap += New-RegMapItem "State(PauseUX)" "HKLM" "SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" "PauseQualityUpdatesStartTime" "REG_SZ" "Quality updates pause start time (UTC)."
$RegMap += New-RegMapItem "State(PauseUX)" "HKLM" "SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" "PauseQualityUpdatesEndTime" "REG_SZ" "Quality updates pause end time (UTC)."
$RegMap += New-RegMapItem "State(PauseUX)" "HKLM" "SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" "PauseUpdatesStartTime" "REG_SZ" "Unified pause start time (newer builds)."
$RegMap += New-RegMapItem "State(PauseUX)" "HKLM" "SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" "PauseUpdatesExpiryTime" "REG_SZ" "Unified pause expiry time (newer builds)."
$RegMap += New-RegMapItem "State(PauseUX)" "HKLM" "SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" "FlightSettingsMaxPauseDays" "REG_DWORD" "Max pause window allowed by UI (where present)."

# Pause status flags
$RegMap += New-RegMapItem "State(PauseStatus)" "HKLM" "SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\Settings" "PausedFeatureStatus" "REG_DWORD" "Feature update pause status flag."
$RegMap += New-RegMapItem "State(PauseStatus)" "HKLM" "SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\Settings" "PausedQualityStatus" "REG_DWORD" "Quality update pause status flag."

# Upgrade blocks
$RegMap += New-RegMapItem "Policy(UpgradeBlock)" "HKLM" "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "DisableOSUpgrade" "REG_DWORD" "Blocks OS upgrades when 1."
$RegMap += New-RegMapItem "State(UpgradeBlock)" "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" "AllowOSUpgrade" "REG_DWORD" "Legacy allowance for OS upgrade (0 can suppress)."

# Update source remnants
$RegMap += New-RegMapItem "Policy(UpdateSource)" "HKLM" "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "WUServer" "REG_SZ" "WSUS server URL."
$RegMap += New-RegMapItem "Policy(UpdateSource)" "HKLM" "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "WUStatusServer" "REG_SZ" "WSUS status server URL."
$RegMap += New-RegMapItem "Policy(UpdateSource)" "HKLM" "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "UseWUServer" "REG_DWORD" "When 1, AU uses WSUS (paired with WUServer/WUStatusServer)."

# Scan source (policy-driven)
$RegMap += New-RegMapItem "Policy(ScanSource)" "HKLM" "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "DisableDualScan" "REG_DWORD" "Disables dual-scan; can interfere with WUfB/Intune scanning in mixed configs."
$RegMap += New-RegMapItem "Policy(ScanSource)" "HKLM" "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "SetPolicyDrivenUpdateSourceForDriverUpdates" "REG_DWORD" "Policy-driven scan source selector (Driver Updates)."
$RegMap += New-RegMapItem "Policy(ScanSource)" "HKLM" "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "SetPolicyDrivenUpdateSourceForFeatureUpdates" "REG_DWORD" "Policy-driven scan source selector (Feature Updates)."
$RegMap += New-RegMapItem "Policy(ScanSource)" "HKLM" "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "SetPolicyDrivenUpdateSourceForOtherUpdates" "REG_DWORD" "Policy-driven scan source selector (Other Microsoft Updates)."
$RegMap += New-RegMapItem "Policy(ScanSource)" "HKLM" "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "SetPolicyDrivenUpdateSourceForQualityUpdates" "REG_DWORD" "Policy-driven scan source selector (Quality Updates)."

# Internet access policies
$RegMap += New-RegMapItem "Policy(UpdateAccess)" "HKLM" "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "DoNotConnectToWindowsUpdateInternetLocations" "REG_DWORD" "When enabled, prevents connecting to Windows Update internet locations (intranet-only update behavior)."
$RegMap += New-RegMapItem "Policy(UpdateAccess)" "HKLM" "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "SetDisableUXWUAccess" "REG_DWORD" "When enabled, removes user access to scan/download/install Windows Update in Settings (UX disabled)."

# Effective policy (PolicyManager)
$PolicyManagerKey = "SOFTWARE\Microsoft\PolicyManager\current\device\Update"
$PolicyManagerValues = @(
  "BranchReadinessLevel",
  "DeferFeatureUpdatesPeriodInDays",
  "DeferQualityUpdatesPeriodInDays",
  "PauseFeatureUpdatesStartTime",
  "PauseQualityUpdatesStartTime",
  "UpdateServiceUrl",
  "UpdateServiceUrlAlternate",
  "SetDisableUXWUAccess",
  "SetDisablePauseUXAccess",
  "DisableWUfBSafeguards",
  "ProductVersion",
  "TargetReleaseVersion",
  "TargetReleaseVersionInfo"
)

# -------------------------
# Classifiers
# -------------------------
function Classify-RegFinding {
  param(
    [string]$ValueName,
    [object]$Value
  )

  $severity = 'OK'
  $status = 'OK'
  $fix = ''

  function Get-OnOffState {
    param($v)
    switch ($v) {
      1 { 'Enabled' }
      0 { 'Disabled' }
      default { 'NotConfigured' }
    }
  }

  function Get-ScanSourceText {
    param($v)
    switch ($v) {
      0 { 'Default / Not explicitly set' }
      1 { 'Windows Update' }
      2 { 'WSUS / Intranet update service' }
      default { "Unknown scan source value: $v" }
    }
  }

  switch ($ValueName) {

    # ----------------------------------------------------
    # Upgrade blocking / targeting
    # ----------------------------------------------------
    'DisableOSUpgrade' {
      switch ($Value) {
        1 {
          $severity = 'CRITICAL'
          $status = 'Enabled - OS upgrades are blocked'
          $fix = 'Set to 0 or remove this policy to allow Windows 11 upgrades'
        }
        0 {
          $severity = 'INFO'
          $status = 'Disabled - OS upgrades not blocked by this policy'
        }
        default {
          $severity = 'INFO'
          $status = 'NotConfigured'
        }
      }
    }

    'TargetReleaseVersion' {
      switch ($Value) {
        1 {
          $severity = 'WARNING'
          $status = 'Enabled - Release pinning is active'
          $fix = 'Check ProductVersion and TargetReleaseVersionInfo to confirm the exact pin'
        }
        0 {
          $severity = 'INFO'
          $status = 'Disabled - Release pinning not enabled'
        }
        default {
          $severity = 'INFO'
          $status = 'NotConfigured'
        }
      }
    }

    'ProductVersion' {
      if ([string]::IsNullOrWhiteSpace([string]$Value)) {
        $severity = 'INFO'
        $status = 'NotConfigured'
      }
      elseif ($Value -eq 'Windows 10') {
        $severity = 'WARNING'
        $status = 'Pinned product target: Windows 10'
        $fix = 'Set to Windows 11 or remove targeting if Windows 11 should be offered'
      }
      elseif ($Value -eq 'Windows 11') {
        $severity = 'OK'
        $status = 'Pinned product target: Windows 11'
      }
      else {
        $severity = 'INFO'
        $status = ("Pinned product target: {0} (unusual value)" -f $Value)
        $fix = 'Verify this value is intended'
      }
    }

    'TargetReleaseVersionInfo' {
      if ([string]::IsNullOrWhiteSpace([string]$Value)) {
        $severity = 'INFO'
        $status = 'NotConfigured'
      }
      else {
        $severity = 'WARNING'
        $status = ("Pinned release target: {0}" -f $Value)
        $fix = 'Change or remove this value if newer feature updates should be offered'
      }
    }

    # ----------------------------------------------------
    # Deferrals
    # ----------------------------------------------------
    'DeferFeatureUpdatesPeriodInDays' {
      try {
        $d = [int]$Value
        $baseline = 7

        if ($d -eq 0) {
          $severity = 'OK'
          $status = 'No feature update deferral configured'
        }
        elseif ($d -eq $baseline) {
          $severity = 'INFO'
          $status = ("Baseline feature update deferral: {0} days" -f $d)
        }
        elseif ($d -ge 1 -and $d -le 14) {
          $severity = 'INFO'
          $status = ("Non-baseline feature update deferral: {0} days (baseline {1})" -f $d, $baseline)
        }
        else {
          $severity = 'WARNING'
          $status = ("High feature update deferral: {0} days" -f $d)
          $fix = 'Review whether this is intentional; high deferral can delay Windows 11 offers'
        }
      }
      catch {
        if ($null -ne $Value -and "$Value" -ne '') {
          $severity = 'INFO'
          $status = ("Feature update deferral present but value could not be parsed: {0}" -f $Value)
          $fix = 'Check registry type/value for this setting'
        }
        else {
          $severity = 'INFO'
          $status = 'NotConfigured'
        }
      }
    }

    'DeferQualityUpdatesPeriodInDays' {
      try {
        $d = [int]$Value
        $baseline = 7

        if ($d -eq 0) {
          $severity = 'OK'
          $status = 'No quality update deferral configured'
        }
        elseif ($d -eq $baseline) {
          $severity = 'INFO'
          $status = ("Baseline quality update deferral: {0} days" -f $d)
        }
        elseif ($d -ge 1 -and $d -le 14) {
          $severity = 'INFO'
          $status = ("Non-baseline quality update deferral: {0} days (baseline {1})" -f $d, $baseline)
        }
        else {
          $severity = 'WARNING'
          $status = ("High quality update deferral: {0} days" -f $d)
          $fix = 'Review whether this is intentional; high deferral may delay security updates'
        }
      }
      catch {
        if ($null -ne $Value -and "$Value" -ne '') {
          $severity = 'INFO'
          $status = ("Quality update deferral present but value could not be parsed: {0}" -f $Value)
          $fix = 'Check registry type/value for this setting'
        }
        else {
          $severity = 'INFO'
          $status = 'NotConfigured'
        }
      }
    }

    # ----------------------------------------------------
    # Pause states
    # ----------------------------------------------------
    'PauseFeatureUpdatesStartTime' {
      if ($Value) {
        $severity = 'INFO'
        $status = ("Feature pause start recorded: {0}" -f $Value)
      }
      else {
        $severity = 'INFO'
        $status = 'NotConfigured'
      }
    }

    'PauseFeatureUpdatesEndTime' {
      $dt = Try-ParseIsoUtc ([string]$Value)
      if ($dt -and $dt -gt (Get-Date).ToUniversalTime()) {
        $severity = 'WARNING'
        $status = ("Feature updates paused until {0}" -f $Value)
        $fix = 'Resume updates or clear pause settings if Windows 11 should be offered'
      }
      elseif ($Value) {
        $severity = 'INFO'
        $status = ("Feature pause end timestamp present: {0}" -f $Value)
      }
      else {
        $severity = 'INFO'
        $status = 'NotConfigured'
      }
    }

    'PauseQualityUpdatesStartTime' {
      if ($Value) {
        $severity = 'INFO'
        $status = ("Quality pause start recorded: {0}" -f $Value)
      }
      else {
        $severity = 'INFO'
        $status = 'NotConfigured'
      }
    }

    'PauseQualityUpdatesEndTime' {
      $dt = Try-ParseIsoUtc ([string]$Value)
      if ($dt -and $dt -gt (Get-Date).ToUniversalTime()) {
        $severity = 'WARNING'
        $status = ("Quality updates paused until {0}" -f $Value)
        $fix = 'Resume updates or clear pause settings if normal patching should resume'
      }
      elseif ($Value) {
        $severity = 'INFO'
        $status = ("Quality pause end timestamp present: {0}" -f $Value)
      }
      else {
        $severity = 'INFO'
        $status = 'NotConfigured'
      }
    }

    'PauseUpdatesStartTime' {
      if ($Value) {
        $severity = 'INFO'
        $status = ("Unified pause start recorded: {0}" -f $Value)
      }
      else {
        $severity = 'INFO'
        $status = 'NotConfigured'
      }
    }

    'PauseUpdatesExpiryTime' {
      $dt = Try-ParseIsoUtc ([string]$Value)
      if ($dt -and $dt -gt (Get-Date).ToUniversalTime()) {
        $severity = 'WARNING'
        $status = ("Unified updates pause active until {0}" -f $Value)
        $fix = 'Resume updates or clear pause settings if updates should resume'
      }
      elseif ($Value) {
        $severity = 'INFO'
        $status = ("Unified pause expiry timestamp present: {0}" -f $Value)
      }
      else {
        $severity = 'INFO'
        $status = 'NotConfigured'
      }
    }

    'FlightSettingsMaxPauseDays' {
      try {
        $d = [int]$Value
        $severity = 'INFO'
        $status = ("Maximum pause window allowed by UX: {0} days" -f $d)
      }
      catch {
        if ($Value) {
          $severity = 'INFO'
          $status = ("Max pause value present but could not be parsed: {0}" -f $Value)
        }
        else {
          $severity = 'INFO'
          $status = 'NotConfigured'
        }
      }
    }

    'PausedFeatureStatus' {
      switch ($Value) {
        1 {
          $severity = 'WARNING'
          $status = 'Feature update pause status flag is active'
          $fix = 'Check corresponding pause timestamps and clear pause if unintended'
        }
        0 {
          $severity = 'INFO'
          $status = 'Feature update pause status flag not active'
        }
        default {
          $severity = 'INFO'
          $status = 'NotConfigured'
        }
      }
    }

    'PausedQualityStatus' {
      switch ($Value) {
        1 {
          $severity = 'WARNING'
          $status = 'Quality update pause status flag is active'
          $fix = 'Check corresponding pause timestamps and clear pause if unintended'
        }
        0 {
          $severity = 'INFO'
          $status = 'Quality update pause status flag not active'
        }
        default {
          $severity = 'INFO'
          $status = 'NotConfigured'
        }
      }
    }

    # ----------------------------------------------------
    # Update source / WSUS / dual scan
    # ----------------------------------------------------
    'UseWUServer' {
      switch ($Value) {
        1 {
          $severity = 'INFO'
          $status = 'Enabled - Device is configured to scan against WSUS / intranet update service'
          $fix = 'Remove WSUS remnants if this device should use WUfB / Intune / Microsoft Update'
        }
        0 {
          $severity = 'INFO'
          $status = 'Disabled - Device is not forced to use WSUS by this setting'
        }
        default {
          $severity = 'INFO'
          $status = 'NotConfigured'
        }
      }
    }

    'WUServer' {
      if ([string]::IsNullOrWhiteSpace([string]$Value)) {
        $severity = 'INFO'
        $status = 'NotConfigured'
      }
      else {
        $severity = 'INFO'
        $status = ("WSUS server configured: {0}" -f $Value)
        $fix = 'Remove if the device should use Windows Update for Business / Intune'
      }
    }

    'WUStatusServer' {
      if ([string]::IsNullOrWhiteSpace([string]$Value)) {
        $severity = 'INFO'
        $status = 'NotConfigured'
      }
      else {
        $severity = 'INFO'
        $status = ("WSUS status server configured: {0}" -f $Value)
      }
    }

    'DisableDualScan' {
      switch ($Value) {
        1 {
          $severity = 'INFO'
          $status = 'Enabled - Dual scan disabled'
          $fix = 'Review in mixed WSUS/WUfB estates if scanning behaviour is unexpected'
        }
        0 {
          $severity = 'INFO'
          $status = 'Disabled - Dual scan not explicitly blocked'
        }
        default {
          $severity = 'INFO'
          $status = 'NotConfigured'
        }
      }
    }

    'SetPolicyDrivenUpdateSourceForFeatureUpdates' {
      $severity = 'INFO'
      $status = ("Feature Updates scan source: {0}" -f (Get-ScanSourceText $Value))
    }

    'SetPolicyDrivenUpdateSourceForQualityUpdates' {
      $severity = 'INFO'
      $status = ("Quality Updates scan source: {0}" -f (Get-ScanSourceText $Value))
    }

    'SetPolicyDrivenUpdateSourceForDriverUpdates' {
      $severity = 'INFO'
      $status = ("Driver Updates scan source: {0}" -f (Get-ScanSourceText $Value))
    }

    'SetPolicyDrivenUpdateSourceForOtherUpdates' {
      $severity = 'INFO'
      $status = ("Other Updates scan source: {0}" -f (Get-ScanSourceText $Value))
    }

    # ----------------------------------------------------
    # Update access / UX access
    # ----------------------------------------------------
    'DoNotConnectToWindowsUpdateInternetLocations' {
      switch ($Value) {
        1 {
          $severity = 'WARNING'
          $status = 'Enabled - Online Windows Update endpoints are blocked (intranet-only behaviour)'
          $fix = 'Disable/remove if the device should reach Windows Update / WUfB / Intune endpoints'
        }
        0 {
          $severity = 'INFO'
          $status = 'Disabled - Online Windows Update endpoints are allowed'
        }
        default {
          $severity = 'INFO'
          $status = 'NotConfigured'
        }
      }
    }

    'SetDisableUXWUAccess' {
      switch ($Value) {
        1 {
          $severity = 'INFO'
          $status = 'Enabled - Windows Update UX is disabled/hidden in Settings'
          $fix = 'Set to 0 or remove if interactive Windows Update access is required'
        }
        0 {
          $severity = 'INFO'
          $status = 'Disabled - Windows Update UX is allowed'
        }
        default {
          $severity = 'INFO'
          $status = 'NotConfigured'
        }
      }
    }

    'SetDisablePauseUXAccess' {
      switch ($Value) {
        1 {
          $severity = 'INFO'
          $status = 'Enabled - Pause controls are hidden in Windows Update UX'
        }
        0 {
          $severity = 'INFO'
          $status = 'Disabled - Pause controls are available in Windows Update UX'
        }
        default {
          $severity = 'INFO'
          $status = 'NotConfigured'
        }
      }
    }

    'DisableWUfBSafeguards' {
      switch ($Value) {
        1 {
          $severity = 'WARNING'
          $status = 'Enabled - WUfB safeguard holds are disabled / bypassed'
          $fix = 'Review whether bypassing safeguard holds is appropriate for this device'
        }
        0 {
          $severity = 'INFO'
          $status = 'Disabled - Safeguard holds remain in effect'
        }
        default {
          $severity = 'INFO'
          $status = 'NotConfigured'
        }
      }
    }

    # ----------------------------------------------------
    # PolicyManager service URLs
    # ----------------------------------------------------
    'UpdateServiceUrl' {
      if ([string]::IsNullOrWhiteSpace([string]$Value)) {
        $severity = 'INFO'
        $status = 'NotConfigured'
      }
      else {
        $severity = 'INFO'
        $status = ("PolicyManager UpdateServiceUrl configured: {0}" -f $Value)
      }
    }

    'UpdateServiceUrlAlternate' {
      if ([string]::IsNullOrWhiteSpace([string]$Value)) {
        $severity = 'INFO'
        $status = 'NotConfigured'
      }
      else {
        $severity = 'INFO'
        $status = ("PolicyManager UpdateServiceUrlAlternate configured: {0}" -f $Value)
      }
    }

    # ----------------------------------------------------
    # Default
    # ----------------------------------------------------
    default {
      if ($null -eq $Value -or "$Value" -eq '') {
        $severity = 'INFO'
        $status = 'NotConfigured'
      }
      else {
        $severity = 'INFO'
        $status = ("Value present: {0}" -f $Value)
      }
    }
  }

  return [pscustomobject]@{
    Severity = $severity
    Status   = $status
    Fix      = $fix
  }
}

# -------------------------
# Hardware + OS checks
# -------------------------
function Add-HwErrorToken {
  param([ref]$Errors, [string]$Component, [string]$Message)

  if ([string]::IsNullOrWhiteSpace($Message)) {
    $Errors.Value += ("{0}:UnknownError" -f $Component)
    return
  }

  if ($Message -match 'WS-Management|WinRM|WSMan|The client cannot connect to the destination specified') {
    $Errors.Value += ("WinRMUnavailable:{0}" -f $Component)
  }
  else {
    $msg = ($Message -replace '\r|\n', ' ').Trim()
    if ($msg.Length -gt 140) { $msg = $msg.Substring(0, 137) + '...' }
    $Errors.Value += ("{0}:{1}" -f $Component, $msg)
  }
}

function Get-OSSignals {
  param([string]$TargetComputer)

  $isLocal = Get-IsLocalTarget $TargetComputer

  $caption = $null
  $version = $null
  $build = $null
  $arch = $null
  $errors = @()

  try {
    if ($isLocal) {
      $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    }
    else {
      $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $TargetComputer -ErrorAction Stop
    }

    $caption = $os.Caption
    $version = $os.Version
    $build = $os.BuildNumber
    $arch = $os.OSArchitecture
  }
  catch {
    Add-HwErrorToken -Errors ([ref]$errors) -Component 'OS' -Message $_.Exception.Message
  }

  [pscustomobject]@{
    Caption = $caption
    Version = $version
    Build   = $build
    Arch    = $arch
    Errors  = ($errors -join ' | ')
  }
}

function Get-HardwareSignals {
  param([string]$TargetComputer)

  $isLocal = Get-IsLocalTarget $TargetComputer

  $cpuName = $null
  $cpuCores = $null
  $ramGB = $null
  $sysDriveGB = $null
  $sysFreeGB = $null
  $tpmPresent = $null
  $tpmReady = $null
  $secureBoot = $null
  $partitionStyle = $null

  $errors = @()

  function Add-HwErrorToken {
    param([string]$Component, [string]$Message)

    if ([string]::IsNullOrWhiteSpace($Message)) {
      $errors += ("{0}:UnknownError" -f $Component)
      return
    }

    if ($Message -match 'WS-Management|WinRM|WSMan|The client cannot connect to the destination specified') {
      $errors += ("WinRMUnavailable:{0}" -f $Component)
      return
    }

    $msg = ($Message -replace '\r|\n', ' ').Trim()
    if ($msg.Length -gt 140) { $msg = $msg.Substring(0, 137) + '...' }
    $errors += ("{0}:{1}" -f $Component, $msg)
  }

  # -------------------------
  # CPU (RELIABLE: does NOT rely on CIM)
  # -------------------------
  try {
    $cpuName = Get-CPUNameReliable -TargetComputer $TargetComputer

    if ([string]::IsNullOrWhiteSpace($cpuName)) {
      $cpuName = $null
      Add-HwErrorToken -Component 'CPU' -Message 'CPU query returned empty value'
    }
  }
  catch {
    Add-HwErrorToken -Component 'CPU' -Message $_.Exception.Message
  }

  # -------------------------
  # RAM (CIM best-effort)
  # -------------------------
  try {
    $cs = $null
    if ($isLocal) {
      $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    }
    else {
      $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $TargetComputer -ErrorAction Stop
    }

    if ($cs -and $cs.TotalPhysicalMemory) {
      $ramGB = [math]::Round(($cs.TotalPhysicalMemory / 1GB), 2)
    }
  }
  catch {
    Add-HwErrorToken -Component 'RAM' -Message $_.Exception.Message
  }

  # -------------------------
  # Disk (CIM best-effort)
  # -------------------------
  try {
    $os = $null
    if ($isLocal) {
      $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    }
    else {
      $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $TargetComputer -ErrorAction Stop
    }

    if ($os -and $os.SystemDrive) {
      $sysDrive = $os.SystemDrive

      $ld = $null
      if ($isLocal) {
        $ld = Get-CimInstance -ClassName Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $sysDrive) -ErrorAction Stop
      }
      else {
        $ld = Get-CimInstance -ClassName Win32_LogicalDisk -ComputerName $TargetComputer -Filter ("DeviceID='{0}'" -f $sysDrive) -ErrorAction Stop
      }

      if ($ld) {
        if ($ld.Size) { $sysDriveGB = [math]::Round(($ld.Size / 1GB), 2) }
        if ($ld.FreeSpace) { $sysFreeGB = [math]::Round(($ld.FreeSpace / 1GB), 2) }
      }
    }
  }
  catch {
    Add-HwErrorToken -Component 'Disk' -Message $_.Exception.Message
  }

  # -------------------------
  # TPM / SecureBoot / PartitionStyle (LOCAL ONLY)
  # -------------------------
  if ($isLocal) {

    try {
      $tpm = Get-Tpm -ErrorAction Stop
      $tpmPresent = $tpm.TpmPresent
      $tpmReady = $tpm.TpmReady
    }
    catch {
      Add-HwErrorToken -Component 'TPM' -Message $_.Exception.Message
    }

    try {
      $secureBoot = Confirm-SecureBootUEFI
    }
    catch {
      $secureBoot = $false
      Add-HwErrorToken -Component 'SecureBoot' -Message $_.Exception.Message
    }

    try {
      $disk0 = Get-Disk -Number 0 -ErrorAction Stop
      $partitionStyle = $disk0.PartitionStyle
    }
    catch {
      Add-HwErrorToken -Component 'PartitionStyle' -Message $_.Exception.Message
    }

  }
  else {
    $errors += 'NotCheckedRemote:TPM'
    $errors += 'NotCheckedRemote:SecureBoot'
    $errors += 'NotCheckedRemote:PartitionStyle'
  }

  # Return object
  [pscustomobject]@{
    CpuName        = $cpuName
    CpuCores       = $cpuCores
    RamGB          = $ramGB
    SysDriveGB     = $sysDriveGB
    SysFreeGB      = $sysFreeGB
    TpmPresent     = $tpmPresent
    TpmReady       = $tpmReady
    SecureBoot     = $secureBoot
    PartitionStyle = $partitionStyle
    Errors         = ($errors -join ' | ')
  }
}


function Get-CPUHeuristic {
  param(
    [Parameter(Mandatory)]
    [string]$CpuName
  )

  $name = ($CpuName -replace '\s+', ' ').Trim()

  # ---------------------------
  # Intel heuristic
  # ---------------------------
  if ($name -match 'Intel\(R\)|Intel') {

    # Try parse common Intel Core patterns:
    #   i5-6500
    #   i7-8650U
    #   i5-1145G7
    #   i7-1255U
    #   i9-13900K
    #
    # Capture the leading numeric model portion immediately after i3/i5/i7/i9-
    $m = [regex]::Match(
      $name,
      'i[3579]-\s*([0-9]{4,5})',
      [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )

    if ($m.Success) {
      $num = $m.Groups[1].Value
      $gen = $null

      if ($num.Length -eq 5) {
        # 10th+ desktop/mobile patterns like 10400, 12500, 13900
        $gen = [int]$num.Substring(0, 2)
      }
      elseif ($num.Length -eq 4) {
        # 4-digit Intel model numbers can be:
        # 6500  -> 6th gen
        # 8650  -> 8th gen
        # 9700  -> 9th gen
        # 1145  -> 11th gen
        # 1265  -> 12th gen
        # 1335  -> 13th gen
        # Rule:
        # - if it starts with 10/11/12/13/14 -> take first 2 digits
        # - otherwise -> take first digit
        if ($num -match '^(10|11|12|13|14)') {
          $gen = [int]$num.Substring(0, 2)
        }
        else {
          $gen = [int]$num.Substring(0, 1)
        }
      }

      if ($gen -ne $null) {
        # Practical Windows 11 Intel rule-of-thumb:
        # 8th gen Core and newer = likely supported
        if ($gen -ge 8) {
          return [pscustomobject]@{
            Verdict  = 'LikelySupported'
            Detail   = ("Intel Core gen {0} (heuristic)" -f $gen)
            Severity = 'OK'
          }
        }
        else {
          return [pscustomobject]@{
            Verdict  = 'PossiblyUnsupported'
            Detail   = ("Intel Core gen {0} (heuristic)" -f $gen)
            Severity = 'WARNING'
          }
        }
      }
    }

    return [pscustomobject]@{
      Verdict  = 'Unknown'
      Detail   = 'Intel CPU (could not parse Core generation heuristically)'
      Severity = 'INFO'
    }
  }

  # ---------------------------
  # AMD heuristic
  # ---------------------------
  if ($name -match 'AMD') {

    # Try parse Ryzen family numbers from common patterns:
    #   Ryzen 5 2600
    #   Ryzen 7 3700X
    #   Ryzen 5 PRO 4650G
    #   Ryzen 7 7840HS
    #   Ryzen Threadripper 3960X
    #
    # This captures the first 4-digit family model after Ryzen branding.
    $m = [regex]::Match(
      $name,
      'Ryzen(?:\s+Threadripper)?(?:\s+\w+){0,3}\s+([0-9]{4})',
      [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )

    if ($m.Success) {
      $series = [int]$m.Groups[1].Value

      # Practical Windows 11 AMD rule-of-thumb:
      # - Ryzen 3000+  => likely supported
      # - Ryzen 2000   => possibly supported (known exceptions)
      # - Ryzen 1000   => likely unsupported
      if ($series -ge 3000) {
        return [pscustomobject]@{
          Verdict  = 'LikelySupported'
          Detail   = ("AMD Ryzen {0} series (heuristic)" -f $series)
          Severity = 'OK'
        }
      }
      elseif ($series -ge 2000) {
        return [pscustomobject]@{
          Verdict  = 'PossiblySupported'
          Detail   = ("AMD Ryzen {0} series (heuristic; 2000-series has known exceptions)" -f $series)
          Severity = 'INFO'
        }
      }
      else {
        return [pscustomobject]@{
          Verdict  = 'PossiblyUnsupported'
          Detail   = ("AMD Ryzen {0} series (heuristic)" -f $series)
          Severity = 'WARNING'
        }
      }
    }

    return [pscustomobject]@{
      Verdict  = 'Unknown'
      Detail   = 'AMD CPU (could not parse Ryzen family heuristically)'
      Severity = 'INFO'
    }
  }

  # ---------------------------
  # Fallback
  # ---------------------------
  return [pscustomobject]@{
    Verdict  = 'Unknown'
    Detail   = 'Non-Intel/AMD CPU (heuristic not implemented)'
    Severity = 'INFO'
  }
}

function Get-CPUNameReliable {
  param([string]$TargetComputer)

  $isLocal = Get-IsLocalTarget $TargetComputer

  # -------------------------
  # LOCAL (most reliable)
  # -------------------------
  if ($isLocal) {
    try {
      $cpu = Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1
      if ($cpu -and -not [string]::IsNullOrWhiteSpace($cpu.Name)) {
        return $cpu.Name.Trim()
      }
    }
    catch {}

    try {
      $cpu = Get-WmiObject Win32_Processor -ErrorAction Stop | Select-Object -First 1
      if ($cpu -and -not [string]::IsNullOrWhiteSpace($cpu.Name)) {
        return $cpu.Name.Trim()
      }
    }
    catch {}
  }

  # -------------------------
  # REMOTE - WMI (DCOM)
  # -------------------------
  try {
    $cpu = Get-WmiObject Win32_Processor -ComputerName $TargetComputer -ErrorAction Stop | Select-Object -First 1
    if ($cpu -and -not [string]::IsNullOrWhiteSpace($cpu.Name)) {
      return $cpu.Name.Trim()
    }
  }
  catch {}

  # -------------------------
  # REMOTE - Registry (fallback, limited reliability)
  # -------------------------
  try {
    $keyPath = "HARDWARE\DESCRIPTION\System\CentralProcessor\0"
    $valueName = "ProcessorNameString"

    $r = Get-RegValueSafe -TargetComputer $TargetComputer -Hive "HKLM" -KeyPath $keyPath -ValueName $valueName

    if ($r.Present -eq $true -and -not [string]::IsNullOrWhiteSpace($r.Value)) {
      return $r.Value.Trim()
    }
  }
  catch {}

  # -------------------------
  # REMOTE - LAST RESORT (WMIC via process)
  # -------------------------
  try {
    $tempFile = "C:\Windows\Temp\cpu.txt"
    $cmd = "cmd /c wmic cpu get Name /value > $tempFile"

    Invoke-WmiMethod -Class Win32_Process -Name Create -ComputerName $TargetComputer -ArgumentList $cmd | Out-Null
    Start-Sleep -Milliseconds 500

    $content = Get-Content "\\$TargetComputer\C$\Windows\Temp\cpu.txt" -ErrorAction Stop

    foreach ($line in $content) {
      if ($line -match "^Name=(.+)$") {
        return $matches[1].Trim()
      }
    }
  }
  catch {}

  return $null
}

# -------------------------
# Compatibility & update signals
# -------------------------
function Get-CompatAppraiserState {
  param([string]$TargetComputer)

  $taskPath = "\Microsoft\Windows\Application Experience\"
  $taskName = "Microsoft Compatibility Appraiser"

  if (Get-IsLocalTarget $TargetComputer) {
    try {
      $t = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction Stop
      $i = Get-ScheduledTaskInfo -TaskName $taskName -TaskPath $taskPath -ErrorAction Stop
      return [pscustomobject]@{ Checked = $true; State = $t.State; LastRunTime = $i.LastRunTime; LastResult = $i.LastTaskResult; Error = $null }
    }
    catch {
      return [pscustomobject]@{ Checked = $true; State = $null; LastRunTime = $null; LastResult = $null; Error = $_.Exception.Message }
    }
  }

  try {
    $out = & schtasks.exe /Query /S $TargetComputer /TN ("{0}{1}" -f $taskPath, $taskName) /FO LIST /V 2>&1
    $txt = ($out | Out-String)

    $state = $null
    $lastRun = $null
    $lastResult = $null

    foreach ($line in ($txt -split "`r?`n")) {
      if ($line -match '^Status:\s*(.+)$') { $state = $matches[1].Trim() }
      if ($line -match '^Last Run Time:\s*(.+)$') { $lastRun = $matches[1].Trim() }
      if ($line -match '^Last Result:\s*(.+)$') { $lastResult = $matches[1].Trim() }
    }

    return [pscustomobject]@{ Checked = $true; State = $state; LastRunTime = $lastRun; LastResult = $lastResult; Error = $null }
  }
  catch {
    return [pscustomobject]@{ Checked = $false; State = $null; LastRunTime = $null; LastResult = $null; Error = $_.Exception.Message }
  }
}

function Get-UpgradeExperienceIndicatorsSafe {
  param([string]$TargetComputer)

  $basePath = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TargetVersionUpgradeExperienceIndicators"
  $sub = Get-RegSubKeyNamesSafe -TargetComputer $TargetComputer -Hive "HKLM" -KeyPath $basePath

  if ($sub.Present -ne $true) {
    return [pscustomobject]@{ Checked = $false; Items = @(); Error = $sub.Error }
  }

  $items = @()
  foreach ($name in @($sub.Names)) {
    $k = "{0}\{1}" -f $basePath, $name
    $vals = Get-RegKeyAllValuesSafe -TargetComputer $TargetComputer -Hive "HKLM" -KeyPath $k

    if ($vals.Present -eq $true) {
      foreach ($v in @($vals.Values)) {
        if ($v.Name -like 'Gated*') {
          $items += [pscustomobject]@{ ReleaseKey = $name; ValueName = $v.Name; Value = $v.Value }
        }
      }
    }
  }

  return [pscustomobject]@{ Checked = $true; Items = $items; Error = $null }
}

function Get-ServiceStateSafe {
  param([string]$TargetComputer, [string]$Name)

  try {
    $s = Get-Service -Name $Name -ComputerName $TargetComputer -ErrorAction Stop
    return [pscustomobject]@{ Checked = $true; Status = $s.Status.ToString(); Error = $null }
  }
  catch {
    if (Get-IsLocalTarget $TargetComputer) {
      try {
        $s2 = Get-Service -Name $Name -ErrorAction Stop
        return [pscustomobject]@{ Checked = $true; Status = $s2.Status.ToString(); Error = $null }
      }
      catch {
        return [pscustomobject]@{ Checked = $false; Status = $null; Error = $_.Exception.Message }
      }
    }
    return [pscustomobject]@{ Checked = $false; Status = $null; Error = $_.Exception.Message }
  }
}

function Get-WUEventSignals {
  param([string]$TargetComputer)

  try {
    $latest = Get-WinEvent -ComputerName $TargetComputer -LogName 'Microsoft-Windows-WindowsUpdateClient/Operational' -MaxEvents 1 -ErrorAction Stop
    $lastTime = $latest.TimeCreated

    $errors = Get-WinEvent -ComputerName $TargetComputer -FilterHashtable @{ LogName = 'Microsoft-Windows-WindowsUpdateClient/Operational'; Level = 2, 3 } -MaxEvents 5 -ErrorAction Stop

    $errMsg = $null
    if ($errors) {
      $errMsg = $null
      $errCode = $null
      $errTime = $null
      $errLevel = $null

      if ($errors) {
        $e = $errors | Select-Object -First 1

        $errMsg = $e.Message
        $errTime = $e.TimeCreated
        $errLevel = $e.LevelDisplayName
        $errId = $e.Id

        # Extract error code (e.g. 0x8024402C)
        if ($errMsg -match '0x[0-9A-Fa-f]{6,8}') {
          $errCode = $matches[0]
        }
      }
      if ($errMsg) { $errMsg = ($errMsg -replace '\r|\n', ' ').Trim() }
    }

    
    return [pscustomobject]@{
      Checked          = $true
      LastEventTime    = $lastTime
      LastErrorMessage = $errMsg
      LastErrorCode    = $errCode
      LastErrorTime    = $errTime
      LastErrorLevel   = $errLevel
      LastErrorId      = $errId
      Error            = $null
    }

  }
  catch {
    return [pscustomobject]@{ Checked = $false; LastEventTime = $null; LastErrorMessage = $null; Error = $_.Exception.Message }
  }
}

function Test-PendingReboot {
  param([string]$TargetComputer)

  $isLocal = Get-IsLocalTarget $TargetComputer

  $hardReboot = $false
  $softReboot = $false
  $reasons = @()

  try {
    # -------------------------
    # HARD reboot indicators
    # -------------------------

    # Windows Update
    $wu = Get-RegValueSafe -TargetComputer $TargetComputer -Hive 'HKLM' `
      -KeyPath 'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' `
      -ValueName ''

    if ($wu.Present) {
      $hardReboot = $true
      $reasons += 'RebootRequired'
    }

    # Component Based Servicing (CBS)
    $cbs = Get-RegValueSafe -TargetComputer $TargetComputer -Hive 'HKLM' `
      -KeyPath 'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' `
      -ValueName ''

    if ($cbs.Present) {
      $hardReboot = $true
      $reasons += 'RebootPending'
    }

    # -------------------------
    # SOFT reboot indicator
    # -------------------------

    $pfro = Get-RegValueSafe -TargetComputer $TargetComputer -Hive 'HKLM' `
      -KeyPath 'SYSTEM\CurrentControlSet\Control\Session Manager' `
      -ValueName 'PendingFileRenameOperations'

    if ($pfro.Present -and $pfro.Value) {
      $softReboot = $true
      $reasons += 'PendingFileRename'
    }

  }
  catch {}

  # -------------------------
  # Final classification
  # -------------------------

  $required = ($hardReboot -or $softReboot)

  $severity = 'OK'
  $state = 'None'

  if ($hardReboot) {
    $severity = 'CRITICAL'
    $state = 'Hard'
  }
  elseif ($softReboot) {
    $severity = 'INFO'
    $state = 'Soft'
  }

  # -------------------------
  # Get uptime (for age calculation)
  # -------------------------

  $uptimeDays = $null

  try {
    if ($isLocal) {
      $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    }
    else {
      $os = Get-CimInstance Win32_OperatingSystem -ComputerName $TargetComputer -ErrorAction Stop
    }

    if ($os.LastBootUpTime) {
      $uptime = (Get-Date) - $os.LastBootUpTime
      $uptimeDays = [int]$uptime.TotalDays
    }

  }
  catch {}

  # -------------------------
  # Final object
  # -------------------------

  return [pscustomobject]@{
    Required   = $required
    Severity   = $severity
    State      = $state
    Reasons    = ($reasons -join ', ')
    UptimeDays = $uptimeDays
  }

}

# -------------------------
# Device summary helpers
# -------------------------
function Get-DeviceSummary {
  param([string]$TargetComputer)

  $isLocal = Get-IsLocalTarget $TargetComputer

  $manufacturer = $null
  $model = $null
  $user = $null

  try {
    if ($isLocal) {
      $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    }
    else {
      $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $TargetComputer -ErrorAction Stop
    }

    $manufacturer = $cs.Manufacturer
    $model = $cs.Model
    $user = $cs.UserName
  }
  catch {
    if (-not $model) { $model = 'Unavailable (CIM blocked)' }
  }

  $modeValue = 'Remote'
  if ($isLocal) { $modeValue = 'Local' }

  [pscustomobject]@{
    Computer     = $TargetComputer
    Manufacturer = $manufacturer
    Model        = $model
    User         = $user
    Mode         = $modeValue
  }
}

function Get-UpdateSourceMode {
  param([object[]]$ComputerFindings)

  $f = @($ComputerFindings)

  $useWUServer = @($f | Where-Object { $_.Setting -eq 'UseWUServer' -and $_.Value -ne $null })
  $wuServer = @($f | Where-Object { $_.Setting -eq 'WUServer' -and $_.Value })

  $policyDriven = @($f | Where-Object {
      $_.Setting -like 'SetPolicyDrivenUpdateSourceFor*' -and $_.Value -ne $null
    })

  $blockInternet = @($f | Where-Object { $_.Setting -eq 'DoNotConnectToWindowsUpdateInternetLocations' -and $_.Value -eq 1 })

  $hasWSUS = ($useWUServer.Count -gt 0 -and ($useWUServer | Select-Object -First 1).Value -eq 1) -or ($wuServer.Count -gt 0)
  $hasPolicyDriven = ($policyDriven.Count -gt 0)

  if ($hasWSUS -and $hasPolicyDriven) { return 'Mixed (WSUS + Policy-driven scan source)' }
  if ($hasWSUS) { return 'WSUS / Intranet update service' }
  if ($blockInternet.Count -gt 0) { return 'IntranetOnly (Online WU blocked)' }

  return 'WUfB / Windows Update (online)'
}

function Get-AppraiserFailureReason {
  param(
    [string]$TargetComputer
  )

  $reasons = New-Object System.Collections.ArrayList

  # ✅ Check scheduled task existence
  try {
    $task = schtasks.exe /Query /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" 2>$null
    if (-not $task -or $task -match 'ERROR') {
      [void]$reasons.Add('Scheduled task missing')
    }
  }
  catch {
    [void]$reasons.Add('Unable to query scheduled task')
  }

  # ✅ Check CompatTelRunner (core binary)
  $compatPath = "$env:SystemRoot\System32\CompatTelRunner.exe"
  if (-not (Test-Path $compatPath)) {
    [void]$reasons.Add('CompatTelRunner.exe missing')
  }

  # ✅ Check telemetry policy
  try {
    $telemetry = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -ErrorAction Stop

    if ($telemetry.AllowTelemetry -eq 0) {
      [void]$reasons.Add('Telemetry disabled via policy')
    }
  }
  catch {
    [void]$reasons.Add('Telemetry policy not set')
  }

  # ✅ Check Application Experience service/task folder existence
  if (-not (Test-Path "$env:SystemRoot\System32\Tasks\Microsoft\Windows\Application Experience")) {
    [void]$reasons.Add('Application Experience tasks missing')
  }

  if ($reasons.Count -eq 0) {
    return 'Unknown cause'
  }

  return ($reasons -join '; ')
}

# -------------------------
# Verdict engine
# -------------------------
function Get-DeviceVerdict {
  param(
    [string]$Computer,
    [array]$ComputerFindings
  )

  # =========================================
  # ✅ Pre-checks: critical evaluation blockers
  # =========================================

  $hasAppraiserIssue = $ComputerFindings | Where-Object {
    $_.Setting -eq 'MicrosoftCompatibilityAppraiser' -and $_.Severity -eq 'WARNING'
  }

  $hasWUServiceIssue = $ComputerFindings | Where-Object {
    $_.Setting -eq 'wuauserv' -and $_.Severity -eq 'WARNING'
  }

  # ✅ NOT EVALUATED (Appraiser missing + WU inactive)
  if ($hasAppraiserIssue -and $hasWUServiceIssue) {
    return @{
      Computer = $Computer
      Verdict  = 'NOT EVALUATED'
      Reason   = 'Appraiser unavailable and Windows Update inactive'
    }
  }

  # ✅ Appraiser missing only
  if ($hasAppraiserIssue) {
    return @{
      Computer = $Computer
      Verdict  = 'NOT READY'
      Reason   = 'Compatibility Appraiser unavailable'
    }
  }

  # ✅ WU service stopped only
  if ($hasWUServiceIssue) {
    return @{
      Computer = $Computer
      Verdict  = 'DELAYED'
      Reason   = 'Windows Update service not running'
    }
  }

  # =========================================
  # ✅ Existing evaluation logic (unchanged)
  # =========================================
  # Check for upgrade blockers (hardware / policy / etc.)
  $blockingFindings = @($ComputerFindings | Where-Object {
      $_.Severity -in @('WARN', 'WARNING', 'ERROR', 'FAIL')
    })

  if ($blockingFindings) {


    $reasons = ($blockingFindings | Select-Object -ExpandProperty Setting -Unique)
    return @{
      Computer = $Computer
      Verdict  = 'BLOCKED'
      Reason   = ($reasons -join ', ')
    }
  }

  # =========================================
  # ✅ Default: Ready
  # =========================================

  return @{
    Computer = $Computer
    Verdict  = 'READY'
    Reason   = 'No obvious blockers detected in checked signals'
  }
}

function Get-UpgradeReadiness {
  param(
    [object[]]$ComputerFindings
  )

  # Normalize input
  $f = @($ComputerFindings)

  # =========================================
  # ✅ Safeguard / Gated detection
  # =========================================

  $gated = @($f | Where-Object { $_.Setting -eq 'UpgradeExperienceIndicators(Gated*)' })

  $hasDriverBlock = $false
  $hasAppBlock = $false
  $hasSafeguard = $false

  if ($gated.Count -gt 0) {

    foreach ($g in $gated) {

      $status = $g.Status

      if ($status -match 'Reason=Driver') {
        $hasDriverBlock = $true
      }
      elseif ($status -match 'Reason=App') {
        $hasAppBlock = $true
      }
      elseif ($status -match 'Reason=Safeguard') {
        $hasSafeguard = $true
      }
    }
  }

  # =========================================
  # ✅ Policy-based blockers
  # =========================================

  $hasPolicyBlock = $f | Where-Object {
    $_.Setting -eq 'DisableOSUpgrade' -and $_.Severity -eq 'CRITICAL'
  }

  # =========================================
  # ✅ Appraiser / evaluation state
  # =========================================

  $hasAppraiserIssue = $f | Where-Object {
    $_.Setting -eq 'MicrosoftCompatibilityAppraiser' -and $_.Severity -eq 'WARNING'
  }

  # =========================================
  # ✅ Final classification (ORDER MATTERS)
  # =========================================

  # ✅ NOT EVALUATED — MUST BE FIRST
  if ($hasAppraiserIssue) {
    return [pscustomobject]@{
      Status = 'NotEvaluated'
      Reason = 'Appraiser missing or not run'
    }
  }

  # ✅ Blocking conditions
  if ($hasDriverBlock) {
    return [pscustomobject]@{
      Status = 'Blocked'
      Reason = 'Driver'
    }
  }

  if ($hasAppBlock) {
    return [pscustomobject]@{
      Status = 'Blocked'
      Reason = 'Application'
    }
  }

  if ($hasPolicyBlock) {
    return [pscustomobject]@{
      Status = 'Blocked'
      Reason = 'Policy'
    }
  }

  # ✅ Safeguard hold
  if ($hasSafeguard) {
    return [pscustomobject]@{
      Status = 'Safeguarded'
      Reason = 'Microsoft safeguard hold'
    }
  }

  # ✅ Ready state (only if real data exists)
  if ($gated.Count -gt 0) {
    return [pscustomobject]@{
      Status = 'Ready'
      Reason = 'No blockers detected'
    }
  }

  # ✅ Fallback (no signals at all)
  return [pscustomobject]@{
    Status = 'Unknown'
    Reason = 'No data'
  }
}

function Get-UpgradeExperienceIndicators {
  param([string]$TargetComputer)

  $basePath = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TargetVersionUpgradeExperienceIndicators'

  $result = [pscustomobject]@{
    VersionKey         = $null
    UpgEx              = $null
    RedReason          = $null
    SystemDriveTooFull = $null
    GatedBlockId       = $null
    GatedBlockReason   = $null
    GatedFeature       = $null
  }

  try {
    # ✅ Get subkeys (use your safe registry reader pattern)
    $rk = Get-Item -Path ("Registry::HKEY_LOCAL_MACHINE\" + $basePath) -ErrorAction Stop

    $subkeys = $rk.GetSubKeyNames()

    if (-not $subkeys -or $subkeys.Count -eq 0) {
      return $null
    }

    # ✅ Filter out UNV
    $validKeys = $subkeys | Where-Object { $_ -ne 'UNV' }

    # ✅ --- INSERT YOUR BLOCK HERE ---
    if ($subkeys -contains 'UNV' -and $validKeys.Count -eq 0) {
      Write-DebugLog "[UPG] Only UNV key present (Appraiser has not populated upgrade data)"
      return $null
    }

    # ✅ Fallback if nothing left
    if (-not $validKeys -or $validKeys.Count -eq 0) {
      return $null
    }

    # ✅ Select latest real key
    $sub = $validKeys | Sort-Object -Descending | Select-Object -First 1
    $result.VersionKey = $sub

    $fullPath = "$basePath\$sub"

    # ✅ Read values (PS native)
    $vals = Get-ItemProperty -Path ("Registry::HKEY_LOCAL_MACHINE\" + $fullPath) -ErrorAction Stop

    if ($vals.UpgEx) { $result.UpgEx = $vals.UpgEx }
    if ($vals.RedReason) { $result.RedReason = $vals.RedReason }
    if ($vals.SystemDriveTooFull) { $result.SystemDriveTooFull = $vals.SystemDriveTooFull }
    if ($vals.GatedBlockId) { $result.GatedBlockId = $vals.GatedBlockId }
    if ($vals.GatedBlockReason) { $result.GatedBlockReason = $vals.GatedBlockReason }
    if ($vals.GatedFeature) { $result.GatedFeature = $vals.GatedFeature }

  }
  catch {}

  return $result
}


# -------------------------
# Common Windows Update error code hints (small, actionable)
# -------------------------
$WUErrorHintMap = @{
  '0x8024402C' = 'Name not resolved / connectivity to WU/WSUS (DNS/proxy). Check DNS resolution and proxy settings.'
  '0x8024001E' = ("Windows Update installation failed due to various causes (service disruption/restart/task/WSUS)." + [Environment]::NewLine +
    "Check UpdateSessionOrchestrator logs and WSUS health.")
  '0x80070013' = ("Write-protected or blocked write scenario" + [Environment]::NewLine +
    "Common causes: AV interference, storage protection, lack of stoorage space or driver conflict" + [Environment]::NewLine +
    "Check endpoint protection and disk state")
  '0x8024500C' = ("Update redirection blocked by policy (connection policy)." + [Environment]::NewLine +
    "Often caused by Windows Update policies (e.g., intranet-only / no internet WU locations).")
  '0x800f081f' = ("CBS source missing (component store/source files missing)." + [Environment]::NewLine + 
    "Repair component store (DISM/SFC) or use correct source.")
  '0x80072EE7' = 'Name resolution / network/DNS issue. Check TCP/IPv4 DNS configuration and resolution.'
  '0x80240438' = ("Update or Microsoft Store error that indicates a network connectivity issue or" + [Environment]::NewLine +
    "a misconfigured update component blocking your PC from communicating with Microsoft servers.")
  '0x80248014' = ("Usually indicates broken or corrupt Windows Update files, often preventing updates or Microsoft Store downloads." + [Environment]::NewLine +
    "Fix it by running the Windows Update Troubleshooter, clearing the SoftwareDistribution cache, or running SFC/DISM scans.")
  '0x80080005' = ("Usually indicates an access denied or server execution failure, which most commonly blocks the system from installing updates." + [Environment]::NewLine + 
    "It is generally caused by permission issues, file corruption, or interference from third-party antivirus software.")
  '0x80070570' = ("In Windows means a file or directory is corrupted, unreadable, or missing." + [Environment]::NewLine +
    "It commonly appears when you are trying to delete, move, or copy files, update Windows, or install a new OS.")
  '0x80244011' = ("Corresponds to code WU_E_PT_SUS_SERVER_NOT_SET, meaning your device cannot find the WSUS address in its registry.")
}

function Get-WUErrorHint {
  param([string]$Code)

  if ([string]::IsNullOrWhiteSpace($Code)) {
    return $null
  }

  $c = $Code.ToUpperInvariant()

  if ($WUErrorHintMap.ContainsKey($c)) {
    return $WUErrorHintMap[$c]
  }

  return $null
}

# -------------------------
# Build targets
# -------------------------
$targets = @()
if ($ComputerList -and @($ComputerList).Count -gt 0) { $targets = $ComputerList }
else { $targets = @($ComputerName) }

$SingleDeviceMode = (@($targets).Count -eq 1)

$findings = New-Object System.Collections.Generic.List[object]

# -------------------------
# Main loop
# -------------------------
foreach ($t in $targets) {

  # --- Registry map ---
  foreach ($item in $RegMap) {

    $read = Get-RegValueSafe -TargetComputer $t -Hive $item.Hive -KeyPath $item.KeyPath -ValueName $item.ValueName

    $presentStatus = 'Error'
    if ($read.Present -eq $true) { $presentStatus = 'Present' }
    elseif ($read.Present -eq $false) { $presentStatus = 'NotPresent' }

    if (-not $IncludeMissing -and $presentStatus -eq 'NotPresent') { continue }

    if ($presentStatus -eq 'Error') {
      $findings.Add((New-Finding -Computer $t -Area $item.Area -Severity 'INFO' -Setting $item.ValueName -Value $null -Status 'ERROR reading registry' -Fix $read.Error -Source 'Registry')) | Out-Null
      continue
    }

    if ($presentStatus -eq 'NotPresent') {
      $findings.Add((New-Finding -Computer $t -Area $item.Area -Severity 'OK' -Setting $item.ValueName -Value $null -Status 'Not present' -Fix '' -Source 'Registry')) | Out-Null
      continue
    }


    $cls = Classify-RegFinding -ValueName $item.ValueName -Value $read.Value
    $st = $cls.Status

    # ✅ Only fall back if classifier explicitly returns nothing
    if ([string]::IsNullOrWhiteSpace($st) -or $st -eq 'OK') {
      $st = $item.Meaning
    }


    $findings.Add((New-Finding -Computer $t -Area $item.Area -Severity $cls.Severity -Setting $item.ValueName -Value $read.Value -Status $st -Fix $cls.Fix -Source 'Registry')) | Out-Null
  }

  # --- PolicyManager effective values ---
  foreach ($pv in $PolicyManagerValues) {

    $r = Get-RegValueSafe -TargetComputer $t -Hive 'HKLM' -KeyPath $PolicyManagerKey -ValueName $pv

    if (-not $IncludeMissing -and $r.Present -eq $false) { continue }

    if ($r.Present -eq $true) {
      $cls = Classify-RegFinding -ValueName $pv -Value $r.Value
      $sev = $cls.Severity
      if ($sev -eq 'OK') { $sev = 'INFO' }
      $st = $cls.Status

      if ([string]::IsNullOrWhiteSpace($st) -or $st -eq 'OK') {
        $st = 'Effective policy value set (PolicyManager)'
      }

      $findings.Add((New-Finding -Computer $t -Area 'EffectivePolicy(PolicyManager)' -Severity $sev -Setting $pv -Value $r.Value -Status $st -Fix $cls.Fix -Source 'PolicyManager')) | Out-Null
    }
    elseif ($IncludeMissing) {
      $findings.Add((New-Finding -Computer $t -Area 'EffectivePolicy(PolicyManager)' -Severity 'OK' -Setting $pv -Value $null -Status 'Not present' -Fix '' -Source 'PolicyManager')) | Out-Null
    }
  }

  # --- OS baseline ---
  $osSig = Get-OSSignals -TargetComputer $t
  if ($osSig.Caption -or $osSig.Version -or $osSig.Build) {
    $findings.Add((New-Finding -Computer $t -Area 'OS' -Severity 'INFO' -Setting 'OS' -Value ($osSig.Caption) -Status ("{0} ({1} build {2})" -f $osSig.Caption, $osSig.Version, $osSig.Build) -Fix '' -Source 'CIM')) | Out-Null

    # Win10 upgrade baseline heuristic: build 19041 = 2004
    try {
      $b = [int]$osSig.Build
      if ($b -lt 19041) {
        $findings.Add((New-Finding -Computer $t -Area 'OS' -Severity 'CRITICAL' -Setting 'OSBaseline' -Value $osSig.Build -Status 'BLOCKED: OS build below Win10 2004 baseline (heuristic)' -Fix 'Update Windows 10 to 2004+ before expecting Windows 11 offer' -Source 'CIM')) | Out-Null
      }
    }
    catch { }
  }
  elseif ($osSig.Errors) {
    $findings.Add((New-Finding -Computer $t -Area 'OS' -Severity 'INFO' -Setting 'OS' -Value $null -Status 'NotChecked/Unavailable' -Fix $osSig.Errors -Source 'CIM')) | Out-Null
  }

  # --- Hardware signals ---
  $hw = Get-HardwareSignals -TargetComputer $t

  # CPU (show value in Status so it actually renders in your table)
  if (-not [string]::IsNullOrWhiteSpace($hw.CpuName)) {

    $findings.Add((New-Finding -Computer $t -Area 'Hardware' -Severity 'INFO' -Setting 'CPU' -Value $null -Status ("CPU detected: {0}" -f $hw.CpuName) -Fix '' -Source 'Hardware')) | Out-Null

    $cpuH = Get-CPUHeuristic -CpuName $hw.CpuName
    $findings.Add((New-Finding -Computer $t -Area 'Hardware' -Severity $cpuH.Severity -Setting 'CPUHeuristic' -Value $null -Status ("{0}; CPU support: {1} (heuristic)" -f $cpuH.Detail, $cpuH.Verdict) -Fix 'If flagged, verify against official supported CPU lists/PC Health Check' -Source 'Heuristic')) | Out-Null

  }
  elseif ($IncludeMissing) {
    $findings.Add((New-Finding -Computer $t -Area 'Hardware' -Severity 'INFO' -Setting 'CPU' -Value $null -Status 'NotChecked/Unavailable' -Fix '' -Source 'Hardware')) | Out-Null
  }

  # RAM
  if ($hw.RamGB -ne $null) {

    $sev = 'INFO'
    $fix = ''
    $st = ("Memory: {0:N1} GB" -f $hw.RamGB)

    if ($hw.RamGB -lt 4) {
      $sev = 'CRITICAL'
      $st = ("Memory too low: {0:N1} GB (minimum 4.0 GB)" -f $hw.RamGB)
      $fix = 'Increase RAM to meet Windows 11 minimum'
    }

    $findings.Add((New-Finding -Computer $t -Area 'Hardware' -Severity $sev -Setting 'RAM_GB' -Value $null -Status $st -Fix $fix -Source 'Hardware')) | Out-Null

  }
  elseif ($IncludeMissing) {
    $findings.Add((New-Finding -Computer $t -Area 'Hardware' -Severity 'INFO' -Setting 'RAM_GB' -Value $null -Status 'NotChecked/Unavailable' -Fix '' -Source 'Hardware')) | Out-Null
  }

  # System disk size + free space
  if ($hw.SysDriveGB -ne $null) {

    $sev = 'INFO'
    $fix = ''
    $st = ("System disk size: {0:N1} GB" -f $hw.SysDriveGB)

    if ($hw.SysDriveGB -lt 64) {
      $sev = 'CRITICAL'
      $st = ("System disk size too small: {0:N1} GB (minimum 64.0 GB)" -f $hw.SysDriveGB)
      $fix = 'Increase system disk size to meet Windows 11 minimum'
    }

    $findings.Add((New-Finding -Computer $t -Area 'Hardware' -Severity $sev -Setting 'SystemDisk_GB' -Value $null -Status $st -Fix $fix -Source 'Hardware')) | Out-Null

  }
  elseif ($IncludeMissing) {
    $findings.Add((New-Finding -Computer $t -Area 'Hardware' -Severity 'INFO' -Setting 'SystemDisk_GB' -Value $null -Status 'NotChecked/Unavailable' -Fix '' -Source 'Hardware')) | Out-Null
  }

  if ($hw.SysFreeGB -ne $null) {

    $sev = 'INFO'
    $fix = ''
    $st = ("Free space: {0:N1} GB" -f $hw.SysFreeGB)

    if ($hw.SysFreeGB -lt 20) {
      $sev = 'WARNING'
      $st = ("Low free space: {0:N1} GB (may block upgrade)" -f $hw.SysFreeGB)
      $fix = 'Free up space (aim 20GB+ free) and retry'
    }

    $findings.Add((New-Finding -Computer $t -Area 'Hardware' -Severity $sev -Setting 'SystemDiskFree_GB' -Value $null -Status $st -Fix $fix -Source 'Hardware')) | Out-Null

  }
  elseif ($IncludeMissing) {
    $findings.Add((New-Finding -Computer $t -Area 'Hardware' -Severity 'INFO' -Setting 'SystemDiskFree_GB' -Value $null -Status 'NotChecked/Unavailable' -Fix '' -Source 'Hardware')) | Out-Null
  }

  # TPM (local-only in many estates)
  if ($hw.TpmPresent -ne $null) {

    $sev = 'INFO'
    $fix = ''
    $st = ("TPM: Present={0}, Ready={1}" -f $hw.TpmPresent, $hw.TpmReady)

    if (-not $hw.TpmPresent -or -not $hw.TpmReady) {
      $sev = 'CRITICAL'
      $st = ("TPM issue: Present={0}, Ready={1}" -f $hw.TpmPresent, $hw.TpmReady)
      $fix = 'Enable TPM in BIOS/UEFI (PTT/fTPM) and ensure it is provisioned'
    }

    $findings.Add((New-Finding -Computer $t -Area 'Hardware' -Severity $sev -Setting 'TPM' -Value $null -Status $st -Fix $fix -Source 'Hardware')) | Out-Null

  }
  elseif ($IncludeMissing) {
    $findings.Add((New-Finding -Computer $t -Area 'Hardware' -Severity 'INFO' -Setting 'TPM' -Value $null -Status 'NotChecked (remote or unavailable)' -Fix 'Run locally for TPM checks' -Source 'Hardware')) | Out-Null
  }

  # Secure Boot (local-only in many estates)
  if ($hw.SecureBoot -ne $null) {

    $sev = 'INFO'
    $fix = ''
    $st = ("Secure Boot: {0}" -f $hw.SecureBoot)

    if (-not $hw.SecureBoot) {
      $sev = 'CRITICAL'
      $st = 'Secure Boot not enabled / not UEFI'
      $fix = 'Switch to UEFI boot + enable Secure Boot in firmware'
    }

    $findings.Add((New-Finding -Computer $t -Area 'Hardware' -Severity $sev -Setting 'SecureBootUEFI' -Value $null -Status $st -Fix $fix -Source 'Hardware')) | Out-Null

  }
  elseif ($IncludeMissing) {
    $findings.Add((New-Finding -Computer $t -Area 'Hardware' -Severity 'INFO' -Setting 'SecureBootUEFI' -Value $null -Status 'NotChecked (remote or unavailable)' -Fix 'Run locally (Confirm-SecureBootUEFI is local)' -Source 'Hardware')) | Out-Null
  }

  # Partition style (local-only)
  if (-not [string]::IsNullOrWhiteSpace([string]$hw.PartitionStyle)) {

    $sev = 'INFO'
    $fix = ''
    $st = ("Partition style: {0}" -f $hw.PartitionStyle)

    if ($hw.PartitionStyle -eq 'MBR') {
      $sev = 'WARNING'
      $st = 'MBR detected (UEFI/GPT recommended for Windows 11)'
      $fix = 'Consider MBR2GPT conversion + UEFI boot where supported'
    }

    $findings.Add((New-Finding -Computer $t -Area 'Hardware' -Severity $sev -Setting 'PartitionStyle' -Value $null -Status $st -Fix $fix -Source 'Hardware')) | Out-Null

  }
  elseif ($IncludeMissing) {
    $findings.Add((New-Finding -Computer $t -Area 'Hardware' -Severity 'INFO' -Setting 'PartitionStyle' -Value $null -Status 'NotChecked (remote or unavailable)' -Fix 'Run locally to verify GPT/UEFI' -Source 'Hardware')) | Out-Null
  }

  # Hardware error summariser (only outputs if something meaningful exists)
  if (-not [string]::IsNullOrWhiteSpace($hw.Errors)) {

    $errorList = @($hw.Errors -split '\s*\|\s*')
    $winRMErrors = @($errorList | Where-Object { $_ -like 'WinRMUnavailable:*' })
    $otherErrors = @($errorList | Where-Object { $_ -notlike 'WinRMUnavailable:*' -and $_ -notlike 'NotCheckedRemote:*' })

    if ($winRMErrors.Count -gt 0) {
      $components = ($winRMErrors | ForEach-Object { ($_ -split ':')[1] }) -join ', '
      $findings.Add((New-Finding -Computer $t -Area 'Hardware' -Severity 'INFO' -Setting 'HardwareAccess' -Value $null -Status ("Hardware checks skipped (WinRM unavailable: {0})" -f $components) -Fix 'Run locally or enable WinRM/CIM for remote hardware checks' -Source 'Hardware')) | Out-Null
    }

    if ($otherErrors.Count -gt 0) {
      $findings.Add((New-Finding -Computer $t -Area 'Hardware' -Severity 'INFO' -Setting 'HardwareQueryNotes' -Value $null -Status ("Hardware query notes: {0}" -f ($otherErrors -join ' | ')) -Fix 'Check CIM/permissions/connectivity' -Source 'Hardware')) | Out-Null
    }
  }

  # --- Compatibility Appraiser ---
  $app = Get-CompatAppraiserState -TargetComputer $t

  if ($app.Checked) {
    $details = @()
    $state = [string]$app.State
    $lastRun = [string]$app.LastRunTime
    $result = [string]$app.LastResult

    # ✅ Detect empty / not populated appraiser data
    if ([string]::IsNullOrWhiteSpace($state) -and
      [string]::IsNullOrWhiteSpace($lastRun) -and
      [string]::IsNullOrWhiteSpace($result)) {
      $reason = Get-AppraiserFailureReason -TargetComputer $t

      # ✅ Primary + full breakdown
      $parts = @($reason -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
      $primary = $parts | Select-Object -First 1

      $sev = 'WARNING'
      $st = 'No data available (Appraiser has not populated results)'

      # ✅ Clean primary action
      $fix = ("Investigate Appraiser: {0}" -f $primary)

      # ✅ Always add full detail line
      if ($parts.Count -gt 1) {
        $details = ("Details: {0}" -f ($parts -join '; '))
      }
    }
    else {

      $sev = 'INFO'
      $st = ("State={0}; LastRun={1}; Result={2}" -f $state, $lastRun, $result)
      $fix = $null

      # ✅ Staleness heuristic (local only)
      if (Get-IsLocalTarget $t) {
        try {
          $dt = [datetime]$lastRun
          if ($dt -lt (Get-Date).AddDays(-14)) {
            $sev = 'WARNING'
            $st = ("Appraiser stale (last run: {0})" -f $dt)
            $fix = 'Re-run Compatibility Appraiser scheduled task'
          }
        }
        catch { }
      }
    }

    $findings.Add((New-Finding `
          -Computer $t `
          -Area 'Compatibility' `
          -Severity $sev `
          -Setting 'MicrosoftCompatibilityAppraiser' `
          -Value $state `
          -Status $st `
          -Fix $fix `
          -Details $details `
          -Source 'ScheduledTask')) | Out-Null
  }
  else {
    $sev = 'WARNING'
    $status = 'Compatibility Appraiser task missing or inaccessible'

    # ✅ Detect specific case (task missing)
    if ($app.Error -match 'cannot find the file specified') {
      $fix = 'Task not present. Likely disabled by policy (telemetry/Application Experience). Verify GPO or rebuild component.'
    }
    else {
      $fix = $app.Error
    }

    $findings.Add((New-Finding `
          -Computer $t `
          -Area 'Compatibility' `
          -Severity $sev `
          -Setting 'MicrosoftCompatibilityAppraiser' `
          -Value $null `
          -Status $status `
          -Fix $fix `
          -Source 'ScheduledTask')) | Out-Null
  }

  # --- Upgrade Experience Indicators (Gated*) ---
  $uei = Get-UpgradeExperienceIndicatorsSafe -TargetComputer $t
  if ($uei.Checked -and @($uei.Items).Count -gt 0) {
    # --- Hardened Gated output (noise-free) ---
    $grouped = @{}
    $severity = 'INFO'      # default: no problems
    $hasRealBlock = $false

    foreach ($item in $uei.Items) {

      $release = $item.ReleaseKey
      if ([string]::IsNullOrWhiteSpace($release)) { continue }

      if (-not $grouped.ContainsKey($release)) {
        $grouped[$release] = New-Object System.Collections.ArrayList
      }

      # Normalise value (flatten arrays)
      $value = $item.Value
      if ($value -is [array]) { $value = ($value -join ', ') }
      if ($null -ne $value) { $value = ($value.ToString() -replace '\r|\n', ' ').Trim() }

      # Drop noise
      if ([string]::IsNullOrWhiteSpace($value)) { continue }
      if ($value -eq 'None') { continue }

      # Ignore non-actionable metadata (this is the main noise source)
      if ($item.ValueName -eq 'GatedFeature') { continue }

      # Severity detection (only on real reasons)
      if ($item.ValueName -in @('GatedReason', 'GatedBlockReason')) {

        switch ($value) {
          'Driver' {
            $severity = 'CRITICAL'
            $hasRealBlock = $true
          }
          'App' {
            if ($severity -ne 'CRITICAL') { $severity = 'WARNING' }
            $hasRealBlock = $true
          }
          'Safeguard' {
            if ($severity -ne 'CRITICAL') { $severity = 'WARNING' }
            $hasRealBlock = $true
          }
          default {
            # Unknown reason -> treat as warning (still a potential block)
            if ($severity -ne 'CRITICAL') { $severity = 'WARNING' }
            $hasRealBlock = $true
          }
        }
      }

      # Only keep a small set of fields that are useful for actioning
      $entry = switch ($item.ValueName) {
        'GatedBlockId' { "BlockId=$value" }
        'GatedReason' { "Reason=$value" }
        'GatedBlockReason' { "Reason=$value" }
        'GatedDriver' { "DriverBlock=$value" }
        'GatedApp' { "AppBlock=$value" }
        'GatedStatus' { "Status=$value" }
        default { $null }   # drop everything else
      }

      if (-not [string]::IsNullOrWhiteSpace($entry)) {
        [void]$grouped[$release].Add($entry)
      }
    }

    # --- Upgrade Experience Indicators ---
    #Write-DebugLog ("[UPG] Checking Upgrade Experience Indicators | Computer={0}" -f $t)

    $upg = Get-UpgradeExperienceIndicators -TargetComputer $t

    if ($upg) {

      #Write-DebugLog ("[UPG] Found version key: {0} | UpgEx={1} | RedReason={2}" -f $upg.VersionKey, $upg.UpgEx, $upg.RedReason)

      # ✅ Default
      $fix = $null

      # ✅ Handle UNV / not evaluated case
      if (-not $upg.UpgEx -and -not $upg.RedReason) {

        Write-DebugLog "[UPG] No usable upgrade data (likely UNV / appraiser not run)"

        $sev = 'INFO'
        $status = 'Not evaluated (Appraiser data missing)'
        $value = 'Unknown'
        $fix = 'Run Compatibility Appraiser scheduled task'

      }
      else {

        # ✅ Determine base status
        if ($upg.UpgEx -eq 'Green' -and ($upg.RedReason -eq 'None' -or -not $upg.RedReason)) {
          $sev = 'OK'
          $status = 'Upgrade ready'
          $value = $upg.VersionKey
        }
        else {
          $sev = 'WARNING'
          $status = ("Blocked: {0}" -f $upg.RedReason)
          $value = $upg.VersionKey
          $fix = 'Review compatibility blockers or safeguard holds'
        }

        # ✅ Disk issue overlay
        if ($upg.SystemDriveTooFull -eq 1) {
          $status += ' | Disk too full'
          $sev = 'WARNING'
          $fix = 'Free space on system drive'
        }

        # ✅ Safeguard hold overlay (FIXED properly)
        if ($upg.GatedBlockId -and $upg.GatedBlockId -ne 'None') {

          $status += (" | SafeguardId={0}" -f $upg.GatedBlockId)

          if ($upg.GatedBlockReason -and $upg.GatedBlockReason -ne 'None') {
            $status += (" ({0})" -f $upg.GatedBlockReason)
          }

          $sev = 'WARNING'
          $fix = 'Review safeguard hold details or wait for Microsoft fix'
        }
      }

      # ✅ Final output — Fix only passed if needed
      $findings.Add((New-Finding `
            -Computer $t `
            -Area 'Compatibility' `
            -Severity $sev `
            -Setting 'UpgradeReadiness' `
            -Value $value `
            -Status $status `
            -Fix $fix `
            -Source 'Registry')) | Out-Null
    }
    else {
      Write-DebugLog ("[UPG] No Upgrade Experience Indicators found | Computer={0}" -f $t)
    }

    # --- Safeguard bypass policy check ---
    $disableSafeguards = $null

    try {
      $wuPol = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction Stop
      $disableSafeguards = $wuPol.DisableWUfBSafeguards
    }
    catch {}

    if ($disableSafeguards -eq 1) {

      Write-DebugLog "[UPG] Safeguard holds are DISABLED via policy"

      $findings.Add((New-Finding `
            -Computer $t `
            -Area 'Policy' `
            -Severity 'WARN' `
            -Setting 'DisableWUfBSafeguards' `
            -Value 'Enabled' `
            -Status 'Safeguards bypassed (device may ignore upgrade blocks)' `
            -Fix 'Re-enable safeguard holds unless explicitly required' `
            -Source 'Registry')) | Out-Null
    }

    # --- Pending reboot check ---
    $rb = Test-PendingReboot -TargetComputer $t

    if ($rb.UptimeDays -ge 3 -and $rb.Required -and $rb.State -eq 'Hard') {
      $rb.Severity = 'CRITICAL'
    }


    if ($rb.Required) {

      $suffix = ''
      if ($rb.UptimeDays -ne $null) {
        $suffix = (" ({0} days)" -f $rb.UptimeDays)
      }

      if ($rb.State -eq 'Soft') {

        $st = ("Pending file operations{0} (may not require reboot)" -f $suffix)

      }
      else {

        $st = ("Pending reboot{0}: {1}" -f $suffix, $rb.Reasons)
      }

      $findings.Add((New-Finding -Computer $t -Area 'Services' -Severity $rb.Severity -Setting 'PendingReboot' -Value $null -Status $st -Fix 'Reboot the device to clear update/install state' -Source 'Registry')) | Out-Null

    }
    elseif ($IncludeMissing) {

      $findings.Add((New-Finding -Computer $t -Area 'Services' -Severity 'OK' -Setting 'PendingReboot' -Value $null -Status 'No reboot pending' -Fix '' -Source 'Registry')) | Out-Null
    }

    # Build output: only releases with at least one actionable entry
    $lines = @()
    foreach ($release in ($grouped.Keys | Sort-Object)) {
      if ($grouped[$release].Count -gt 0) {
        # de-dupe per release
        $uniq = @($grouped[$release] | Select-Object -Unique)
        $lines += ("{0}: {1}" -f $release, ($uniq -join ' | '))
      }
    }

    # Final result
    if ($lines.Count -eq 0) {
      $sample = 'No problems found'
      $severity = 'INFO'
    }
    else {
      # If we have output but no real block detected, keep INFO (e.g., status fields only)
      if (-not $hasRealBlock) { $severity = 'INFO' }
      $sample = ($lines -join [Environment]::NewLine)
    }

    $findings.Add((New-Finding -Computer $t -Area 'Safeguard/Compat' -Severity $severity -Setting 'UpgradeExperienceIndicators(Gated*)' -Value $null -Status $sample -Fix 'Resolve compatibility issue / safeguard hold; re-run appraiser' -Source 'Registry')) | Out-Null
  }
  elseif (-not $uei.Checked) {
    $findings.Add((New-Finding -Computer $t -Area 'Safeguard/Compat' -Severity 'INFO' -Setting 'UpgradeExperienceIndicators' -Value $null -Status 'NotChecked/AccessDenied reading indicators' -Fix $uei.Error -Source 'Registry')) | Out-Null
  }
  elseif ($IncludeMissing) {
    $findings.Add((New-Finding -Computer $t -Area 'Safeguard/Compat' -Severity 'OK' -Setting 'UpgradeExperienceIndicators(Gated*)' -Value $null -Status 'No Gated* values found' -Fix '' -Source 'Registry')) | Out-Null
  }

  # --- Services health ---
  foreach ($svcName in @('wuauserv', 'UsoSvc', 'WaaSMedicSvc', 'BITS', 'CryptSvc')) {

    $svc = Get-ServiceStateSafe -TargetComputer $t -Name $svcName

    # --- Only output if NOT running or failed ---
    if ($svc.Checked -and $svc.Status -ne 'Running') {

      $sev = 'INFO'
      $fix = ''

      if ($svcName -in @('wuauserv', 'UsoSvc')) {
        $sev = 'WARNING'
        $fix = 'Start service and retry scan; investigate if it keeps stopping'
      }

      $findings.Add((New-Finding -Computer $t -Area 'Services' -Severity $sev -Setting $svcName -Value $null -Status ("Service NOT running: {0}" -f $svc.Status) -Fix $fix -Source 'ServiceControl')) | Out-Null
    }
    elseif (-not $svc.Checked) {

      $findings.Add((New-Finding -Computer $t -Area 'Services' -Severity 'INFO' -Setting $svcName -Value $null -Status 'NotChecked/AccessDenied' -Fix $svc.Error -Source 'ServiceControl')) | Out-Null
    }
  }

  # --- WU event log signals ---
  $ev = Get-WUEventSignals -TargetComputer $t

  if ($ev.Checked) {

    # --- Last scan / activity ---
    if ($ev.LastEventTime) {

      $ageDays = [int]((Get-Date) - $ev.LastEventTime).TotalDays

      $sev = 'INFO'
      $fix = ''

      $st = ("Last scan activity: {0} ({1} days ago)" -f $ev.LastEventTime, $ageDays)

      if ($ageDays -ge 14) {
        $sev = 'WARNING'
        $st = ("STALE: Last scan {0} days ago ({1})" -f $ageDays, $ev.LastEventTime)
        $fix = 'Trigger scan / check services / connectivity'
      }

      $findings.Add((New-Finding -Computer $t -Area 'WindowsUpdateClientLog' -Severity $sev -Setting 'LastWUEventTime' -Value $null -Status $st -Fix $fix -Source 'EventLog')) | Out-Null

    }
    elseif ($IncludeMissing) {

      $findings.Add((New-Finding -Computer $t -Area 'WindowsUpdateClientLog' -Severity 'INFO' -Setting 'LastWUEventTime' -Value $null -Status 'NotChecked/Unavailable' -Fix '' -Source 'EventLog')) | Out-Null
    }

    # --- Recent WU error (ENHANCED VERSION) ---
    if (-not [string]::IsNullOrWhiteSpace($ev.LastErrorMessage)) {

      $msg = $ev.LastErrorMessage

      # Normalize
      $msg = ($msg -replace '\r|\n', ' ').Trim()

      # Truncate
      if (-not [string]::IsNullOrWhiteSpace($msg) -and $msg.Length -gt 120) {
        $msg = $msg.Substring(0, 117) + '...'
      }

      # Enhanced output with ID + Level
      if ($ev.LastErrorTime) {

        if ($ev.LastErrorCode) {
          $st = ("Last event: {0} | ID: {1} | Level: {2} | Code: {3} | {4}" -f $ev.LastErrorTime, $ev.LastErrorId, $ev.LastErrorLevel, $ev.LastErrorCode, $msg)
        }
        else {
          $st = ("Last event: {0} | ID: {1} | Level: {2} | {3}" -f $ev.LastErrorTime, $ev.LastErrorId, $ev.LastErrorLevel, $msg)
        }

      }
      else {
        $st = $msg
      }

      $findings.Add((New-Finding -Computer $t -Area 'WindowsUpdateClientLog' -Severity 'INFO' -Setting 'RecentWUError' -Value $null -Status $st -Fix 'Use this message to guide next step' -Source 'EventLog')) | Out-Null
    }
    elseif ($IncludeMissing) {

      $findings.Add((New-Finding -Computer $t -Area 'WindowsUpdateClientLog' -Severity 'OK' -Setting 'RecentWUError' -Value $null -Status 'No recent error events captured' -Fix '' -Source 'EventLog')) | Out-Null
    }

  }
  else {

    $findings.Add((New-Finding -Computer $t -Area 'WindowsUpdateClientLog' -Severity 'INFO' -Setting 'WindowsUpdateClientLog' -Value $null -Status 'NotChecked/AccessDenied' -Fix $ev.Error -Source 'EventLog')) | Out-Null
  }
}

# -------------------------
# Output: top banner + table + troubleshooting summary
# -------------------------
# --- Logical section order ---
$areaOrder = @(
  'Policy(Targeting)',
  'Policy(Deferral)',
  'Policy(UpdateSource)',
  'Policy(ScanSource)',
  'Policy(UpdateAccess)',
  'EffectivePolicy(PolicyManager)',
  'OS',
  'Hardware',
  'Compatibility',
  'Safeguard/Compat',
  'Services',
  'WindowsUpdateClientLog'
)

$sorted = $findings | Sort-Object Computer, Severity, Area, Setting
if ($OnlyProblems) { $sorted = $sorted | Where-Object { $_.Severity -ne 'OK' } }

# Wide columns (less truncation)
$wSev = 8
$wSetting = 48
$wStatus = 100
$wComputer = 18

# Top banner (single-device)
if ($SingleDeviceMode) {
  $comp = $targets[0]
  $group = @($findings | Where-Object { $_.Computer -eq $comp })

  $summary = Get-DeviceSummary -TargetComputer $comp
  $verdict = Get-DeviceVerdict -Computer $comp -ComputerFindings $group
  $wuMode = Get-UpdateSourceMode -ComputerFindings $group
  $upgrade = Get-UpgradeReadiness -ComputerFindings $group

  $osRow = $group | Where-Object { $_.Area -eq 'OS' -and $_.Setting -eq 'OS' } | Select-Object -First 1

  Write-Host ''
  Write-Host '=== DEVICE SUMMARY ===' -ForegroundColor Cyan
  Write-Host ("Computer      : {0}" -f $summary.Computer)
  Write-Host ("Mode          : {0}" -f $summary.Mode)
  if ($summary.Manufacturer) { Write-Host ("Manufacturer  : {0}" -f $summary.Manufacturer) }
  Write-Host ("Model         : {0}" -f $summary.Model)
  if ($osRow -and $osRow.Status) { Write-Host ("OS            : {0}" -f $osRow.Status) }
  if ($summary.User) { Write-Host ("User          : {0}" -f $summary.User) }
  Write-Host ("WU Source     : {0}" -f $wuMode)
  Write-Host ("Verdict       : {0} ({1})" -f $verdict.Verdict, $verdict.Reason)
  Write-Host ("UpgradeStatus : {0} ({1})" -f $upgrade.Status, $upgrade.Reason)
  Write-Host ''
}

# Table header
Write-Host ''
if ($SingleDeviceMode) {
  Write-Host ("{0} | {1} | {2}" -f (TruncPad 'Severity' $wSev), (TruncPad 'Setting' $wSetting), (TruncPad 'Status' $wStatus)) -ForegroundColor Cyan
  Write-Host (("{0}-|-{1}-|-{2}" -f ('-' * $wSev), ('-' * $wSetting), ('-' * $wStatus)))
}
else {
  Write-Host ("{0} | {1} | {2} | {3}" -f (TruncPad 'Computer' $wComputer), (TruncPad 'Severity' $wSev), (TruncPad 'Setting' $wSetting), (TruncPad 'Status' $wStatus)) -ForegroundColor Cyan
  Write-Host (("{0}-|-{1}-|-{2}-|-{3}" -f ('-' * $wComputer), ('-' * $wSev), ('-' * $wSetting), ('-' * $wStatus)))
}

$groupedOutput = $sorted | Group-Object Area | Sort-Object {
  $idx = $areaOrder.IndexOf($_.Name)
  if ($idx -eq -1) { 999 } else { $idx }
}

foreach ($areaGroup in $groupedOutput) {

  
  # ✅ --- HIDE EMPTY SECTIONS HERE ---
  if (-not $areaGroup.Group -or @($areaGroup.Group).Count -eq 0) {
    continue
  }

  Write-Host ''
  Write-Host ("=== {0} ===" -f $areaGroup.Name.ToUpper()) -ForegroundColor Cyan

  foreach ($r in $areaGroup.Group) {

    if ($SingleDeviceMode) {
      $line = "{0} | {1} | {2}" -f (TruncPad $r.Severity $wSev), (TruncPad $r.Setting $wSetting), (TruncPad $r.Status $wStatus)
    }
    else {
      $line = "{0} | {1} | {2} | {3}" -f (TruncPad $r.Computer $wComputer), (TruncPad $r.Severity $wSev), (TruncPad $r.Setting $wSetting), (TruncPad $r.Status $wStatus)
    }

    Write-ColoredLine -Line $line -Severity $r.Severity -NoColor:$NoColor
  }
}

# Troubleshooting summary
Write-Host ''
Write-Host '=== TROUBLESHOOTING SUMMARY ===' -ForegroundColor Cyan
Write-Host ''

$byComputer = $findings | Group-Object Computer

foreach ($g in $byComputer) {

  $ver = Get-DeviceVerdict -Computer $g.Name -ComputerFindings $g.Group

  Write-Host ("{0} -> {1} ({2})" -f $ver.Computer, $ver.Verdict, $ver.Reason) -ForegroundColor Yellow

  # ✅ Only problem findings
  $problems = @(
    $g.Group | Where-Object { $_.Severity -in @('WARN', 'WARNING', 'ERROR', 'FAIL') } | Sort-Object Severity
  )

  if (-not $problems -or $problems.Count -eq 0) {
    Write-Host "  No issues detected"
  }

  foreach ($p in $problems) {

    Write-ColoredLine -Line ("  [{0}] {1} | {2}" -f $p.Severity, $p.Setting, $p.Status) -Severity $p.Severity -NoColor:$NoColor

    # ✅ WU hint (unchanged)
    if ($p.Setting -eq 'RecentWUError') {

      $code = $null
      if ($p.Status -match '0x[0-9A-Fa-f]{6,8}') { $code = $matches[0] }

      $hint = Get-WUErrorHint -Code $code

      if ($hint) {
        $lines = $hint -split "`r?`n"
        foreach ($l in $lines) {
          Write-Host ("         Hint: {0}" -f $l)
        }
      }
    }

    if ($p.Severity -in @('WARN', 'WARNING', 'ERROR', 'FAIL')) {
      if ($p.Fix -and $p.Fix.Trim() -ne '') {
        Write-Host ("         Fix: {0}" -f $p.Fix)
      }
    }
    
    if ($p.PSObject.Properties.Match('Details').Count -gt 0) {
      if ($p.Details -and $p.Details.Trim() -ne '') {
        Write-Host ("         {0}" -f $p.Details)
      }
    }
  }

  Write-Host ''
}

# CSV export
if ($CsvPath) {
  $findings | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $CsvPath
  Write-Host ("Exported CSV to: {0}" -f $CsvPath)
}
