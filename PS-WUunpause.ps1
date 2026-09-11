[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Remediate,
    [switch]$ClearTargetReleaseVersion,
    [switch]$NudgeConfigMgr,
    
    [Alias('v', 'vs')]
    [switch]$VerboseSummary,

    [switch]$Help
)

# --- Help / Usage ---
if ($Help -or $args -contains '/?' -or $args -contains '-?') {
    Write-Host ''
    Write-Host 'Invoke-WUUnblockDiagnose.ps1 - Available switches:' -ForegroundColor Cyan
    Write-Host ''

    Write-Host '  -Remediate                     Perform remediation actions (default: diagnose only)'
    Write-Host '  -ClearTargetReleaseVersion     Remove feature update pinning (TargetReleaseVersion)'
    Write-Host '  -NudgeConfigMgr                Trigger ConfigMgr update cycles (if present)'
    Write-Host '  -VerboseSummary                Show full detailed summary output'
    Write-Host '  -WhatIf                        Simulate changes (no registry/service changes)'
    Write-Host ''

    Write-Host 'What the script checks:' -ForegroundColor Yellow
    Write-Host '  - Windows Update pause (UI and policy-based)'
    Write-Host '  - Feature vs Quality update pause state'
    Write-Host '  - Intune / WUfB / PolicyManager settings'
    Write-Host '  - WSUS / GPO update configuration'
    Write-Host '  - Feature update deferrals'
    Write-Host '  - TargetReleaseVersion pinning / misconfiguration'
    Write-Host '  - Windows Update service state (wuauserv, BITS)'
    Write-Host '  - Pending reboot conditions'
    Write-Host ''

    Write-Host 'Safety behaviour:' -ForegroundColor Yellow
    Write-Host '  - If -Remediate is NOT specified -> script runs in diagnose-only mode'
    Write-Host '  - -WhatIf is honoured for all registry and service changes'
    Write-Host '  - Deferral policies are reported but NOT removed'
    Write-Host '  - UX-only policies are suppressed from normal output'
    Write-Host '  - Policy-based settings may reapply after remediation'
    Write-Host ''

    Write-Host 'Examples:' -ForegroundColor Yellow
    Write-Host '  .\PS-WUunpause.ps1'
    Write-Host '  .\PS-WUunpause.ps1 -VerboseSummary'
    Write-Host '  .\PS-WUunpause.ps1 -Remediate -WhatIf'
    Write-Host '  .\PS-WUunpause.ps1 -Remediate'
    Write-Host '  .\PS-WUunpause.ps1 -Remediate -ClearTargetReleaseVersion'
    Write-Host '  .\PS-WUunpause.ps1 -Remediate -NudgeConfigMgr'
    Write-Host ''
    return
}

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------
function Write-Info {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Green
}

function Write-WarnLine {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Yellow
}

function Write-ErrLine {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Red
}

function Add-Finding {
    param(
        [ref]$Findings,
        [ValidateSet('INFO', 'WARN', 'BLOCK', 'ERROR')]
        [string]$Severity,
        [string]$Area,
        [string]$Message,
        [string]$Path,
        [string]$Name,
        [object]$Value
    )

    $item = [pscustomobject]@{
        Severity = $Severity
        Area     = $Area
        Message  = $Message
        Path     = $Path
        Name     = $Name
        Value    = $Value
    }

    $Findings.Value += $item
}

function Get-RegValueSafe {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    try {
        $item = Get-ItemProperty -Path $Path -ErrorAction Stop
        if ($null -ne $item.PSObject.Properties[$Name]) {
            return $item.$Name
        }
        return $null
    }
    catch {
        return $null
    }
}

function Test-RegValueExists {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    try {
        $item = Get-ItemProperty -Path $Path -ErrorAction Stop
        return ($null -ne $item.PSObject.Properties[$Name])
    }
    catch {
        return $false
    }
}

function Remove-RegValueSafe {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if (Test-RegValueExists -Path $Path -Name $Name) {
        Remove-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $true
    }

    return $false
}

function Set-RegValueSafe {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][object]$Value,
        [ValidateSet('String', 'ExpandString', 'Binary', 'DWord', 'MultiString', 'QWord')]
        [string]$PropertyType = 'DWord'
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }

    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType -Force | Out-Null
}

function Restart-ServiceSafe {
    param([Parameter(Mandatory = $true)][string]$Name)

    try {
        $svc = Get-Service -Name $Name -ErrorAction Stop
        if ($svc.Status -eq 'Running') {
            Restart-Service -Name $Name -Force -ErrorAction Stop
        }
        else {
            Start-Service -Name $Name -ErrorAction Stop
        }
        return $true
    }
    catch {
        return $false
    }
}

function Get-PendingRebootState {
    $reasons = @()

    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
        $reasons += 'CBS'
    }

    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
        $reasons += 'WindowsUpdate'
    }

    $pfro = Get-RegValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations'
    if ($pfro) {
        $reasons += 'PendingFileRenameOperations'
    }

    [pscustomobject]@{
        Pending = ($reasons.Count -gt 0)
        Reasons = $reasons
    }
}

function Invoke-CMClientCycle {
    param(
        [ValidateSet('MachinePolicy', 'SoftwareUpdatesScan', 'SoftwareUpdatesEval')]
        [string]$Cycle
    )

    $scheduleMap = @{
        MachinePolicy       = '{00000000-0000-0000-0000-000000000021}'
        SoftwareUpdatesScan = '{00000000-0000-0000-0000-000000000113}'
        SoftwareUpdatesEval = '{00000000-0000-0000-0000-000000000108}'
    }

    try {
        $null = Invoke-WmiMethod -Namespace 'root\ccm' -Class 'SMS_Client' -Name 'TriggerSchedule' -ArgumentList $scheduleMap[$Cycle] -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

function Get-IntValueOrNull {
    param([object]$Value)

    if ($null -eq $Value) {
        return $null
    }

    try {
        return [int]$Value
    }
    catch {
        return $null
    }
}

# ------------------------------------------------------------
# Registry locations
# ------------------------------------------------------------
$reg = @{
    UXSettings           = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
    UpdatePolicySettings = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\Settings'
    PolicyManagerCurrent = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update'
    WUPolicies           = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    WUPoliciesAU         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
}

# ------------------------------------------------------------
# Start
# ------------------------------------------------------------
if (-not $Remediate) {
    Write-Info '[INFO] Running in diagnose-only mode (no changes will be made)'
}

Write-Info 'Diagnosing Windows Update state...'

$findings = @()
$actions = @()
$stateFlags = New-Object System.Collections.Generic.List[string]

# ------------------------------------------------------------
# Detect - service state
# ------------------------------------------------------------
foreach ($svcName in @('wuauserv', 'bits')) {
    try {
        $svc = Get-Service -Name $svcName -ErrorAction Stop
        if ($svc.Status -ne 'Running') {
            Add-Finding -Findings ([ref]$findings) -Severity 'BLOCK' -Area 'Service' `
                -Message ("Service not running: {0}" -f $svcName) -Path $null -Name $svcName -Value $svc.Status
            if (-not $stateFlags.Contains('SERVICE_ISSUE')) {
                $stateFlags.Add('SERVICE_ISSUE')
            }
        }
    }
    catch {
        Add-Finding -Findings ([ref]$findings) -Severity 'ERROR' -Area 'Service' `
            -Message ("Service not found or inaccessible: {0}" -f $svcName) -Path $null -Name $svcName -Value $null
        if (-not $stateFlags.Contains('SERVICE_ISSUE')) {
            $stateFlags.Add('SERVICE_ISSUE')
        }
    }
}

# ------------------------------------------------------------
# Detect - UX pause values
# ------------------------------------------------------------
$uxPauseValues = @(
    'PauseFeatureUpdatesStartTime',
    'PauseFeatureUpdatesEndTime',
    'PauseQualityUpdatesStartTime',
    'PauseQualityUpdatesEndTime',
    'PauseUpdatesStartTime',
    'PauseUpdatesExpiryTime'
)

foreach ($name in $uxPauseValues) {
    $val = Get-RegValueSafe -Path $reg.UXSettings -Name $name
    if ($null -ne $val -and "$val" -ne '') {
        Add-Finding -Findings ([ref]$findings) -Severity 'BLOCK' -Area 'Pause-UX' `
            -Message 'UI pause value present' -Path $reg.UXSettings -Name $name -Value $val
        if (-not $stateFlags.Contains('PAUSED')) {
            $stateFlags.Add('PAUSED')
        }
    }
}

# ------------------------------------------------------------
# Detect - UpdatePolicy pause status
# ------------------------------------------------------------

# --- Read UpdatePolicy values ---

$pausedFeatureStatusInt = Get-RegValueSafe -Path $reg.UpdatePolicySettings -Name 'PausedFeatureStatus'
$pausedQualityStatusInt = Get-RegValueSafe -Path $reg.UpdatePolicySettings -Name 'PausedQualityStatus'
$pausedFeatureDate = Get-RegValueSafe -Path $reg.UpdatePolicySettings -Name 'PausedFeatureDate'
$pausedQualityDate = Get-RegValueSafe -Path $reg.UpdatePolicySettings -Name 'PausedQualityDate'

# Detect MDM-driven pause (PolicyManager / Intune)
$pm = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update' -ErrorAction SilentlyContinue

$mdmPauseActive = $false

if ($pm) {
    $pf = $pm.PSObject.Properties['PauseFeatureUpdatesStartTime']
    $pq = $pm.PSObject.Properties['PauseQualityUpdatesStartTime']

    if (($pf -and $pf.Value) -or ($pq -and $pq.Value)) {
        $mdmPauseActive = $true
    }
}

# --- Evaluate ACTIVE pause state (authoritative) ---

if ($pausedFeatureStatusInt -eq 1 -or $pausedQualityStatusInt -eq 1 -or $mdmPauseActive) {

    # Classify source (optional but useful)
    if ($mdmPauseActive) {
        $stateFlags.Add('PAUSED_MDM')
    }
    else {
        $stateFlags.Add('PAUSED')
    }

    # Add finding (BLOCK - this is real)
    Add-Finding -Findings ([ref]$findings) -Severity 'BLOCK' -Area 'Pause-State' `
        -Message 'Windows Update is currently paused' `
        -Path $reg.UpdatePolicySettings -Name 'PausedFeatureStatus' -Value $pausedFeatureStatusInt
}

# --- Historical pause only (NO impact) ---

elseif ($pausedFeatureDate -or $pausedQualityDate) {

    # Optional: only show in verbose mode
    if ($VerboseSummary -or $PSBoundParameters.ContainsKey('Verbose')) {
        Add-Finding -Findings ([ref]$findings) -Severity 'INFO' -Area 'Pause-State' `
            -Message 'Historical pause data present (not active)' `
            -Path $reg.UpdatePolicySettings -Name 'PausedFeatureDate' -Value $pausedFeatureDate
    }
}

# ------------------------------------------------------------
# Detect - PolicyManager (MDM / WUfB)
# ------------------------------------------------------------
$pmPauseFeature = Get-RegValueSafe -Path $reg.PolicyManagerCurrent -Name 'PauseFeatureUpdates'
$pmPauseFeatureStart = Get-RegValueSafe -Path $reg.PolicyManagerCurrent -Name 'PauseFeatureUpdatesStartTime'
$pmPauseQuality = Get-RegValueSafe -Path $reg.PolicyManagerCurrent -Name 'PauseQualityUpdates'
$pmPauseQualityStart = Get-RegValueSafe -Path $reg.PolicyManagerCurrent -Name 'PauseQualityUpdatesStartTime'
$pmDeferFeatureDays = Get-RegValueSafe -Path $reg.PolicyManagerCurrent -Name 'DeferFeatureUpdatesPeriodInDays'
$pmDeferQualityDays = Get-RegValueSafe -Path $reg.PolicyManagerCurrent -Name 'DeferQualityUpdatesPeriodInDays'
$pmProductVersion = Get-RegValueSafe -Path $reg.PolicyManagerCurrent -Name 'ProductVersion'
$pmTargetReleaseVersion = Get-RegValueSafe -Path $reg.PolicyManagerCurrent -Name 'TargetReleaseVersion'

# Pause-related PM values
foreach ($pair in @(
        @{ Name = 'PauseFeatureUpdates'; Value = $pmPauseFeature },
        @{ Name = 'PauseFeatureUpdatesStartTime'; Value = $pmPauseFeatureStart },
        @{ Name = 'PauseQualityUpdates'; Value = $pmPauseQuality },
        @{ Name = 'PauseQualityUpdatesStartTime'; Value = $pmPauseQualityStart }
    )) {
    if ($null -ne $pair.Value -and "$($pair.Value)" -ne '') {
        Add-Finding -Findings ([ref]$findings) -Severity 'BLOCK' -Area 'PolicyManager' `
            -Message 'PolicyManager pause value present' -Path $reg.PolicyManagerCurrent -Name $pair.Name -Value $pair.Value
        if (-not $stateFlags.Contains('PAUSED')) {
            $stateFlags.Add('PAUSED')
        }
    }
}

# Deferrals are informative / warning only
$pmDeferFeatureDaysInt = Get-IntValueOrNull -Value $pmDeferFeatureDays
if ($null -ne $pmDeferFeatureDaysInt -and $pmDeferFeatureDaysInt -gt 0) {
    Add-Finding -Findings ([ref]$findings) -Severity 'WARN' -Area 'PolicyManager' `
        -Message 'PolicyManager feature deferral present' -Path $reg.PolicyManagerCurrent -Name 'DeferFeatureUpdatesPeriodInDays' -Value $pmDeferFeatureDaysInt
    if (-not $stateFlags.Contains('CONTROLLED_DEFERRAL')) {
        $stateFlags.Add('CONTROLLED_DEFERRAL')
    }
}

$pmDeferQualityDaysInt = Get-IntValueOrNull -Value $pmDeferQualityDays
if ($null -ne $pmDeferQualityDaysInt -and $pmDeferQualityDaysInt -gt 0) {
    Add-Finding -Findings ([ref]$findings) -Severity 'WARN' -Area 'PolicyManager' `
        -Message 'PolicyManager quality deferral present' -Path $reg.PolicyManagerCurrent -Name 'DeferQualityUpdatesPeriodInDays' -Value $pmDeferQualityDaysInt
    if (-not $stateFlags.Contains('CONTROLLED_DEFERRAL')) {
        $stateFlags.Add('CONTROLLED_DEFERRAL')
    }
}

# ProductVersion is only interesting when targeting is in play
$invalidTargetRelease = $false
$pmTargetReleaseText = $null
if ($null -ne $pmTargetReleaseVersion) {
    $pmTargetReleaseText = [string]$pmTargetReleaseVersion
    if ($pmTargetReleaseText -and $pmTargetReleaseText -ne '0' -and $pmTargetReleaseText -ne '0000') {
        Add-Finding -Findings ([ref]$findings) -Severity 'WARN' -Area 'PolicyManager' `
            -Message 'PolicyManager target release value present' -Path $reg.PolicyManagerCurrent -Name 'TargetReleaseVersion' -Value $pmTargetReleaseText
    }
    elseif ($pmTargetReleaseText -eq '0' -or $pmTargetReleaseText -eq '0000') {
        Add-Finding -Findings ([ref]$findings) -Severity 'WARN' -Area 'PolicyManager' `
            -Message 'PolicyManager target release value appears invalid' -Path $reg.PolicyManagerCurrent -Name 'TargetReleaseVersion' -Value $pmTargetReleaseText
        $invalidTargetRelease = $true
        if (-not $stateFlags.Contains('MISCONFIGURED_TARGET')) {
            $stateFlags.Add('MISCONFIGURED_TARGET')
        }
    }
}

if ($null -ne $pmProductVersion -and "$pmProductVersion" -ne '' -and $null -ne $pmTargetReleaseVersion) {
    Add-Finding -Findings ([ref]$findings) -Severity 'WARN' -Area 'PolicyManager' `
        -Message 'PolicyManager product version present alongside targeting' -Path $reg.PolicyManagerCurrent -Name 'ProductVersion' -Value $pmProductVersion
    if (-not $stateFlags.Contains('MISCONFIGURED_TARGET') -and ($pmTargetReleaseText -and $pmTargetReleaseText -ne '0' -and $pmTargetReleaseText -ne '0000')) {
        $stateFlags.Add('TARGET_PINNED')
    }
}

# ------------------------------------------------------------
# Detect - classic Windows Update policy
# ------------------------------------------------------------
$wuDeferFeature = Get-RegValueSafe -Path $reg.WUPolicies -Name 'DeferFeatureUpdates'
$wuDeferFeatureDays = Get-RegValueSafe -Path $reg.WUPolicies -Name 'DeferFeatureUpdatesPeriodInDays'
$wuDeferQuality = Get-RegValueSafe -Path $reg.WUPolicies -Name 'DeferQualityUpdates'
$wuDeferQualityDays = Get-RegValueSafe -Path $reg.WUPolicies -Name 'DeferQualityUpdatesPeriodInDays'
$wuDoNotConnectInternet = Get-RegValueSafe -Path $reg.WUPolicies -Name 'DoNotConnectToWindowsUpdateInternetLocations'
$wuTargetReleaseVersion = Get-RegValueSafe -Path $reg.WUPolicies -Name 'TargetReleaseVersion'
$wuTargetReleaseVersionInfo = Get-RegValueSafe -Path $reg.WUPolicies -Name 'TargetReleaseVersionInfo'
$wuProductVersion = Get-RegValueSafe -Path $reg.WUPolicies -Name 'ProductVersion'
$wuServer = Get-RegValueSafe -Path $reg.WUPolicies -Name 'WUServer'
$wuStatusServer = Get-RegValueSafe -Path $reg.WUPolicies -Name 'WUStatusServer'
$useWUServer = Get-RegValueSafe -Path $reg.WUPoliciesAU -Name 'UseWUServer'

# Deferrals (warn only)
$wuDeferFeatureInt = Get-IntValueOrNull -Value $wuDeferFeature
if ($null -ne $wuDeferFeatureInt -and $wuDeferFeatureInt -eq 1) {
    Add-Finding -Findings ([ref]$findings) -Severity 'WARN' -Area 'Policy' `
        -Message 'Windows Update feature deferral enabled' -Path $reg.WUPolicies -Name 'DeferFeatureUpdates' -Value $wuDeferFeatureInt
    if (-not $stateFlags.Contains('CONTROLLED_DEFERRAL')) {
        $stateFlags.Add('CONTROLLED_DEFERRAL')
    }
}

$wuDeferFeatureDaysInt = Get-IntValueOrNull -Value $wuDeferFeatureDays
if ($null -ne $wuDeferFeatureDaysInt -and $wuDeferFeatureDaysInt -gt 0) {
    Add-Finding -Findings ([ref]$findings) -Severity 'WARN' -Area 'Policy' `
        -Message 'Windows Update feature deferral days present' -Path $reg.WUPolicies -Name 'DeferFeatureUpdatesPeriodInDays' -Value $wuDeferFeatureDaysInt
    if (-not $stateFlags.Contains('CONTROLLED_DEFERRAL')) {
        $stateFlags.Add('CONTROLLED_DEFERRAL')
    }
}

$wuDeferQualityInt = Get-IntValueOrNull -Value $wuDeferQuality
if ($null -ne $wuDeferQualityInt -and $wuDeferQualityInt -eq 1) {
    Add-Finding -Findings ([ref]$findings) -Severity 'WARN' -Area 'Policy' `
        -Message 'Windows Update quality deferral enabled' -Path $reg.WUPolicies -Name 'DeferQualityUpdates' -Value $wuDeferQualityInt
    if (-not $stateFlags.Contains('CONTROLLED_DEFERRAL')) {
        $stateFlags.Add('CONTROLLED_DEFERRAL')
    }
}

$wuDeferQualityDaysInt = Get-IntValueOrNull -Value $wuDeferQualityDays
if ($null -ne $wuDeferQualityDaysInt -and $wuDeferQualityDaysInt -gt 0) {
    Add-Finding -Findings ([ref]$findings) -Severity 'WARN' -Area 'Policy' `
        -Message 'Windows Update quality deferral days present' -Path $reg.WUPolicies -Name 'DeferQualityUpdatesPeriodInDays' -Value $wuDeferQualityDaysInt
    if (-not $stateFlags.Contains('CONTROLLED_DEFERRAL')) {
        $stateFlags.Add('CONTROLLED_DEFERRAL')
    }
}

# Managed source / internet restriction (warn only)
$wuDoNotConnectInternetInt = Get-IntValueOrNull -Value $wuDoNotConnectInternet
if ($null -ne $wuDoNotConnectInternetInt -and $wuDoNotConnectInternetInt -eq 1) {
    Add-Finding -Findings ([ref]$findings) -Severity 'WARN' -Area 'Policy' `
        -Message 'Direct Windows Update internet locations are disabled by policy' -Path $reg.WUPolicies -Name 'DoNotConnectToWindowsUpdateInternetLocations' -Value $wuDoNotConnectInternetInt
    if (-not $stateFlags.Contains('MANAGED_SOURCE')) {
        $stateFlags.Add('MANAGED_SOURCE')
    }
}

if (($null -ne $wuServer -and "$wuServer" -ne '') -or ($null -ne $wuStatusServer -and "$wuStatusServer" -ne '') -or ($null -ne $useWUServer -and [int]$useWUServer -eq 1)) {
    Add-Finding -Findings ([ref]$findings) -Severity 'INFO' -Area 'Policy' `
        -Message 'Managed update source configured' -Path $reg.WUPolicies -Name 'ManagedSource' -Value 'WSUS/Policy'
    if (-not $stateFlags.Contains('MANAGED_SOURCE')) {
        $stateFlags.Add('MANAGED_SOURCE')
    }
}

# Target pinning in classic policy
if ($null -ne $wuTargetReleaseVersion -or $null -ne $wuTargetReleaseVersionInfo -or $null -ne $wuProductVersion) {
    Add-Finding -Findings ([ref]$findings) -Severity 'WARN' -Area 'Policy' `
        -Message 'Windows Update target release pinning present' -Path $reg.WUPolicies -Name 'TargetReleaseVersion' -Value $wuTargetReleaseVersion
    if (-not $stateFlags.Contains('TARGET_PINNED')) {
        $stateFlags.Add('TARGET_PINNED')
    }
}

# ------------------------------------------------------------
# Detect - pending reboot
# ------------------------------------------------------------
$reboot = Get-PendingRebootState
if ($reboot.Pending) {
    Add-Finding -Findings ([ref]$findings) -Severity 'WARN' -Area 'PendingReboot' `
        -Message ('Pending reboot detected: {0}' -f ($reboot.Reasons -join ', ')) `
        -Path $null -Name 'PendingReboot' -Value ($reboot.Reasons -join ', ')
    if (-not $stateFlags.Contains('REBOOT_REQUIRED')) {
        $stateFlags.Add('REBOOT_REQUIRED')
    }
}

# ------------------------------------------------------------
# Win11 / Feature Update Eligibility Classification
# ------------------------------------------------------------

$eligibility = 'ELIGIBLE'
$blockReasons = New-Object System.Collections.Generic.List[string]
$infoReasons = New-Object System.Collections.Generic.List[string]

# ------------------------------------------------------------
# HARD BLOCKS (true blockers only)
# ------------------------------------------------------------

# --- Pause (authoritative) ---
if ($stateFlags -contains 'PAUSED' -or $stateFlags -contains 'PAUSED_MDM') {
    $eligibility = 'BLOCKED'
    $blockReasons.Add('PAUSED')
}

# --- Service issues ---
if ($stateFlags -contains 'SERVICE_ISSUE') {
    $eligibility = 'BLOCKED'
    $blockReasons.Add('SERVICE')
}

# --- Pending reboot (treat as block in your estate) ---
if ($stateFlags -contains 'REBOOT_REQUIRED') {
    $eligibility = 'BLOCKED'
    $blockReasons.Add('REBOOT_REQUIRED')
}

# --- Target misconfiguration ---
if ($stateFlags -contains 'MISCONFIGURED_TARGET') {
    $eligibility = 'BLOCKED'
    $blockReasons.Add('TARGET_INVALID')
}

# --- Explicit target pinning ---
if ($stateFlags -contains 'TARGET_PINNED') {
    $eligibility = 'BLOCKED'
    $blockReasons.Add('TARGET_PINNED')
}

# ------------------------------------------------------------
# NON-BLOCKING CONDITIONS (informational only)
# ------------------------------------------------------------

# --- Controlled rollout / deferral ---
if ($stateFlags -contains 'CONTROLLED_DEFERRAL') {
    $infoReasons.Add('DEFERRED')
}

# --- Managed update source (WSUS / WUfB / ConfigMgr) ---
if ($stateFlags -contains 'MANAGED_SOURCE') {
    $infoReasons.Add('MANAGED_SOURCE')
}

# ------------------------------------------------------------
# FINAL STATE NORMALISATION
# ------------------------------------------------------------

if ($blockReasons.Count -eq 0 -and $infoReasons.Count -gt 0) {
    $eligibility = 'ELIGIBLE_WITH_DELAY'
}

if ($blockReasons.Count -eq 0 -and $infoReasons.Count -eq 0) {
    $eligibility = 'ELIGIBLE'
}

# ------------------------------------------------------------
# BUILD OUTPUT STRING
# ------------------------------------------------------------

$reasonText = @()

if ($blockReasons.Count -gt 0) {
    $reasonText += ($blockReasons -join '+')
}

if ($infoReasons.Count -gt 0) {
    $reasonText += ($infoReasons -join '+')
}

$eligibilitySummary = if ($reasonText.Count -gt 0) {
    "{0}:{1}" -f $eligibility, ($reasonText -join '+')
}
else {
    $eligibility
}

$uxPauseDisabled = Get-RegValueSafe -Path $reg.WUPolicies -Name 'SetDisablePauseUXAccess'
$hiddenPause = $false

if (($pausedFeatureStatusInt -eq 1 -or $pausedQualityStatusInt -eq 1) -and $uxPauseDisabled -eq 1) {
    $hiddenPause = $true
}

if ($hiddenPause) {
    Write-WarnLine 'Hidden pause detected: Updates paused but UI resume option is disabled'
}

# ------------------------------------------------------------
# Remediation
# ------------------------------------------------------------
if ($Remediate) {
    Write-Info 'Remediation mode enabled'

    # Ensure core services are running
    foreach ($svcName in @('wuauserv', 'bits')) {
        if ($PSCmdlet.ShouldProcess($svcName, 'Ensure service is running')) {
            if (Restart-ServiceSafe -Name $svcName) {
                $actions += "Service restarted/started: $svcName"
            }
            else {
                $actions += "Failed to restart/start service: $svcName"
            }
        }
    }

    # Remove UX pause values
    foreach ($name in $uxPauseValues) {
        if ($PSCmdlet.ShouldProcess("$($reg.UXSettings)\$name", 'Remove UX pause value')) {
            try {
                if (Remove-RegValueSafe -Path $reg.UXSettings -Name $name) {
                    $actions += "Removed UX pause value: $name"
                }
            }
            catch {
                $actions += "Failed removing UX pause value: $name"
            }
        }
    }

    # Reset UpdatePolicy pause values
    if ($PSCmdlet.ShouldProcess($reg.UpdatePolicySettings, 'Reset UpdatePolicy pause state')) {
        try {
            Set-RegValueSafe -Path $reg.UpdatePolicySettings -Name 'PausedFeatureStatus' -Value 0 -PropertyType 'DWord'
            $actions += 'Reset PausedFeatureStatus=0'
        }
        catch {
            $actions += 'Failed to reset PausedFeatureStatus'
        }

        try {
            Set-RegValueSafe -Path $reg.UpdatePolicySettings -Name 'PausedQualityStatus' -Value 0 -PropertyType 'DWord'
            $actions += 'Reset PausedQualityStatus=0'
        }
        catch {
            $actions += 'Failed to reset PausedQualityStatus'
        }

        foreach ($name in @('PausedFeatureDate', 'PausedQualityDate')) {
            try {
                if (Remove-RegValueSafe -Path $reg.UpdatePolicySettings -Name $name) {
                    $actions += "Removed $name"
                }
            }
            catch {
                $actions += "Failed removing $name"
            }
        }
    }

    # Remove PolicyManager pause values only (do not remove deferrals)
    foreach ($name in @(
            'PauseFeatureUpdates',
            'PauseFeatureUpdatesStartTime',
            'PauseQualityUpdates',
            'PauseQualityUpdatesStartTime'
        )) {
        if ($PSCmdlet.ShouldProcess("$($reg.PolicyManagerCurrent)\$name", 'Remove PolicyManager pause value')) {
            try {
                if (Remove-RegValueSafe -Path $reg.PolicyManagerCurrent -Name $name) {
                    $actions += "Removed PolicyManager pause value: $name"
                }
            }
            catch {
                $actions += "Failed removing PolicyManager pause value: $name"
            }
        }
    }

    # Remove invalid TargetReleaseVersion automatically if it is 0 / 0000
    if ($invalidTargetRelease) {
        if ($PSCmdlet.ShouldProcess("$($reg.PolicyManagerCurrent)\TargetReleaseVersion", 'Remove invalid TargetReleaseVersion')) {
            try {
                if (Remove-RegValueSafe -Path $reg.PolicyManagerCurrent -Name 'TargetReleaseVersion') {
                    $actions += 'Removed invalid PolicyManager TargetReleaseVersion'
                }
            }
            catch {
                $actions += 'Failed removing invalid PolicyManager TargetReleaseVersion'
            }
        }
    }

    # Optional: clear target release pinning explicitly
    if ($ClearTargetReleaseVersion) {
        foreach ($path in @($reg.PolicyManagerCurrent, $reg.WUPolicies)) {
            foreach ($name in @('TargetReleaseVersion', 'TargetReleaseVersionInfo', 'ProductVersion')) {
                if ($PSCmdlet.ShouldProcess("$path\$name", 'Remove target release pinning')) {
                    try {
                        if (Remove-RegValueSafe -Path $path -Name $name) {
                            $actions += "Removed target release value: $path\$name"
                        }
                    }
                    catch {
                        $actions += "Failed removing target release value: $path\$name"
                    }
                }
            }
        }
    }

    # Best-effort scan trigger
    if ($PSCmdlet.ShouldProcess('UsoClient StartScan', 'Trigger update scan')) {
        try {
            $uso = Join-Path $env:SystemRoot 'System32\UsoClient.exe'
            if (Test-Path $uso) {
                Start-Process -FilePath $uso -ArgumentList 'StartScan' -WindowStyle Hidden -ErrorAction Stop
                $actions += 'Triggered UsoClient StartScan'
            }
        }
        catch {
            $actions += 'UsoClient StartScan trigger failed'
        }
    }

    # Optional ConfigMgr nudges
    if ($NudgeConfigMgr) {
        foreach ($cycle in @('MachinePolicy', 'SoftwareUpdatesScan', 'SoftwareUpdatesEval')) {
            if ($PSCmdlet.ShouldProcess($cycle, 'Trigger ConfigMgr cycle')) {
                if (Invoke-CMClientCycle -Cycle $cycle) {
                    $actions += "Triggered ConfigMgr cycle: $cycle"
                }
                else {
                    $actions += "ConfigMgr cycle unavailable/failed: $cycle"
                }
            }
        }
    }
}

# Detect hidden pause condition
$uxPauseDisabled = Get-RegValueSafe -Path $reg.WUPolicies -Name 'SetDisablePauseUXAccess'
$hiddenPause = $false

if (($pausedFeatureStatusInt -eq 1 -or $pausedQualityStatusInt -eq 1) -and $uxPauseDisabled -eq 1) {
    $hiddenPause = $true
}

# ------------------------------------------------------------
# Force clear pause state
# ------------------------------------------------------------

if ($pausedFeatureStatusInt -eq 1 -or $pausedQualityStatusInt -eq 1 -or $mdmPauseActive) {

    if ($hiddenPause) {
        Write-WarnLine 'Hidden pause detected: Updates paused but UI resume option is disabled'
    }

    if ($PSCmdlet.ShouldProcess('Windows Update Pause State', 'Force clear pause state')) {

        try {
            # Reset pause status flags
            Set-RegValueSafe -Path $reg.UpdatePolicySettings -Name 'PausedFeatureStatus' -Value 0
            Set-RegValueSafe -Path $reg.UpdatePolicySettings -Name 'PausedQualityStatus' -Value 0

            if ($hiddenPause) {
                $actions += 'Detected hidden pause (pause active + UX blocked)'
            }

            $actions += 'Force-cleared PausedFeatureStatus=0'
            $actions += 'Force-cleared PausedQualityStatus=0'

        }
        catch {
            $actions += 'Failed to reset pause status flags'
        }

        # Remove legacy pause date values
        foreach ($name in @('PausedFeatureDate', 'PausedQualityDate')) {
            try {
                if (Remove-RegValueSafe -Path $reg.UpdatePolicySettings -Name $name) {
                    $actions += "Removed $name"
                }
            }
            catch {
                $actions += "Failed removing $name"
            }
        }

        # Remove UX pause values
        foreach ($name in $uxPauseValues) {
            try {
                if (Remove-RegValueSafe -Path $reg.UXSettings -Name $name) {
                    $actions += "Removed UX pause value: $name"
                }
            }
            catch {
                $actions += "Failed removing UX pause value: $name"
            }
        }
    }

    
    # Restart Windows Update services to force state refresh
    Restart-Service wuauserv -Force -ErrorAction SilentlyContinue
    Restart-Service bits -Force -ErrorAction SilentlyContinue

    Start-Sleep -Seconds 3

    # Trigger USO refresh
    $uso = Join-Path $env:SystemRoot 'System32\UsoClient.exe'
    if (Test-Path $uso) {
        Start-Process -FilePath $uso -ArgumentList 'RefreshSettings' -WindowStyle Hidden -ErrorAction SilentlyContinue
    }

    # --- Verify pause cleared ---
    Start-Sleep -Seconds 2

    $verify = Get-RegValueSafe -Path $reg.UpdatePolicySettings -Name 'PausedFeatureStatus'

    if ($verify -ne 0) {
        $actions += "WARNING: Pause state persisted after remediation (value=$verify)"
    }
    else {
        $actions += "Verified pause state cleared"
    }
}

# ------------------------------------------------------------
# Output - actionable only unless verbose
# ------------------------------------------------------------
$allFindings = @($findings)

if (-not $VerboseSummary) {
    $displayFindings = @($allFindings | Where-Object { $_.Severity -ne 'INFO' })
}
else {
    $displayFindings = $allFindings
}

$blocks = @($allFindings | Where-Object { $_.Severity -eq 'BLOCK' })
$warns = @($allFindings | Where-Object { $_.Severity -eq 'WARN' })
$errs = @($allFindings | Where-Object { $_.Severity -eq 'ERROR' })
$infos = @($allFindings | Where-Object { $_.Severity -eq 'INFO' })

Write-Host ''

if ($stateFlags.Count -gt 0) {
    Write-WarnLine ("WU-STATE | {0}" -f ($stateFlags.ToArray() -join ' + '))
    Write-WarnLine ("WU-ELIGIBILITY | {0}" -f $eligibilitySummary)
}
else {
    Write-Ok 'STATE | OK'
}

if (($displayFindings.Count -eq 0) -and ($errs.Count -eq 0)) {
    Write-Ok 'OK | No actionable Windows Update pause/policy blocks detected'
}
else {
    foreach ($f in $displayFindings) {
        $line = "{0} | Area={1} | Message={2}" -f $f.Severity, $f.Area, $f.Message

        if ($f.Name) { $line += " | Name=$($f.Name)" }
        if ($null -ne $f.Value -and "$($f.Value)" -ne '') { $line += " | Value=$($f.Value)" }
        if ($f.Path) { $line += " | Path=$($f.Path)" }

        switch ($f.Severity) {
            'BLOCK' { Write-WarnLine $line }
            'WARN' { Write-WarnLine $line }
            'ERROR' { Write-ErrLine  $line }
            default { Write-Host $line }
        }
    }
}

if ($Remediate -and $actions.Count -gt 0) {
    Write-Host ''
    foreach ($a in $actions) {
        Write-Host ("ACTION | {0}" -f $a) -ForegroundColor Green
    }
}

Write-Host ''
if ($VerboseSummary) {
    $summary = [pscustomobject]@{
        RemediationMode = [bool]$Remediate
        State           = ($stateFlags.ToArray() -join ' + ')
        Blocks          = $blocks.Count
        Warnings        = $warns.Count
        Errors          = $errs.Count
        Infos           = $infos.Count
        PendingReboot   = [bool]$reboot.Pending
        RebootReasons   = ($reboot.Reasons -join ', ')
        Actions         = ($actions -join '; ')
        WU_Eligibility  = $eligibilitySummary   # <-- inline instead
    }

    $summary | Format-List
}
else {
    Write-Host ("SUMMARY | Remediate={0} | Blocks={1} | Warnings={2} | Errors={3} | PendingReboot={4}" -f `
            [bool]$Remediate, $blocks.Count, $warns.Count, $errs.Count, [bool]$reboot.Pending) -ForegroundColor Cyan
}