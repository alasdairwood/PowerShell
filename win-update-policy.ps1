param(
    [string]$ComputerName = $env:COMPUTERNAME
)

$ScriptBlock = {

    # ----------------------
    # Registry paths (use Registry:: for WinRM reliability)
    # ----------------------
    $GpoWU      = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $GpoAU      = "$GpoWU\AU"

    # Windows Update policy state (what you explicitly want surfaced)
    $PolicyStatePath = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState'

    # UpdatePolicy\Settings often contains pause/status flags, but keep it if you want later
    $PolicySettingsPath = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\Settings'

    # MDM Policy CSP backing store (useful for extra context; deferrals often map here too) [1](https://github.com/homotechsual/Blog-Scripts/blob/main/Update%20Management/FeatureUpdateTargeting.ps1)
    $PolMgrCur  = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\Update'
    $PolMgrDef  = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Update'

    # SYSTEM policy block (0x80240025 scenario)
    $SysWUBlock = 'Registry::HKEY_USERS\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate'

    function Get-RegObj {
        param([string]$Path)
        try { Get-ItemProperty -Path $Path -ErrorAction Stop } catch { $null }
    }

    function Get-RegVal {
        param([string]$Path, [string]$Name)
        try { (Get-ItemProperty -Path $Path -ErrorAction Stop).$Name } catch { $null }
    }

    function Normalize-Val {
        param([object]$Value)
        if ($null -eq $Value) { return $null }
        $s = $Value.ToString().Trim()
        if ($s.Length -eq 0) { return $null }
        # treat common placeholders as "not set"
        if ($s -eq '0' -or $s -eq '0000' -or $s -eq '4294967295') { return $null }
        return $Value
    }

    function First-NonNull {
        param([object[]]$Values)
        foreach ($v in $Values) {
            $n = Normalize-Val $v
            if ($null -ne $n) { return $n }
        }
        return $null
    }

    # ----------------------
    # Collect raw data
    # ----------------------
    $WU_GPO   = Get-RegObj $GpoWU
    $AU_GPO   = Get-RegObj $GpoAU

    $PS       = Get-RegObj $PolicyStatePath
    $PS_Set   = Get-RegObj $PolicySettingsPath

    $PM_Cur   = Get-RegObj $PolMgrCur
    $PM_Def   = Get-RegObj $PolMgrDef

    $DisableWUAccess = Get-RegVal $SysWUBlock 'DisableWindowsUpdateAccess'

    # ----------------------
    # Update source evaluation (same as before)
    # ----------------------
    if ($DisableWUAccess -eq 1) {
        $UpdateSourceStatus = "Blocked"
        $UpdateSourceReason = "Windows Update access disabled"
    }
    elseif ($AU_GPO.UseWUServer -eq 1) {
        if ($WU_GPO.WUServer) {
            $UpdateSourceStatus = "WSUS"
            $UpdateSourceReason = "Using WSUS server"
        } else {
            $UpdateSourceStatus = "Misconfigured"
            $UpdateSourceReason = "UseWUServer=1 but no server"
        }
    }
    elseif ($AU_GPO.UseWUServer -eq 0) {
        if ($WU_GPO.WUServer) {
            $UpdateSourceStatus = "Conflict"
            $UpdateSourceReason = "WSUS defined but not used"
        } else {
            $UpdateSourceStatus = "Microsoft Update"
            $UpdateSourceReason = "Using public Windows Update"
        }
    }
    else {
        $UpdateSourceStatus = "Not Set"
        $UpdateSourceReason = "No policy configured"
    }

    # ----------------------
    # TARGETING - PolicyState FIRST (your requirement)
    # GPO target policy is enabled by TargetReleaseVersion=1 
    # ----------------------
    $TargetEnabled_GPO = ($WU_GPO.TargetReleaseVersion -eq 1)

    $TargetProductVersion_GPO = Normalize-Val $WU_GPO.ProductVersion
    $TargetReleaseVersion_GPO = Normalize-Val $WU_GPO.TargetReleaseVersionInfo

    # PolicyState often has TargetProductVersion and sometimes target release info
    $TargetProductVersion_PS  = Normalize-Val $PS.TargetProductVersion
    $TargetReleaseVersion_PS  = First-NonNull @(
        $PS.TargetReleaseVersionInfo,
        $PS.TargetReleaseVersion
    )

    # PolicyManager fallback (build/policy dependent) [1](https://github.com/homotechsual/Blog-Scripts/blob/main/Update%20Management/FeatureUpdateTargeting.ps1)
    $TargetProductVersion_MDM = First-NonNull @(
        $PM_Cur.TargetProductVersion, $PM_Cur.ProductVersion,
        $PM_Def.TargetProductVersion, $PM_Def.ProductVersion
    )
    $TargetReleaseVersion_MDM = First-NonNull @(
        $PM_Cur.TargetReleaseVersionInfo, $PM_Cur.TargetReleaseVersion,
        $PM_Def.TargetReleaseVersionInfo, $PM_Def.TargetReleaseVersion
    )

    # Effective targeting: PolicyState -> GPO(enabled) -> MDM -> None
    $TargetSource = "None"
    $TargetProductVersion = $null
    $TargetReleaseVersion = $null

    if ($TargetProductVersion_PS -or $TargetReleaseVersion_PS) {
        $TargetSource = "PolicyState"
        $TargetProductVersion = $TargetProductVersion_PS
        $TargetReleaseVersion = $TargetReleaseVersion_PS
    }
    elseif ($TargetEnabled_GPO -and $TargetProductVersion_GPO -and $TargetReleaseVersion_GPO) {
        $TargetSource = "GPO"
        $TargetProductVersion = $TargetProductVersion_GPO
        $TargetReleaseVersion = $TargetReleaseVersion_GPO
    }
    elseif ($TargetProductVersion_MDM -or $TargetReleaseVersion_MDM) {
        $TargetSource = "MDM"
        $TargetProductVersion = $TargetProductVersion_MDM
        $TargetReleaseVersion = $TargetReleaseVersion_MDM
    }

    $TargetEnabledEffective = $TargetSource

    # ----------------------
    # DEFERRALS - PolicyState FIRST (your requirement)
    # PolicyState includes the enable flags and day counts (as per your example).
    # GPO deferral days live under Policies key (also well-documented) [1](https://github.com/homotechsual/Blog-Scripts/blob/main/Update%20Management/FeatureUpdateTargeting.ps1)
    # ----------------------
    $DeferFeatureUpdates_PS  = Normalize-Val $PS.DeferFeatureUpdates
    $DeferQualityUpdates_PS  = Normalize-Val $PS.DeferQualityUpdates

    $FeatureDeferral_PS      = Normalize-Val $PS.FeatureUpdatesDeferralInDays
    $QualityDeferral_PS      = Normalize-Val $PS.QualityUpdatesDeferralInDays

    $FeatureDeferral_GPO     = Normalize-Val $WU_GPO.DeferFeatureUpdatesPeriodInDays
    $QualityDeferral_GPO     = Normalize-Val $WU_GPO.DeferQualityUpdatesPeriodInDays

    # MDM fallback (PolicyManager) [1](https://github.com/homotechsual/Blog-Scripts/blob/main/Update%20Management/FeatureUpdateTargeting.ps1)
    $FeatureDeferral_MDM     = First-NonNull @(
        $PM_Cur.DeferFeatureUpdatesPeriodInDays,
        $PM_Def.DeferFeatureUpdatesPeriodInDays
    )
    $QualityDeferral_MDM     = First-NonNull @(
        $PM_Cur.DeferQualityUpdatesPeriodInDays,
        $PM_Def.DeferQualityUpdatesPeriodInDays
    )

    # Effective deferral days: PolicyState -> MDM -> GPO
    $FeatureDeferralEffective = First-NonNull @($FeatureDeferral_PS, $FeatureDeferral_MDM, $FeatureDeferral_GPO)
    $QualityDeferralEffective = First-NonNull @($QualityDeferral_PS, $QualityDeferral_MDM, $QualityDeferral_GPO)

    # ----------------------
    # PolicyState details you explicitly listed
    # ----------------------
    $BranchReadinessLevel_PS = Normalize-Val $PS.BranchReadinessLevel

    # Some builds spell these slightly differently; handle both
    $IsDeferralIsActive_PS   = First-NonNull @($PS.IsDeferralIsActive, $PS.IsDeferralsActive)
    $IsWUfBConfigured_PS     = Normalize-Val $PS.IsWUfBConfigured
    $IsWUfBDualScanActive_PS = Normalize-Val $PS.IsWUfBDualScanActive
    $IsDisableDualScanConfigured_PS = Normalize-Val $PS.IsDisableDualScanConfigured

    $PolicySources_PS        = Normalize-Val $PS.PolicySources
    $UseUpdateClassPolicySource_PS = Normalize-Val $PS.UseUpdateClassPolicySource

    $SetSrcFeature_PS = Normalize-Val $PS.SetPolicyDrivenUpdateSourceForFeatureUpdates
    $SetSrcQuality_PS = Normalize-Val $PS.SetPolicyDrivenUpdateSourceForQualityUpdates
    $SetSrcDriver_PS  = Normalize-Val $PS.SetPolicyDrivenUpdateSourceForDriverUpdates
    $SetSrcOther_PS   = Normalize-Val $PS.SetPolicyDrivenUpdateSourceForOtherUpdates

    $ExcludeWUDrivers_PS     = First-NonNull @($PS.ExcludeWUDrivers, $PS.ExcludeWUDriversInQualityUpdate, $PS.ExcludeWUDrivers) # keep flexible
    $ExcludeWUDrivers_PS     = if ($null -ne $ExcludeWUDrivers_PS) { $ExcludeWUDrivers_PS } else { $null }

    # Pause flags (from UpdatePolicy\Settings)
    $PausedFeatureStatus = Normalize-Val $PS_Set.PausedFeatureStatus
    $PausedQualityStatus = Normalize-Val $PS_Set.PausedQualityStatus

    # ----------------------
    # Conflict detection (compare PolicyState days vs GPO/MDM days)
    # ----------------------
    $PolicyConflict = "No"
    $PolicyConflictReason = @()

    if (($FeatureDeferral_PS -ne $null) -and ($FeatureDeferral_GPO -ne $null) -and ($FeatureDeferral_PS -ne $FeatureDeferral_GPO)) {
        $PolicyConflict = "Yes"
        $PolicyConflictReason += "Feature deferral mismatch (PolicyState=$FeatureDeferral_PS, GPO=$FeatureDeferral_GPO)"
    }
    if (($QualityDeferral_PS -ne $null) -and ($QualityDeferral_GPO -ne $null) -and ($QualityDeferral_PS -ne $QualityDeferral_GPO)) {
        $PolicyConflict = "Yes"
        $PolicyConflictReason += "Quality deferral mismatch (PolicyState=$QualityDeferral_PS, GPO=$QualityDeferral_GPO)"
    }
    if (($FeatureDeferral_PS -ne $null) -and ($FeatureDeferral_MDM -ne $null) -and ($FeatureDeferral_PS -ne $FeatureDeferral_MDM)) {
        $PolicyConflict = "Yes"
        $PolicyConflictReason += "Feature deferral mismatch (PolicyState=$FeatureDeferral_PS, MDM=$FeatureDeferral_MDM)"
    }
    if (($QualityDeferral_PS -ne $null) -and ($QualityDeferral_MDM -ne $null) -and ($QualityDeferral_PS -ne $QualityDeferral_MDM)) {
        $PolicyConflict = "Yes"
        $PolicyConflictReason += "Quality deferral mismatch (PolicyState=$QualityDeferral_PS, MDM=$QualityDeferral_MDM)"
    }

    $PolicyConflictReason = if ($PolicyConflictReason.Count -gt 0) { $PolicyConflictReason -join "; " } else { "None detected" }

    # ----------------------
    # Output (flat, quick scan, grouped logically)
    # ----------------------
    [PSCustomObject]@{
        ComputerName              = $env:COMPUTERNAME

        # --- Source / Access ---
        UpdateSourceStatus        = $UpdateSourceStatus
        UpdateSourceReason        = $UpdateSourceReason
        UpdateBlocked             = if ($DisableWUAccess -eq 1) {"Yes"} elseif ($DisableWUAccess -eq 0) {"No"} else {"Not Set"}
        UseWUServer               = $AU_GPO.UseWUServer
        WUServer                  = $WU_GPO.WUServer

        # --- Targeting (PolicyState-first) ---
        TargetSource              = $TargetSource
        TargetEnabled_GPO         = $TargetEnabled_GPO
        TargetEnabledEffective    = $TargetEnabledEffective
        TargetProductVersion      = $TargetProductVersion
        TargetReleaseVersion      = $TargetReleaseVersion

        # --- Deferrals (PolicyState-first) ---
        DeferFeatureUpdates       = $DeferFeatureUpdates_PS
        DeferQualityUpdates       = $DeferQualityUpdates_PS
        FeatureDeferral_GPO       = $FeatureDeferral_GPO
        FeatureDeferral_MDM       = $FeatureDeferral_MDM
        FeatureDeferral_PS        = $FeatureDeferral_PS
        FeatureDeferralEffective  = $FeatureDeferralEffective
        QualityDeferral_GPO       = $QualityDeferral_GPO
        QualityDeferral_MDM       = $QualityDeferral_MDM
        QualityDeferral_PS        = $QualityDeferral_PS
        QualityDeferralEffective  = $QualityDeferralEffective

        # --- PolicyState ring / WUfB / dual scan ---
        BranchReadinessLevel      = $BranchReadinessLevel_PS
        IsDeferralIsActive        = $IsDeferralIsActive_PS
        IsWUfBConfigured          = $IsWUfBConfigured_PS
        IsWUfBDualScanActive      = $IsWUfBDualScanActive_PS
        IsDisableDualScanConfigured = $IsDisableDualScanConfigured_PS
        PolicySources             = $PolicySources_PS
        UseUpdateClassPolicySource = $UseUpdateClassPolicySource_PS

        # --- Policy-driven update sources (PolicyState) ---
        SetPolicyDrivenUpdateSourceForFeatureUpdates = $SetSrcFeature_PS
        SetPolicyDrivenUpdateSourceForQualityUpdates = $SetSrcQuality_PS
        SetPolicyDrivenUpdateSourceForDriverUpdates  = $SetSrcDriver_PS
        SetPolicyDrivenUpdateSourceForOtherUpdates   = $SetSrcOther_PS

        # --- Drivers / Pause flags ---
        ExcludeWUDrivers          = $ExcludeWUDrivers_PS
        PausedFeatureStatus       = $PausedFeatureStatus
        PausedQualityStatus       = $PausedQualityStatus

        # --- Conflicts ---
        PolicyConflict            = $PolicyConflict
        PolicyConflictReason      = $PolicyConflictReason

        # --- Raw targeting values (debug-friendly, still flat) ---
        TargetProductVersion_GPO  = $TargetProductVersion_GPO
        TargetReleaseVersion_GPO  = $TargetReleaseVersion_GPO
        TargetProductVersion_MDM  = $TargetProductVersion_MDM
        TargetReleaseVersion_MDM  = $TargetReleaseVersion_MDM
        TargetProductVersion_PS_Raw = $PS.TargetProductVersion
        TargetReleaseVersion_PS_Raw = First-NonNull @($PS.TargetReleaseVersionInfo, $PS.TargetReleaseVersion)
    }
}

# ----------------------
# Execution
# ----------------------
if ($ComputerName -eq $env:COMPUTERNAME) {
    & $ScriptBlock
}
else {
    Invoke-Command -ComputerName $ComputerName -ScriptBlock $ScriptBlock -ErrorAction Stop
}