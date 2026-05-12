param (
    [ValidateSet("On","Off")]
    [string]$State
)

# Determine mode
$ReadOnly = -not $PSBoundParameters.ContainsKey("State")

# Map state if provided
if (-not $ReadOnly) {
    $TargetState = if ($State -eq "On") { 2 } else { 0 }
}

$results = foreach ($adapter in Get-NetAdapter | Where-Object Status -eq "Up") {

    $guid = $adapter.InterfaceGuid
    $path = "HKLM:\SOFTWARE\Microsoft\DusmSvc\Profiles\$guid\*"

    $profiles = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue

    if (-not $profiles) {
        [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            Adapter      = $adapter.Name
            GUID         = $guid
            OldValue     = $null
            NewValue     = $null
            Status       = "No Profile Found"
        }
        continue
    }

    foreach ($profile in $profiles) {
        $Old = $profile.UserCost

        if ($ReadOnly) {
            # 🔍 READ-ONLY MODE
            [PSCustomObject]@{
                ComputerName = $env:COMPUTERNAME
                Adapter      = $adapter.Name
                GUID         = $guid
                OldValue     = $Old
                NewValue     = $null
                Status       = if ($Old -eq 2) { "Metered" } else { "Not Metered" }
            }
        }
        else {
            # 🔧 CHANGE MODE
            $New = $TargetState

            try {
                Set-ItemProperty -Path $profile.PSPath -Name UserCost -Value $New -ErrorAction Stop

                $StatusText = if ($New -eq 2) { "Metered Enabled" } else { "Metered Disabled" }

                [PSCustomObject]@{
                    ComputerName = $env:COMPUTERNAME
                    Adapter      = $adapter.Name
                    GUID         = $guid
                    OldValue     = $Old
                    NewValue     = $New
                    Status       = $StatusText
                }
            }
            catch {
                [PSCustomObject]@{
                    ComputerName = $env:COMPUTERNAME
                    Adapter      = $adapter.Name
                    GUID         = $guid
                    OldValue     = $Old
                    NewValue     = $New
                    Status       = "Failed: $($_.Exception.Message)"
                }
            }
        }
    }
}

# Only restart service if we actually changed something
if (-not $ReadOnly) {
    Restart-Service DusmSvc -Force -ErrorAction SilentlyContinue
}

# Output
$results | Format-Table -AutoSize