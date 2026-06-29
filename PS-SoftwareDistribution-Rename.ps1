<#
.SYNOPSIS
    Renames the SoftwareDistribution folder on a list of remote computers.

.DESCRIPTION
    Stops Windows Update related services, renames C:\Windows\SoftwareDistribution,
    restarts services, and logs results.

.REQUIREMENTS
    - Run as administrator
    - PowerShell Remoting enabled on target devices
    - Appropriate admin permissions on remote devices

.NOTES
    Author: M365 Copilot
#>

# ==============================
# Configuration
# ==============================

$ComputerListPath = "C:\WorkArea\PowerShell\Computers-SoftwareDistribution.txt"
$LogPath = "C:\WorkArea\PowerShell\Rename-SoftwareDistribution-Results.csv"

# Services to stop/start
$Services = @(
    "wuauserv",
    "bits",
    "cryptsvc"
)

# ==============================
# Validate computer list
# ==============================

if (-not (Test-Path $ComputerListPath)) {
    Write-Error "Computer list not found: $ComputerListPath"
    exit 1
}

$Computers = Get-Content $ComputerListPath | Where-Object {
    -not [string]::IsNullOrWhiteSpace($_)
} | ForEach-Object {
    $_.Trim()
}

if (-not $Computers) {
    Write-Error "No computers found in $ComputerListPath"
    exit 1
}

# ==============================
# Results array
# ==============================

$Results = @()

# ==============================
# Process each computer
# ==============================

foreach ($Computer in $Computers) {

    Write-Host "Processing $Computer..." -ForegroundColor Cyan

    $Result = [PSCustomObject]@{
        ComputerName = $Computer
        Status       = "Unknown"
        Message      = ""
        OldPath      = ""
        NewPath      = ""
        Timestamp    = Get-Date
    }

    try {
        $Session = New-PSSession -ComputerName $Computer -ErrorAction Stop

        $RemoteResult = Invoke-Command -Session $Session -ArgumentList ($Services) -ScriptBlock {

            param (
                [string[]]$Services
            )

            $SoftwareDistributionPath = "C:\Windows\SoftwareDistribution"
            $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $RenamedPath = "C:\Windows\SoftwareDistribution.old_$Timestamp"

            $Output = [PSCustomObject]@{
                Status  = "Unknown"
                Message = ""
                OldPath = $SoftwareDistributionPath
                NewPath = $RenamedPath
            }

            try {
                # Stop services
                foreach ($Service in $Services) {
                    $Svc = Get-Service -Name $Service -ErrorAction SilentlyContinue

                    if ($null -ne $Svc) {
                        if ($Svc.Status -ne "Stopped") {
                            Stop-Service -Name $Service -Force -ErrorAction Stop
                            Start-Sleep -Seconds 2
                        }
                    }
                }

                # Check if SoftwareDistribution exists
                if (Test-Path $SoftwareDistributionPath) {
                    Rename-Item -Path $SoftwareDistributionPath -NewName ("SoftwareDistribution.old_$Timestamp") -ErrorAction Stop

                    $Output.Status = "Success"
                    $Output.Message = "SoftwareDistribution folder renamed successfully."
                }
                else {
                    $Output.Status = "Skipped"
                    $Output.Message = "SoftwareDistribution folder does not exist."
                }

                # Restart services
                foreach ($Service in $Services) {
                    $Svc = Get-Service -Name $Service -ErrorAction SilentlyContinue

                    if ($null -ne $Svc) {
                        Start-Service -Name $Service -ErrorAction SilentlyContinue
                    }
                }
            }
            catch {
                $Output.Status = "Failed"
                $Output.Message = $_.Exception.Message

                # Attempt to restart services even if rename fails
                foreach ($Service in $Services) {
                    try {
                        $Svc = Get-Service -Name $Service -ErrorAction SilentlyContinue

                        if ($null -ne $Svc) {
                            Start-Service -Name $Service -ErrorAction SilentlyContinue
                        }
                    }
                    catch {
                        # Suppress restart errors here, main error is already captured
                    }
                }
            }

            return $Output
        }

        $Result.Status = $RemoteResult.Status
        $Result.Message = $RemoteResult.Message
        $Result.OldPath = $RemoteResult.OldPath
        $Result.NewPath = $RemoteResult.NewPath

        Remove-PSSession -Session $Session
    }
    catch {
        $Result.Status = "Failed"
        $Result.Message = $_.Exception.Message
    }

    $Results += $Result
}

# ==============================
# Export results
# ==============================

$Results | Export-Csv -Path $LogPath -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "Completed. Results exported to:" -ForegroundColor Green
Write-Host $LogPath -ForegroundColor Yellow

$Results | Format-Table -AutoSize