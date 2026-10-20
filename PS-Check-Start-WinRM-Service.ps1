$ComputerName = "LANVM04"

Write-Host "`n=== REMOTE COMPUTER: $ComputerName ===" -ForegroundColor Cyan

# ------------------------------------------------------------
# Check connectivity
# ------------------------------------------------------------
if (-not (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet)) {
    Write-Warning "$ComputerName did not respond to ping."
    Write-Warning "Continuing because ICMP may simply be blocked."
}

# ------------------------------------------------------------
# Check WinRM service
# ------------------------------------------------------------
Write-Host "`nChecking WinRM service..." -ForegroundColor Yellow

try {

    $WinRM = Get-Service -ComputerName $ComputerName -Name WinRM -ErrorAction Stop

    Write-Host "WinRM status: $($WinRM.Status)" -ForegroundColor Cyan

    if ($WinRM.Status -ne "Running") {

        Write-Host "WinRM is not running. Attempting to start it..." -ForegroundColor Yellow

        sc.exe "\\$ComputerName" start WinRM | Out-Null

        Start-Sleep -Seconds 3

        $WinRM = Get-Service -ComputerName $ComputerName -Name WinRM -ErrorAction Stop

        if ($WinRM.Status -eq "Running") {
            Write-Host "WinRM successfully started." -ForegroundColor Green
        }
        else {
            Write-Warning "WinRM could not be started."
            return
        }

    }
    else {

        Write-Host "WinRM is already running." -ForegroundColor Green

    }

}
catch {

    Write-Warning "Unable to query or start WinRM on $ComputerName."
    Write-Warning $_.Exception.Message
    return

}

# ------------------------------------------------------------
# Test PowerShell Remoting
# ------------------------------------------------------------
Write-Host "`nTesting PowerShell Remoting..." -ForegroundColor Yellow

try {

    Test-WSMan -ComputerName $ComputerName -ErrorAction Stop | Out-Null

    Write-Host "PowerShell Remoting is available." -ForegroundColor Green

}
catch {

    Write-Warning "WinRM is running, but PowerShell Remoting is not responding."
    Write-Warning $_.Exception.Message
    return

}

# ------------------------------------------------------------
# Run Windows Update checks remotely
# ------------------------------------------------------------
Invoke-Command -ComputerName $ComputerName -ErrorAction Stop -ScriptBlock {

    #
    # YOUR EXISTING WINDOWS UPDATE SCRIPT GOES HERE
    #

}