# Requires ActiveDirectory PowerShell module
Import-Module ActiveDirectory

# Path to CSV file
$CsvPath = "C:\Temp\ComputersToDelete.csv"

# Log file path
$LogPath = "C:\Temp\DeletedADComputers.log"

# Set to $true to simulate only
# Set to $false to actually delete the computer objects
$WhatIfMode = $true

# Check CSV exists
if (-not (Test-Path $CsvPath)) {
    Write-Host "CSV file not found: $CsvPath" -ForegroundColor Red
    exit 1
}

# Import CSV
$Computers = Import-Csv -Path $CsvPath

# Check required column exists
if (-not ($Computers | Get-Member -Name "ComputerName" -MemberType NoteProperty)) {
    Write-Host "CSV must contain a column called 'ComputerName'" -ForegroundColor Red
    exit 1
}

# Start logging
"===== AD Computer Deletion Started: $(Get-Date) =====" | Out-File -FilePath $LogPath -Append

foreach ($Entry in $Computers) {

    $ComputerName = $Entry.ComputerName.Trim()

    if ([string]::IsNullOrWhiteSpace($ComputerName)) {
        Write-Host "Skipping blank computer name" -ForegroundColor Yellow
        "SKIPPED: Blank computer name" | Out-File -FilePath $LogPath -Append
        continue
    }

    try {
        # Try to find the AD computer object
        $ADComputer = Get-ADComputer -Identity $ComputerName -ErrorAction Stop

        Write-Host "Found computer: $ComputerName" -ForegroundColor Cyan

        if ($WhatIfMode) {
            # Simulation only
            Remove-ADComputer -Identity $ADComputer.DistinguishedName -Confirm:$false -WhatIf

            "WHATIF: Would delete computer object: $ComputerName | $($ADComputer.DistinguishedName)" |
                Out-File -FilePath $LogPath -Append
        }
        else {
            # Actual deletion
            Remove-ADComputer -Identity $ADComputer.DistinguishedName -Confirm:$false

            Write-Host "Deleted computer: $ComputerName" -ForegroundColor Green

            "DELETED: $ComputerName | $($ADComputer.DistinguishedName)" |
                Out-File -FilePath $LogPath -Append
        }
    }
    catch {
        Write-Host "Failed or not found: $ComputerName - $($_.Exception.Message)" -ForegroundColor Red

        "FAILED: $ComputerName | $($_.Exception.Message)" |
            Out-File -FilePath $LogPath -Append
    }
}

"===== AD Computer Deletion Finished: $(Get-Date) =====" | Out-File -FilePath $LogPath -Append

Write-Host "Script complete. Log written to: $LogPath" -ForegroundColor Green