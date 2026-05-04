$CsvPath = "C:\WorkArea\CSV\DisableComputers.csv"
$LogPath = "C:\WorkArea\CSV\DisableComputers_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

Import-Csv $CsvPath | ForEach-Object {
  $name = $_.ComputerName.Trim()
  if (-not $name) { return }

  try {
    $adComp = Get-ADComputer -Identity $name -Properties Enabled -ErrorAction Stop

    if ($adComp.Enabled -eq $false) {
      "$name already disabled" | Tee-Object -FilePath $LogPath -Append
      return
    }

    Disable-ADAccount -Identity $adComp -WhatIf
    "$name would be disabled" | Tee-Object -FilePath $LogPath -Append
  }
  catch {
    "$name NOT FOUND / ERROR: $($_.Exception.Message)" | Tee-Object -FilePath $LogPath -Append
  }
}