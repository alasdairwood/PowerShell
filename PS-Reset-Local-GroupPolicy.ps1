
# Reset-LocalGPO.ps1
# Resets Local Group Policy folders and forces gpupdate
# SCCM/MECM friendly (runs as SYSTEM), with logging

$ErrorActionPreference = 'Stop'
$LogPath = Join-Path $env:windir "Temp\Reset-LocalGPO.log"

function Write-Log {
    param([Parameter(Mandatory=$true)][string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp`t$Message" | Out-File -FilePath $LogPath -Append -Encoding UTF8
}

try {
    Write-Log "==== Starting Local GPO reset ===="
    Write-Log "Running as: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
    Write-Log "Computer: $env:COMPUTERNAME"

    # Use explicit paths to avoid Join-Path array parsing issues
    $paths = @(
        "$env:windir\System32\GroupPolicy",
        "$env:windir\System32\GroupPolicyUsers"
    )

    foreach ($p in $paths) {
        if (Test-Path -LiteralPath $p) {
            Write-Log "Removing folder: $p"
            Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction Stop
        }
        else {
            Write-Log "Folder not found (OK): $p"
        }
    }

    Write-Log "Running: gpupdate /force"
    $proc = Start-Process -FilePath "$env:windir\System32\gpupdate.exe" -ArgumentList "/force" -Wait -PassThru -WindowStyle Hidden
    Write-Log "gpupdate exit code: $($proc.ExitCode)"

    Write-Log "==== Completed successfully ===="
    exit 0
}
catch {
    Write-Log "ERROR: $($_.Exception.Message)"
    Write-Log "Stack: $($_.ScriptStackTrace)"
    Write-Log "==== Failed ===="
    exit 1
}