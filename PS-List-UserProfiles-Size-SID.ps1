# Profile sizes based on Win32_UserProfile (Windows profile objects)
$profiles = Get-CimInstance Win32_UserProfile |
    Where-Object {
        $_.LocalPath -like 'C:\Users\*' -and
        $_.Special -eq $false -and
        $_.SID -notin @('S-1-5-18','S-1-5-19','S-1-5-20')
    }

function Resolve-SidToName {
    param([string]$Sid)
    try { ([System.Security.Principal.SecurityIdentifier]$Sid).Translate([System.Security.Principal.NTAccount]).Value }
    catch { $Sid }
}

$profiles | ForEach-Object {
    $p = $_
    $path = $p.LocalPath

    $bytes = 0
    if (Test-Path $path) {
        $bytes = (Get-ChildItem -Path $path -Recurse -Force -File -ErrorAction SilentlyContinue |
                  Measure-Object -Property Length -Sum).Sum
    }

    [pscustomobject]@{
        User     = Resolve-SidToName $p.SID
        SID      = $p.SID
        Path     = $path
        Loaded   = $p.Loaded
        SizeGB   = [math]::Round(($bytes / 1GB), 2)
        SizeMB   = [math]::Round(($bytes / 1MB), 0)
        # Note: Win32_UserProfile.LastUseTime isn't always "true last use"
        WmiLastUseTime = $p.LastUseTime
    }
} |
Sort-Object SizeGB -Descending |
Format-Table -AutoSize