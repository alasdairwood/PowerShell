param(
    [switch]$SetAllowed,   # Change to allowed (0)
    [switch]$SetBlocked    # Change to blocked (1)
)

$Path = 'Registry::HKEY_USERS\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate'
$Name = 'DisableWindowsUpdateAccess'

# Ensure key exists if we are setting
if (($SetAllowed -or $SetBlocked) -and -not (Test-Path $Path)) {
    New-Item -Path $Path -Force | Out-Null
}

# Set value if requested
if ($SetAllowed) {
    Set-ItemProperty -Path $Path -Name $Name -Value 0 -Type DWord
}
elseif ($SetBlocked) {
    Set-ItemProperty -Path $Path -Name $Name -Value 1 -Type DWord
}

# Get current value
$val = $null
if (Test-Path $Path) {
    $val = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
}

# Output (clean + consistent)
switch ($val) {
    1 { "[WUAccess] Blocked (1)" }
    0 { "[WUAccess] Allowed (0)" }
    default { "[WUAccess] Not Set" }
}