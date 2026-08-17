
<#
Detection script for Classic (v1) Microsoft Teams remnants

Exit codes:
  1 = Classic Teams detected (non-compliant)  -> Intune runs remediation
  0 = Classic Teams NOT detected (compliant)  -> Intune does nothing

Notes:
- This only checks Classic Teams footprints (Machine-Wide Installer, per-user folders, classic add-ins, known registry keys).
- It does NOT flag New Teams (MSIX/WebView2) components.
- For speed/safety, deep per-profile registry hive loading is OFF by default.
  Use -DeepUserHiveScan if you want detection to also search every offline user hive (slower).
#>

[CmdletBinding()]
param(
    [switch]$DeepUserHiveScan
)

$ErrorActionPreference = 'SilentlyContinue'
$detected = $false
$reasons  = New-Object System.Collections.Generic.List[string]

function Test-RegistryKey {
    param([string]$Path)
    try { return Test-Path -Path $Path } catch { return $false }
}

function Test-RegistryValue {
    param([string]$Path, [string]$Name)
    try {
        $v = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        return ($null -ne $v)
    } catch { return $false }
}

function Add-Reason { param([string]$msg) $script:reasons.Add($msg) | Out-Null }

# --- 1) Machine-Wide Installer (Classic) ---

# Product codes used by Classic Teams MWI
$Classic64 = '{731F6BAA-A986-45A4-8936-7C3AAAAA760B}'
$Classic32 = '{39AF0813-FA7B-4860-ADBE-93B9B214B914}'

# Classic MWI often registers under WOW6432Node on x64
$uninstallRoots = @(
  'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
  'Registry::HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
)

foreach ($root in $uninstallRoots) {
    foreach ($code in @($Classic64, $Classic32)) {
        if (Test-RegistryKey (Join-Path $root $code)) {
            $detected = $true
            Add-Reason "Found Machine-Wide Installer product code $code in $root"
        }
    }
    # Defensive: also look by DisplayName in case code isn’t present
    Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            if ($p.DisplayName -and $p.DisplayName -match 'Teams Machine.*Wide Installer') {
                $detected = $true
                Add-Reason "Found Teams Machine-Wide Installer under $root ($($p.DisplayName))"
            }
        } catch {}
    }
}

# Folder laid down by Machine-Wide Installer
$mwFolder = "${env:ProgramFiles(x86)}\Teams Installer"
if (Test-Path $mwFolder) {
    $detected = $true
    Add-Reason "Found Teams Machine-Wide Installer folder: $mwFolder"
}

# Classic Run keys that bootstrap per-user installs
$runRoots = @(
  'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
  'Registry::HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
)
$runValueNames = @('TeamsMachineInstaller','TeamsMachineUninstallerLocalAppData','TeamsMachineUninstallerProgramData')
foreach ($rr in $runRoots) {
    foreach ($name in $runValueNames) {
        if (Test-RegistryValue -Path $rr -Name $name) {
            $detected = $true
            Add-Reason "Found Classic Teams run value '$name' in $rr"
        }
    }
}

# --- 2) Per-user Classic Teams footprints (file system only, fast & reliable) ---

# Any user profile remnants of Classic Teams?
$userProfiles = @(Get-ChildItem "$($env:SystemDrive)\Users" -Directory -ErrorAction SilentlyContinue |
                 Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') })

foreach ($p in $userProfiles) {
    $paths = @(
        Join-Path $p.FullName '\AppData\Local\Microsoft\Teams',
        Join-Path $p.FullName '\AppData\Roaming\Microsoft\Teams',
        Join-Path $p.FullName '\AppData\Local\Microsoft\SquirrelTemp',
        Join-Path $p.FullName '\AppData\Local\Microsoft\TeamsMeetingAddin'
    )
    foreach ($path in $paths) {
        if (Test-Path $path) { $detected = $true; Add-Reason "Found Classic Teams user data: $path" }
    }

    # Classic Start Menu shortcuts
    $shortcutGlob = Join-Path $p.FullName '\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Microsoft Teams\*.lnk'
    if (Get-Item $shortcutGlob -ErrorAction SilentlyContinue) {
        $detected = $true
        Add-Reason "Found Classic Teams Start Menu shortcuts for $($p.Name)"
    }
}

# --- 3) Optional deep scan: check EVERY offline user hive for classic uninstall entries ---
if ($DeepUserHiveScan) {
    foreach ($p in $userProfiles) {
        $ntuser = Join-Path $p.FullName 'NTUSER.DAT'
        if (Test-Path $ntuser) {
            $hiveName = "TEMP_DETECT_$($p.Name)_$(Get-Random)"
            try {
                $load = Start-Process "$($env:ComSpec)" -ArgumentList @('/c',"REG LOAD `"HKLM\$hiveName`" `"$ntuser`"") -Wait -WindowStyle Hidden -PassThru
                if ($load.ExitCode -eq 0) {
                    $k = "Registry::HKLM\$hiveName\Software\Microsoft\Windows\CurrentVersion\Uninstall\Teams"
                    if (Test-RegistryKey $k) { $detected = $true; Add-Reason "Found Classic Teams uninstall key in user hive: $($p.Name)" }
                }
            } catch {} finally {
                try { Start-Process "$($env:ComSpec)" -ArgumentList @('/c',"REG UNLOAD `"HKLM\$hiveName`"") -Wait -WindowStyle Hidden | Out-Null } catch {}
            }
        }
    }
}

# --- 4) Classic MSI PatchCache remnants (harmless but a good indicator) ---
$patchCachePaths = @(
    'C:\Windows\Installer\$PatchCache$\Managed\AD7E5E9D92C699247949F5DDF5A4D661\',
    'C:\Windows\Installer\$PatchCache$\Managed\3180FA93B7AF0684DAEB399B2B419B41\'
)
foreach ($pc in $patchCachePaths) {
    if (Test-Path $pc) { $detected = $true; Add-Reason "Found Classic Teams PatchCache path: $pc" }
}

# --- Result for Intune ---
if ($detected) {
    Write-Output "[Detect-ClassicTeams] Non-compliant. Reasons:"
    $reasons | ForEach-Object { Write-Output "  - $_" }
    exit 1
}
else {
    Write-Output "[Detect-ClassicTeams] Compliant. Classic Teams not detected."
    exit 0
}

# SIG # Begin signature block
# MIIsVQYJKoZIhvcNAQcCoIIsRjCCLEICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUVkT40Bdut+B1i+hwCyUnCD4L
# y9qggiauMIIFAzCCAuugAwIBAgIQHR4Hnvzqa75K+m6DORxCujANBgkqhkiG9w0B
# AQsFADAUMRIwEAYDVQQDEwlQS0lST09UQ0EwHhcNMjEwOTE3MTAwNDIzWhcNNDEw
# OTE3MTAxNDIyWjAUMRIwEAYDVQQDEwlQS0lST09UQ0EwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDk//iKMnYU5glI6yFkRTfkRnbOu5hBRaApjK9qUios
# vtNJLRITtaimW7+noHtXXK5Gi+rIQZnop8DpBwwTHrdH9FBQ+4s2a4Zh5Pj3aNqH
# 8ST7Mn4qKfdfrbv8gebeERqq8Dp3fgPOx3NxoQ3r8upIWnT+c0YP6FNQ60HJrATz
# +OUqjB9z2gS3cJ8mhv2ycukD+P16lXKdeez3pGN/ZJYXRP3UODzZPOpMQ7BUMfyj
# cWJdCkN2QMfyoMVfPoatPCUqIAUKuUAChcdQmy5xv6Oa4jnKgSUz9Q3wrHjYedQV
# zuSsXPOdEBTExC2mLiyoOy3PkDUlxD0bG7SBMUlJJw+hWBgejf7TkGOsiNZc1jB1
# V3DKzJWEoPt1xi6UrFECp3C1ky6lEBVh3ChDffsmr69l3NR6Zml4JXl2AOHRJodf
# dTR1YeUnfxGu8foBhy9503U6KFKXjBqUXr1hfXCKJD/QpSlbb0f3uhuZnEOyAd5e
# D74c3aD5Ilh3IItn62EYB2G68ho4fVkUC7TUwXmaOu+Yo4c0AvGjTUOMK1FhKmxS
# 3GvUgdptsDTgWq/CuiNxDHPKNZQ+YPMCHnguJO0LxJllqcUM0DMqpwc9FkcpR1ti
# WDWjVRqmQ5xFUgOcCNMwghQ+xP7JITHZv4O2+JfXPiHmpTkgpB5Mp19vx5vmItjV
# jQIDAQABo1EwTzALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E
# FgQUDiltdJEaLzI7/Km4+7tVRY2bWGMwEAYJKwYBBAGCNxUBBAMCAQAwDQYJKoZI
# hvcNAQELBQADggIBAAQBXcmXxt6g45qp26c5SYmBq9Dfe1KmVSso0z3tt3DocuTV
# ldB5923HCeOUIpddTxfMiTDBsW3KdTUJRGgmRSjsfvDUDtd1moNgw0jjwKHoZMrW
# 8Y3/li/OpT5w8nvxyx6grAot1ohjs/xZG1tkKmaFN8/l1Ar7Io4poXhRfJczEqW0
# GJLVv0SISN7SEdAAqlA9TyZdU1gjEN+BqqqSLPHh3hDpTaLBDNyCLUsj8OHF+iyB
# pqYLruwIKcHjubt4iUq74wnWXWbqac1yVUT7VU2CXg/b5WmWEIkYwrGbc9Gq8F+B
# /J7nLRsPjNLBT+MmAV0NwAw9BBVesRujKAQE63NoZC6yzpLy6Anpgp1vKZLMHtUj
# FCLqUjd4VjKAMpHUHAo7stJuB+t13sFTY3OS67KnoCkn1Jo3WK3DZ2IJPMk+Dea3
# lOlT1tFVgn9gkALOB2bdQtI78Mh9ne+cA09VnVHyjQT/QJq+vRpmNF3PAsSypJ+H
# 3XD1Q+6jfg1GUy2SC9AOqPIKgCT0Ll7sUpfRpQWadPdG2r20wEe2gAzB/Spg32Ho
# jJb/HZ4+TaIr53A+y5MSlgF57C23wlK8m5F+6JhJSe7F31yhLORnLnPRjQg7DOWq
# p5XGdfR5UFqqqdeXaq+hQ37r16fc423BG+SkqeTyZEGBKVCPrCpglsULS/6uMIIF
# jTCCBHWgAwIBAgIQDpsYjvnQLefv21DiCEAYWjANBgkqhkiG9w0BAQwFADBlMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3Qg
# Q0EwHhcNMjIwODAxMDAwMDAwWhcNMzExMTA5MjM1OTU5WjBiMQswCQYDVQQGEwJV
# UzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQu
# Y29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwggIiMA0GCSqG
# SIb3DQEBAQUAA4ICDwAwggIKAoICAQC/5pBzaN675F1KPDAiMGkz7MKnJS7JIT3y
# ithZwuEppz1Yq3aaza57G4QNxDAf8xukOBbrVsaXbR2rsnnyyhHS5F/WBTxSD1If
# xp4VpX6+n6lXFllVcq9ok3DCsrp1mWpzMpTREEQQLt+C8weE5nQ7bXHiLQwb7iDV
# ySAdYyktzuxeTsiT+CFhmzTrBcZe7FsavOvJz82sNEBfsXpm7nfISKhmV1efVFiO
# DCu3T6cw2Vbuyntd463JT17lNecxy9qTXtyOj4DatpGYQJB5w3jHtrHEtWoYOAMQ
# jdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRzKm6RAXwhTNS8rhsDdV14Ztk6MUSaM0C/
# CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRcRo9k98FpiHaYdj1ZXUJ2h4mXaXpI8OCi
# EhtmmnTK3kse5w5jrubU75KSOp493ADkRSWJtppEGSt+wJS00mFt6zPZxd9LBADM
# fRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMYRJUadmJ+9oCw++hkpjPRiQfhvbfmQ6QY
# uKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4mrLZBdd56rF+NP8m800ERElvlEFDrMcXK
# chYiCd98THU/Y+whX8QgUWtvsauGi0/C1kVfnSD8oR7FwI+isX4KJpn15GkvmB0t
# 9dmpsh3lGwIDAQABo4IBOjCCATYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU
# 7NfjgtJxXWRM3y5nP+e6mK4cD08wHwYDVR0jBBgwFoAUReuir/SSy4IxLVGLp6ch
# nfNtyA8wDgYDVR0PAQH/BAQDAgGGMHkGCCsGAQUFBwEBBG0wazAkBggrBgEFBQcw
# AYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAChjdodHRwOi8v
# Y2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3J0
# MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdp
# Q2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwEQYDVR0gBAowCDAGBgRVHSAAMA0GCSqG
# SIb3DQEBDAUAA4IBAQBwoL9DXFXnOF+go3QbPbYW1/e/Vwe9mqyhhyzshV6pGrsi
# +IcaaVQi7aSId229GhT0E0p6Ly23OO/0/4C5+KH38nLeJLxSA8hO0Cre+i1Wz/n0
# 96wwepqLsl7Uz9FDRJtDIeuWcqFItJnLnU+nBgMTdydE1Od/6Fmo8L8vC6bp8jQ8
# 7PcDx4eo0kxAGTVGamlUsLihVo7spNU96LHc/RzY9HdaXFSMb++hUD38dglohJ9v
# ytsgjTVgHAIDyyCwrFigDkBjxZgiwbJZ9VVrzyerbHbObyMt9H5xaiNrIv8SuFQt
# J37YOtnwtoeW/VvRXKwYw02fc7cBqZ9Xql4o4rmUMIIGPTCCBCWgAwIBAgITdwAA
# AAJ1BUcIyXF2/QAAAAAAAjANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDEwlQS0lS
# T09UQ0EwHhcNMjEwOTE3MTMxNjMyWhcNMzMwOTE3MTMxNzMyWjBnMRIwEAYKCZIm
# iZPyLGQBGRYCdWsxEzARBgoJkiaJk/IsZAEZFgNuaHMxFDASBgoJkiaJk/IsZAEZ
# FgRzY290MRMwEQYKCZImiZPyLGQBGRYDbnNzMREwDwYDVQQDEwhQS0lTVUJDQTCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMfBhpDw5c/+wOaC8OY37gJ1
# RkvgfmEekSxh81KldF8i6w9yTfOXSaFd5VwxkvJQEDhWVou3FTkZO2UmRyynktP2
# B4tbR8lvDf7f0RB5fXxxkeGlpyQQZxSBJ/AEMjIOHZqyz+F2P3m5CQVDJZu1cbP3
# 8bvNdTmXRJTT2YPsSG5he0JVtDLDIjF4KQmKBYWTgRBFZJ9nkNNMdj5aCzE7vO7c
# urv0Gmzeaww9XUW0iDC0Wcfvykh/sRgWBAnfjIvtNCMTzSBpcjfCgXF/Svq9vgpy
# HWFsuEMOiuHIECQwWurZczEbIrkqepIBkbzMpWshAHfiILIyHiXBCVtMg8y+SI8N
# P+2tCfg37zK/qIKbuEri0uMk5SkYeEqtxq/VGr5gVw/YmCEQfv7SEjSr3Q3u9NJv
# CL2z0fcJHLPAa/PPub4eTPz+Hc7mHfbgDb2jb9qNZ2mnS1pUqOVQnBhtlKdT9qzH
# GwiKLTUviZy9TkwqNWyDWYKzqIEQmrm9jhqUN/98VWvR282YyzXwRJ5wW/w1RR2a
# ZeFMjTzgmxxGYs155P9eBg49P/o3Eut7p6rgVxPqmh4VlFUFOXUjQuPpzQJXUlJ2
# mgzGCWzz9dJIqk7kK0IEJfl1e/KiLy5IxA68J85+bZD3aUeesMRSJUblJrW0VLQq
# riybSgeKQPgbEeQteaBxAgMBAAGjggEzMIIBLzAQBgkrBgEEAYI3FQEEAwIBADAd
# BgNVHQ4EFgQUQafq94rp7pTwJIBm4C+QLhHPGAkwGQYJKwYBBAGCNxQCBAweCgBT
# AHUAYgBDAEEwCwYDVR0PBAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0j
# BBgwFoAUDiltdJEaLzI7/Km4+7tVRY2bWGMwRAYDVR0fBD0wOzA5oDegNYYzaHR0
# cDovL0lJU01HTVROU1MubnNzLnNjb3QubmhzLnVrL2lkcC9QS0lST09UQ0EuY3Js
# MFkGCCsGAQUFBwEBBE0wSzBJBggrBgEFBQcwAoY9aHR0cDovL0lJU01HTVROU1Mu
# bnNzLnNjb3QubmhzLnVrL2lkcC9QS0lSb290Q0FfUEtJUk9PVENBLmNydDANBgkq
# hkiG9w0BAQsFAAOCAgEAL/HAtgeSy20hFaZbaFs09mvf1AkEOwOaJ9GITq2TTvpv
# lqyPejqICGD7/DpvH6u/reXL8RpaVvZw8XJl9/mROYR6k8yxgUYdtf+w4W6dpPA8
# o6OwzwnOR/iV/K3cTct7lHegGBW44U+nY3hQcQeEtmT4GnzdpYdIv7wCic5cawaC
# dDvmpx4l8w5R7MTr2sPiWMJIccigGsWzZom9k/xC0ObM3y3DNCbAJnK09Jzfl2Nn
# cI3//IenADzND9z5CC23KKt9LqfLDU/xR+UGaN8RDFGwRUzcwdnKrMNLacMLv0wy
# u0wUwKRyPMWeSePHEDFf/qNhVVLJL3IUnc9Lfgbh6BUm8T2HlLwXrAlmBIZPue2z
# DC/ixMx53AKd/t2TlIdh0AjADoa3eFH5tD0OAYjLIMm9HRcYpirarmmSRZ3CL0Fe
# gnJm1c9EufzzmY6Om18dSTDeMDYHGsCIDotsIupo6zUZWS/9N1ECtLlOixm21K6T
# eclMV8dR28miRf0ZkQOEM2/6Dt+wG4lF8uJl3vCJCDubrpxMPPqMs3O9KjOoDlHy
# 46/cQoyyaCuwxiU0EyMSZ56gsUiFGjd+yDtcpTocY0h20r6j22BB49YcaZ8n842x
# qKgFXiqCYcuvcOz6/accs9XFSf9PFJpk45SOSKaY5/Qi4X+Ga9/VYS5YBBwN/asw
# gga0MIIEnKADAgECAhANx6xXBf8hmS5AQyIMOkmGMA0GCSqGSIb3DQEBCwUAMGIx
# CzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3
# dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBH
# NDAeFw0yNTA1MDcwMDAwMDBaFw0zODAxMTQyMzU5NTlaMGkxCzAJBgNVBAYTAlVT
# MRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1
# c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC0eDHTCphBcr48RsAcrHXbo0Zo
# dLRRF51NrY0NlLWZloMsVO1DahGPNRcybEKq+RuwOnPhof6pvF4uGjwjqNjfEvUi
# 6wuim5bap+0lgloM2zX4kftn5B1IpYzTqpyFQ/4Bt0mAxAHeHYNnQxqXmRinvuNg
# xVBdJkf77S2uPoCj7GH8BLuxBG5AvftBdsOECS1UkxBvMgEdgkFiDNYiOTx4OtiF
# cMSkqTtF2hfQz3zQSku2Ws3IfDReb6e3mmdglTcaarps0wjUjsZvkgFkriK9tUKJ
# m/s80FiocSk1VYLZlDwFt+cVFBURJg6zMUjZa/zbCclF83bRVFLeGkuAhHiGPMvS
# GmhgaTzVyhYn4p0+8y9oHRaQT/aofEnS5xLrfxnGpTXiUOeSLsJygoLPp66bkDX1
# ZlAeSpQl92QOMeRxykvq6gbylsXQskBBBnGy3tW/AMOMCZIVNSaz7BX8VtYGqLt9
# MmeOreGPRdtBx3yGOP+rx3rKWDEJlIqLXvJWnY0v5ydPpOjL6s36czwzsucuoKs7
# Yk/ehb//Wx+5kMqIMRvUBDx6z1ev+7psNOdgJMoiwOrUG2ZdSoQbU2rMkpLiQ6bG
# RinZbI4OLu9BMIFm1UUl9VnePs6BaaeEWvjJSjNm2qA+sdFUeEY0qVjPKOWug/G6
# X5uAiynM7Bu2ayBjUwIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAd
# BgNVHQ4EFgQU729TSunkBnx6yuKQVvYv1Ensy04wHwYDVR0jBBgwFoAU7NfjgtJx
# XWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUF
# BwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGln
# aWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJo
# dHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNy
# bDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQEL
# BQADggIBABfO+xaAHP4HPRF2cTC9vgvItTSmf83Qh8WIGjB/T8ObXAZz8OjuhUxj
# aaFdleMM0lBryPTQM2qEJPe36zwbSI/mS83afsl3YTj+IQhQE7jU/kXjjytJgnn0
# hvrV6hqWGd3rLAUt6vJy9lMDPjTLxLgXf9r5nWMQwr8Myb9rEVKChHyfpzee5kH0
# F8HABBgr0UdqirZ7bowe9Vj2AIMD8liyrukZ2iA/wdG2th9y1IsA0QF8dTXqvcnT
# mpfeQh35k5zOCPmSNq1UH410ANVko43+Cdmu4y81hjajV/gxdEkMx1NKU4uHQcKf
# ZxAvBAKqMVuqte69M9J6A47OvgRaPs+2ykgcGV00TYr2Lr3ty9qIijanrUR3anzE
# wlvzZiiyfTPjLbnFRsjsYg39OlV8cipDoq7+qNNjqFzeGxcytL5TTLL4ZaoBdqbh
# OhZ3ZRDUphPvSRmMThi0vw9vODRzW6AxnJll38F0cuJG7uEBYTptMSbhdhGQDpOX
# gpIUsWTjd6xpR6oaQf/DJbg3s6KCLPAlZ66RzIg9sC+NJpud/v4+7RWsWCiKi9EO
# LLHfMR2ZyJ/+xhCx9yHbxtl5TPau1j/1MIDpMPx0LckTetiSuEtQvLsNz3Qbp7wG
# WqbIiOWCnb5WqxL3/BAPvIXKUjPSxyZsq8WhbaM2tszWkPZPubdcMIIG7TCCBNWg
# AwIBAgIQCoDvGEuN8QWC0cR2p5V0aDANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQG
# EwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0
# IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0Ex
# MB4XDTI1MDYwNDAwMDAwMFoXDTM2MDkwMzIzNTk1OVowYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBTSEEy
# NTYgUlNBNDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVyIDIwMjUgMTCCAiIwDQYJKoZI
# hvcNAQEBBQADggIPADCCAgoCggIBANBGrC0Sxp7Q6q5gVrMrV7pvUf+GcAoB38o3
# zBlCMGMyqJnfFNZx+wvA69HFTBdwbHwBSOeLpvPnZ8ZN+vo8dE2/pPvOx/Vj8Tch
# TySA2R4QKpVD7dvNZh6wW2R6kSu9RJt/4QhguSssp3qome7MrxVyfQO9sMx6ZAWj
# FDYOzDi8SOhPUWlLnh00Cll8pjrUcCV3K3E0zz09ldQ//nBZZREr4h/GI6Dxb2Uo
# yrN0ijtUDVHRXdmncOOMA3CoB/iUSROUINDT98oksouTMYFOnHoRh6+86Ltc5zjP
# KHW5KqCvpSduSwhwUmotuQhcg9tw2YD3w6ySSSu+3qU8DD+nigNJFmt6LAHvH3KS
# uNLoZLc1Hf2JNMVL4Q1OpbybpMe46YceNA0LfNsnqcnpJeItK/DhKbPxTTuGoX7w
# JNdoRORVbPR1VVnDuSeHVZlc4seAO+6d2sC26/PQPdP51ho1zBp+xUIZkpSFA8vW
# doUoHLWnqWU3dCCyFG1roSrgHjSHlq8xymLnjCbSLZ49kPmk8iyyizNDIXj//cOg
# rY7rlRyTlaCCfw7aSUROwnu7zER6EaJ+AliL7ojTdS5PWPsWeupWs7NpChUk555K
# 096V1hE0yZIXe+giAwW00aHzrDchIc2bQhpp0IoKRR7YufAkprxMiXAJQ1XCmnCf
# gPf8+3mnAgMBAAGjggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTkO/zy
# Me39/dfzkXFjGVBDz2GM6DAfBgNVHSMEGDAWgBTvb1NK6eQGfHrK4pBW9i/USezL
# TjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsG
# AQUFBwEBBIGIMIGFMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5j
# b20wXQYIKwYBBQUHMAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdp
# Q2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNy
# dDBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGln
# aUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5j
# cmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEB
# CwUAA4ICAQBlKq3xHCcEua5gQezRCESeY0ByIfjk9iJP2zWLpQq1b4URGnwWBdEZ
# D9gBq9fNaNmFj6Eh8/YmRDfxT7C0k8FUFqNh+tshgb4O6Lgjg8K8elC4+oWCqnU/
# ML9lFfim8/9yJmZSe2F8AQ/UdKFOtj7YMTmqPO9mzskgiC3QYIUP2S3HQvHG1FDu
# +WUqW4daIqToXFE/JQ/EABgfZXLWU0ziTN6R3ygQBHMUBaB5bdrPbF6MRYs03h4o
# bEMnxYOX8VBRKe1uNnzQVTeLni2nHkX/QqvXnNb+YkDFkxUGtMTaiLR9wjxUxu2h
# ECZpqyU1d0IbX6Wq8/gVutDojBIFeRlqAcuEVT0cKsb+zJNEsuEB7O7/cuvTQasn
# M9AWcIQfVjnzrvwiCZ85EE8LUkqRhoS3Y50OHgaY7T/lwd6UArb+BOVAkg2oOvol
# /DJgddJ35XTxfUlQ+8Hggt8l2Yv7roancJIFcbojBcxlRcGG0LIhp6GvReQGgMgY
# xQbV1S3CrWqZzBt1R9xJgKf47CdxVRd/ndUlQ05oxYy2zRWVFjF7mcr4C34Mj3oc
# CVccAvlKV9jEnstrniLvUxxVZE/rptb7IRE2lskKPIJgbaP5t2nGj/ULLi49xTcB
# ZU8atufk+EMF/cWuiC7POGT75qaL6vdCvHlshtjdNXOCIUjsarfNZzCCCCgwggYQ
# oAMCAQICE2AAAAjjUmk3Xs1kd3YAAAAACOMwDQYJKoZIhvcNAQELBQAwZzESMBAG
# CgmSJomT8ixkARkWAnVrMRMwEQYKCZImiZPyLGQBGRYDbmhzMRQwEgYKCZImiZPy
# LGQBGRYEc2NvdDETMBEGCgmSJomT8ixkARkWA25zczERMA8GA1UEAxMIUEtJU1VC
# Q0EwHhcNMjUwODIwMTE0MzM1WhcNMjcwODIwMTE0MzM1WjCBuTESMBAGCgmSJomT
# 8ixkARkWAnVrMRMwEQYKCZImiZPyLGQBGRYDbmhzMRQwEgYKCZImiZPyLGQBGRYE
# c2NvdDETMBEGCgmSJomT8ixkARkWA25zczEpMCcGA1UECxMgQWRtaW4gQWNjb3Vu
# dHMgKG5vbiBTZXJ2ZXIgVGVhbSkxHzAdBgNVBAsTFkRlc2t0b3AgQWRtaW4gQWNj
# b3VudHMxFzAVBgNVBAMTDmdhcnkgbGFpcmQtRFNLMIIBIjANBgkqhkiG9w0BAQEF
# AAOCAQ8AMIIBCgKCAQEAoO8L2mBPR0wNA5HvYRBb3xOHrZi13sAgdedOrbqGOviu
# x6Y1MKJbnFvtZaLNAFVumJccsp1cRHY6Rl9EDCC0Pmd89qXhIZTHFDYs03nyWyB6
# gPpNXgibrWBoJLlaqPinoI3jhWVy5iSXbZY1mgSEKTNxJILXThOKUQ7ifZby77+s
# EoGH6GMREkgATAnbIS0SUVQMVqX5eRi2SW1iykHz7G60VG/XuF+wfDgjwQX6q/Ku
# eBG11mvwUOnlr5bUi5S3jK9etVQLkkoQV5BYb7EG4rnzgz+Hu/6T9KzOBhhSdOw/
# 0SnNR8NF3zBGPeVGODPbZ4+W7S3RiZcX/xgNx3O05QIDAQABo4IDeDCCA3QwPQYJ
# KwYBBAGCNxUHBDAwLgYmKwYBBAGCNxUIgau/ZILf7kKH9Y8Bh9iOe4e2331Fg5Pe
# XIS2+EYCAWQCAQYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwCwYDVR0PBAQDAgeAMBsG
# CSsGAQQBgjcVCgQOMAwwCgYIKwYBBQUHAwMwHQYDVR0OBBYEFIldCKuj36Tvqux0
# WpHTe8GDIuggMB8GA1UdIwQYMBaAFEGn6veK6e6U8CSAZuAvkC4RzxgJMIIBBQYD
# VR0fBIH9MIH6MIH3oIH0oIHxhjJodHRwOi8vSUlTTUdNVE5TUy5OU1MuU0NPVC5O
# SFMuVUsvaWRwL1BLSVNVQkNBLmNybIaBumxkYXA6Ly8vQ049UEtJU1VCQ0EsQ049
# UEtJU1VCQ0EsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
# cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9bnNzLERDPXNjb3QsREM9bmhzLERD
# PXVrP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1j
# UkxEaXN0cmlidXRpb25Qb2ludDCCAR8GCCsGAQUFBwEBBIIBETCCAQ0wVwYIKwYB
# BQUHMAKGS2h0dHA6Ly9JSVNNR01UTlNTLk5TUy5TQ09ULk5IUy5VSy9pZHAvUEtJ
# U1VCQ0EubnNzLnNjb3QubmhzLnVrX1BLSVNVQkNBLmNydDCBsQYIKwYBBQUHMAKG
# gaRsZGFwOi8vL0NOPVBLSVNVQkNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXklMjBT
# ZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPW5zcyxEQz1z
# Y290LERDPW5ocyxEQz11az9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9
# Y2VydGlmaWNhdGlvbkF1dGhvcml0eTA3BgNVHREEMDAuoCwGCisGAQQBgjcUAgOg
# HgwcZ2FyeWxhMDEtZHNrQG5zcy5zY290Lm5ocy51azBPBgkrBgEEAYI3GQIEQjBA
# oD4GCisGAQQBgjcZAgGgMAQuUy0xLTUtMjEtNjY0MzQyMzk2LTE1MjA1OTI1Njgt
# MjI2MjU5MjY2LTEyODk3MTANBgkqhkiG9w0BAQsFAAOCAgEAEjJGCLoJ2r5L/Ldd
# aAu2btQQjDSKcmoaRupVIal3tQnkAvVJc+29ZDC9/VmFA/41uO4sEVADT0OepVt1
# 83EdZgXipQbuIfn1+gVDg27K/yWMwKrEwz6PmQCIJCMhnLOOKJMJQMcG1ZwYsrHD
# nKdg4GgdZVT8gfD2MGqhMGcm7H/I1DnHauvIBH+IKO7Rh2vC/4BYpGlhsoseXM/7
# TfNHRNyhtrUnndcm5VYsFbRsvk7d1/LKlJ/2EJgWD7zmUh34JmAHwyVMngJhxiAH
# IkEJhlQgI18D1gF+q0ojdY4xxr8B0KFaaLA08R3yoHAEIgqsMD/mF8zdt3rJ4mPG
# H15C2vtGKKlt3fa/DcDw6fnNhaKWpnOpPm/Dhtt0gfYPUYoqNNqVz6OQbhvJqeaK
# 7MIobqNttmogUkH7VicHXuqJ2IFjVW1eh3LL+7TRnH14G2kY5LKPxDrDWxctC2dU
# DzT5FFatW8bhOGXbJseULaQjqOatQR1zi+Ihckmf7ENE2dkFgImCQKvhnnr89QZ0
# MhSFQJqpS1aHDt2h0VP1UuX+aND56rzeNJPhGQPt9wlYGwnUoEDZ11am2t1kyBZd
# +R0Gfv6dhU10BYkuf4p5HOGHyGsbZT53wrMQE/EHOPK7uL8KTo7vbymWFU7nGyb4
# 8QvCYv+hSjUo6bpvfZBrW9GUhwoxggURMIIFDQIBATB+MGcxEjAQBgoJkiaJk/Is
# ZAEZFgJ1azETMBEGCgmSJomT8ixkARkWA25oczEUMBIGCgmSJomT8ixkARkWBHNj
# b3QxEzARBgoJkiaJk/IsZAEZFgNuc3MxETAPBgNVBAMTCFBLSVNVQkNBAhNgAAAI
# 41JpN17NZHd2AAAAAAjjMAkGBSsOAwIaBQCgQDAZBgkqhkiG9w0BCQMxDAYKKwYB
# BAGCNwIBBDAjBgkqhkiG9w0BCQQxFgQUinBuB2yWU9SpyF5XRijuk/o3/gowDQYJ
# KoZIhvcNAQEBBQAEggEAmd2lybf896wdnXyDE9woLtUQVNdff7KZBBchBNw2Mnr4
# WAEynGGmzUS8BvUWaCwUgwIcE/d/QaUAYD91wWRGzTLaMu0iwFpKDOY79YNs21HW
# 0Nk7Soaf7OiFbmcH/YgI1rY0FaElOnAkpstUKTTefucUGmTe3RTr57mX1NEY54YV
# grGDq572I1EFKheg7fWe6nQBwmRustBgMFh8mrwURJChIgu+AxR556UDsrwEylZ+
# 7D1AlLWInAwCHFbPmLfvyvn8iPZ/AHlykCcetFy/1Z+WJ8s9QOGSyGYox4JfxKSo
# RL9nh007CyfGRJbkNSkSW1AGlNz8Qba5R5kerxHNp6GCAyYwggMiBgkqhkiG9w0B
# CQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2Vy
# dCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBp
# bmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJ
# YIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3
# DQEJBTEPFw0yNjAxMjYxNTQ2MDhaMC8GCSqGSIb3DQEJBDEiBCDYNGFGIg/kdA4U
# E+QAFtZEJWKyfA+IziNaNFbDzq1UIzANBgkqhkiG9w0BAQEFAASCAgAWQF7ptmBs
# zq9j2L0ZcY4WxkinLT6lMemrNO/DRsSB7+NrZKGgrhpkuVC5Cru/UsMC7Qfz9TIu
# /gzCBmsGMM6K/NYmJnR9zPT92xvdVLD/XYQwWpNflEDVq6/HTSTYkwgkw6TZbtK7
# DFrOXdoIoH8cKXUL0DG4IOdY3i1kMSphg/2X9GhGQCwoQNgVTOAfhqMONiaBmHN2
# c1SOcQiS2EEwU1O6DvNVWobz0Id6psX8cjg3pxLqK52D2ifHunDBjL6xQbp3w26q
# ShylC/dMYsRaHhGORWz2eTLbn7VwMnfKrlASvYsODu7mdwujnktdfGmP9W/wqYhr
# Tfq2HbykQIHXAX6EhiI4Ztbewii9x+Zp4twytCrUSt80Vgmz51sq+lWqzFwLUI30
# /XDFxNiyK61XGQADPTQL4AM3NVqvl7KpqYuQRZdIWs/2PRIjPNroFj1vFmC0NvIJ
# encUJQ1raCawOT+6CYkamEplWrVNbwXY0H0hLFAk3Z3z0DCizfsBRHRgm/U8mV6R
# zRvVXIWXdmHyugHYtZ9rWw6IOJzoaJfyvaa7eUqZ0EZsRHAqeHHgoLfsJYgmHZcI
# MLRbE+cwAzwHp/kRkSZt3GeJBhQnBy6uvtx5lq4am9xJNCi+93duzExmVFbPBfHq
# edF33DJwacIz92N7iBvUg2P1c+tDqaBfWQ==
# SIG # End signature block
