
<#
MIT License

Copyright (c) 2024 Microsoft and Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Filename: UninstallClassicTeams-IntuneRemediation.ps1
Version: 1.2.1 (cleaned)
Description: Intune-compatible script to clean up classic Teams and related artifacts for all users on the device.
#>

param(
    [Parameter()]
    [switch]$SkipAllArtifactsRemoval
)

# Be resilient in IME context
$ErrorActionPreference = 'Continue'

# Application definition for classic Teams (machine-wide installer footprint)
$applicationDefinitions = @(
    @{
        Name        = 'Teams'
        DisplayName = 'Teams'
        Publisher   = 'Microsoft'
        Exe         = 'teams'
        IDs         = @(
            '731F6BAA-A986-45A4-8936-7C3AAAAA760B',
            '{731F6BAA-A986-45A4-8936-7C3AAAAA760B}'
        )
        RegistryKeys = @(
            'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Teams'
        )
        CleanUp = @(
            @{
                RunUninstall      = $true
                RemoveRegistryKeys= $true
                RemoveDirectory   = $true
            }
        )
    }
)

# Counters for a summary
$ScriptResult = @{
    NumProfiles                                   = 0
    NumApplicationsFound                           = 0
    NumApplicationsRemoved                         = 0
    FindApplicationProfilesLoadedSuccessfully      = 0
    FindApplicationProfilesLoadedFailed            = 0
    FindApplicationProfilesUnloadedSuccessfully    = 0
    FindApplicationProfilesUnloadedFailed          = 0
    FindApplicationInstallationFound               = 0
    RemoveApplicationProfilesLoadedSuccessfully    = 0
    RemoveApplicationProfilesLoadedFailed          = 0
    RemoveApplicationNumProfilesUnloadedSuccessfully = 0
    RemoveApplicationProfilesUnloadedFailed        = 0
    RemoveApplicationUninstallionPerformed         = 0
    StaleFileSystemEntryDeleted                    = 0
    AppDataEntryDeleted                            = 0
    StaleRegkeyEntryDeleted                        = 0
    MachineWideInstallerStaleRegkeyEntryDeleted    = 0
    TeamsMeetingAddinDeleted                       = 0
    TeamsWideInstallerRunKeyDeleted                = 0
    StaleUserAssociationRegkeyEntryDeleted         = 0
    StaleSquirrelRegkeyEntryDeleted                = 0
    RemovedBackupMsiInstaller                      = 0
    RemovedBackupMsiInstallerRegkeys               = 0
    StaleVDITMAEntryDeleted                        = 0
    StaleVDIPresenceAddinEntryDeleted              = 0
    SquirrelTempDeleted                            = 0
    ScriptErrors                                   = 0
}

# Create a unique file name for logs
function Get-UniqueFilename {
    param (
        [string]$BaseName,
        [string]$Extension = 'txt',
        [string]$DateTimeFormat = 'yyyyMMddHHmmss'
    )
    $timestamp = (Get-Date).ToString($DateTimeFormat)
    return "$BaseName-$timestamp.$Extension"
}

# Log path (ProgramData is stable for Intune Management Extension)
$LogPath = "$($ENV:ProgramData)\Microsoft\IntuneManagementExtension\Logs"
if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
}
$Logfile = Join-Path $LogPath (Get-UniqueFilename 'Classic_Teams_Uninstallation')

function Write-Teams-Log {
    param([string]$LogString)
    $Stamp = (Get-Date).ToString('yyyy/MM/dd HH:mm:ss')
    $LogMessage = "$Stamp $LogString"
    Add-Content -Path $LogFile -Value $LogMessage
    Write-Output $LogMessage
}

# Safely unload a temporary loaded hive
function Unload-RegistryHive {
    param(
        [string]$HiveName,
        [int]$MaxRetries = 5
    )
    $retryCount = 0
    $success = $false
    while (-not $success -and $retryCount -lt $MaxRetries) {
        try {
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
            Start-Sleep -Milliseconds 500
            $process = Start-Process "$($env:ComSpec)" -ArgumentList @('/c',"REG UNLOAD `"HKLM\$HiveName`"") -Wait -WindowStyle Hidden -PassThru
            if ($process.ExitCode -eq 0) { $success = $true; return $true } else { $retryCount++; Start-Sleep -Seconds 2 }
        } catch { $retryCount++; Start-Sleep -Seconds 2 }
    }
    if (-not $success) { Write-Teams-Log "Warning: Failed to unload registry hive HKLM\$HiveName after $MaxRetries attempts" }
    return $success
}

# Discover installed apps based on registry footprints
function Find-WindowsApplication {
    param(
        [Parameter(Mandatory)] [psobject[]]$ApplicationDefinitions = $null,
        [switch]$AllUsers
    )

    if ((-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) -or
        (-not ([bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match 'S-1-5-32-544')))) {
        Write-Teams-Log "Warning: $($MyInvocation.MyCommand): Running without elevated permissions will reduce functionality"
    }

    Write-Teams-Log "$($MyInvocation.MyCommand): Searching for software..."

    $installed32bitComponents = @(
        Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' -ErrorAction SilentlyContinue | ForEach-Object { Get-ItemProperty $_.PsPath } | Select-Object *
    )
    $installed64bitComponents = @(
        Get-ChildItem 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall' -ErrorAction SilentlyContinue | ForEach-Object { Get-ItemProperty $_.PsPath } | Select-Object *
    )
    $systemEnvironment = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -ErrorAction SilentlyContinue)

    $userComponents = @{}
    $foundApplicationList = @()
    $componentSourceList = @{}

    $componentSourceList['SYSTEM'] = [psobject]@{
        Installed32BitComponents = $installed32bitComponents
        Installed64BitComponents = $installed64bitComponents
        Environment              = $systemEnvironment
        RegFile                  = $null
        Username                 = $null
        HiveName                 = $null
    }

    $componentSourceList['CURRENTUSER'] = [psobject]@{
        Installed32BitComponents = @(
            Get-ChildItem 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' -ErrorAction SilentlyContinue | ForEach-Object { Get-ItemProperty $_.PsPath } | Select-Object *
        )
        Installed64BitComponents = @(
            Get-ChildItem 'HKCU:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall' -ErrorAction SilentlyContinue | ForEach-Object { Get-ItemProperty $_.PsPath } | Select-Object *
        )
        Environment = (Get-ItemProperty 'HKCU:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -ErrorAction SilentlyContinue)
        RegFile     = $null
        Username    = 'SYSTEM'
        HiveName    = $null
    }

    if ($AllUsers) {
        Write-Teams-Log "$($MyInvocation.MyCommand): Getting list of installed software for each user..."
        foreach ($userDirectory in @(Get-ChildItem "$($ENV:SystemDrive)\users" -ErrorAction SilentlyContinue)) {
            if ($userDirectory -ne $null) {
                $userName = "$($userDirectory.Name.ToLower())"
                $ScriptResult.NumProfiles++
                if ($userName -in @('public', 'default', 'default user', 'all users')) { continue }

                $userComponents["$($userName)"] = [psobject]@{ Installed32BitComponents=$null; Installed64BitComponents=$null; Environment=$null; RegFile=$null; Username=$null; HiveName=$null }
                $componentSourceList["$($userName)"] = $userComponents["$($userName)"]

                $ntuserPath = "$($userDirectory.FullName)\NTUSER.DAT"
                if (-not (Test-Path $ntuserPath)) { Write-Teams-Log "Warning: $($MyInvocation.MyCommand): NTUSER.DAT not found for $userName"; continue }

                try {
                    $hiveName = "TEMP_$($userName)_$(Get-Random)"
                    $command = "REG LOAD `"HKLM\$hiveName`" `"$ntuserPath`""
                    $process = Start-Process "$($env:ComSpec)" -ArgumentList @('/c',"$($command)") -Wait -WindowStyle Hidden -PassThru
                    if ($process.ExitCode -eq 0) { $ScriptResult.FindApplicationProfilesLoadedSuccessfully++ } else { $ScriptResult.FindApplicationProfilesLoadedFailed++; Write-Teams-Log "Warning: $($MyInvocation.MyCommand): Profile loading failed with exit code $($process.ExitCode) for $userName"; continue }
                } catch { $ScriptResult.FindApplicationProfilesLoadedFailed++; Write-Teams-Log "Warning: $($MyInvocation.MyCommand): Profile loading caught exception for $userName. An error occurred: $_"; continue }

                $userRegistry = Get-Item "HKLM:\$hiveName" -ErrorAction SilentlyContinue
                if ($userRegistry -ne $null) {
                    $userComponents["$($userName)"].RegFile     = $ntuserPath
                    $userComponents["$($userName)"].HiveName    = $hiveName
                    $userComponents["$($userName)"].Environment = (Get-ItemProperty "HKLM:\$hiveName\Environment" -ErrorAction SilentlyContinue)
                    $userComponents["$($userName)"].Installed32BitComponents = @(
                        Get-ChildItem "HKLM:\$hiveName\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue | ForEach-Object { Get-ItemProperty $_.PsPath } | Select-Object *
                    )
                    $userComponents["$($userName)"].Installed64BitComponents = @(
                        Get-ChildItem "HKLM:\$hiveName\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue | ForEach-Object { Get-ItemProperty $_.PsPath } | Select-Object *
                    )

                    $componentSourceList["$($userName)"] = $userComponents["$($userName)"]

                    if (Unload-RegistryHive -HiveName $hiveName) { $ScriptResult.FindApplicationProfilesUnloadedSuccessfully++ } else { $ScriptResult.FindApplicationProfilesUnloadedFailed++ }
                }
            }
        }
    }

    foreach ($appDef in $ApplicationDefinitions) {
        if ($appDef -ne $null) {
            $foundApplicationEntry = @{
                AppDefinition = $appDef
                Location     = @{ Software=@(); Apps=@(); Components=@{}; Files=@() }
                Found        = $false
            }

            if ($appDef.RegistryKeys -ne $null -and $appDef.RegistryKeys.Count -gt 0) {
                foreach ($componentSource in $componentSourceList.Keys) {
                    $currentRegFile = $($componentSourceList["$($componentSource)"].RegFile)
                    $currentSource  = $componentSource
                    $currentHiveName= $($componentSourceList["$($componentSource)"].HiveName)
                    $currentRegKeys = @()

                    if ($componentSourceList["$($componentSource)"] -ne $null) {
                        if ($componentSourceList["$($componentSource)"].Installed32BitComponents) {
                            if ($componentSourceList["$($componentSource)"].Installed32BitComponents.Count -gt 0) {
                                $currentRegKeys += @($componentSourceList["$($componentSource)"].Installed32BitComponents)
                            }
                        }
                        if ($componentSourceList["$($componentSource)"].Installed64BitComponents) {
                            if ($componentSourceList["$($componentSource)"].Installed64BitComponents.Count -gt 0) {
                                $currentRegKeys += @($componentSourceList["$($componentSource)"].Installed64BitComponents)
                            }
                        }
                    }

                    for ($c = 0; $c -lt $currentRegKeys.Count; $c++) {
                        $regList = @($currentRegKeys[$c])
                        for ($x = 0; $x -lt $regList.Count; $x++) {
                            $appRegKey = $($regList[$x].PSPath.Replace('Microsoft.PowerShell.Core\Registry::',''))
                            for ($r = 0; $r -lt $appDef.RegistryKeys.Count; $r++) {
                                $foundEntry = $false
                                if ($appDef.RegistryKeys[$r].StartsWith('HKEY_')) {
                                    if ($appRegKey.ToLower().StartsWith($appDef.RegistryKeys[$r].ToLower())) { $foundEntry = $true }
                                } else {
                                    if ($appRegKey.ToLower().EndsWith($appDef.RegistryKeys[$r].ToLower())) { $foundEntry = $true }
                                }
                                if ($foundEntry -eq $true) {
                                    Write-Teams-Log "$($MyInvocation.MyCommand): Found application '$($appDef.Name)', adding in found application list"
                                    $componentKey = "$($regList[$x].DisplayName)" + ':' + "$($currentSource)"
                                    if ($foundApplicationEntry.Location.Components["$($componentKey)"] -eq $null) {
                                        $ScriptResult.FindApplicationInstallationFound++
                                        $foundApplicationEntry.Location.Components["$($componentKey)"] = @{
                                            Component      = $($regList[$x])
                                            ComponentSource= $($currentSource)
                                            RegistryKeys   = @()
                                            RegFile        = $currentRegFile
                                            HiveName       = $currentHiveName
                                        }
                                        $foundApplicationEntry.Location.Components["$($componentKey)"].RegistryKeys += $appRegKey
                                        $foundApplicationEntry.Found = $true
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if ($foundApplicationEntry -ne $null -and $foundApplicationEntry.Found -eq $true) { $foundApplicationList += $foundApplicationEntry }
        }
    }

    return @($foundApplicationList)
}

# Remove found application(s)
function Remove-WindowsApplication {
    param([Parameter(Mandatory)][psobject[]]$Applications = $null)

    if ((-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) -or
        (-not ([bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match 'S-1-5-32-544')))) {
        Write-Teams-Log "Warning: $($MyInvocation.MyCommand): Running without elevated permissions will reduce functionality"
    }

    Write-Teams-Log "$($MyInvocation.MyCommand): Removing application(s)..."
    Write-Teams-Log '-------------------'

    $removedApplicationList = @()
    if ($Applications) {
        for ($a = 0; $a -lt $Applications.Count; $a++) {
            if ($Applications[$a] -ne $null) {
                if ([string]::IsNullOrEmpty($Applications[$a].AppDefinition.Exe) -eq $false) {
                    $processList = @(Get-Process -Name $($Applications[$a].AppDefinition.Exe) -ErrorAction SilentlyContinue)
                    if ($processList -and $processList.Count -gt 0) {
                        Write-Teams-Log "$($MyInvocation.MyCommand): Stopping existing processes..."
                        foreach ($proc in $processList) { try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch { Write-Teams-Log "Warning: Failed to stop process $($proc.Id): $_" } }
                        Start-Sleep -Seconds 3
                    }
                }

                if ($Applications[$a].Found -eq $true) {
                    $appEntry = $Applications[$a]
                    if ($appEntry.AppDefinition -and $appEntry.AppDefinition.CleanUp) {
                        Write-Teams-Log "$($MyInvocation.MyCommand): Removing application '$($appEntry.AppDefinition.Name)'..."
                        if ($appEntry.Location -and ($appEntry.Location.Apps -or $appEntry.Location.Components.Keys -or $appEntry.Location.Software -or $appEntry.Location.Files)) {
                            $removedApplicationEntry = $null
                            if ($appEntry.Location.Components.Keys.Count -gt 0) {
                                foreach ($componentName in $appEntry.Location.Components.Keys) {
                                    $componentObj = $($appEntry.Location.Components["$($componentName)"])
                                    if ($componentObj) {
                                        if ($componentObj.Component) {
                                            if ([string]::IsNullOrEmpty($componentObj.Component.InstallLocation) -eq $false) {
                                                $installDir = Get-Item "$($componentObj.Component.InstallLocation)" -ErrorAction SilentlyContinue
                                                if ($installDir) {
                                                    if ($appEntry.AppDefinition.CleanUp.RunUninstall -eq $true) {
                                                        $uninstallCommand = "$($componentObj.Component.UninstallString)"
                                                        if ([string]::IsNullOrEmpty($componentObj.Component.QuietUninstallString) -eq $false) { $uninstallCommand = "$($componentObj.Component.QuietUninstallString)" }
                                                        if ([string]::IsNullOrEmpty($uninstallCommand) -eq $false) {
                                                            Write-Teams-Log "$($MyInvocation.MyCommand): Running component uninstall..."
                                                            try {
                                                                $uninstallProcess = Start-Process "$($env:ComSpec)" -ArgumentList @('/c',"$($uninstallCommand)") -Wait -WindowStyle Hidden -PassThru
                                                                if ($uninstallProcess.ExitCode -eq 0) { $ScriptResult.RemoveApplicationUninstallionPerformed++ } else { Write-Teams-Log "Warning: Uninstall exited with code $($uninstallProcess.ExitCode)" }
                                                            } catch { Write-Teams-Log "Warning: Uninstall failed: $_" }
                                                        } else { Write-Teams-Log "Warning: $($MyInvocation.MyCommand): Component has no uninstall command." }
                                                    }
                                                    if ($appEntry.AppDefinition.CleanUp.RemoveDirectory -eq $true) {
                                                        Write-Teams-Log "$($MyInvocation.MyCommand): Removing component directories..."
                                                        $null = Remove-Item "$($installDir.FullName)" -Recurse -Force -ErrorAction SilentlyContinue
                                                    }
                                                } else { Write-Teams-Log "Warning: $($MyInvocation.MyCommand): Component install path can't be found." }
                                            }
                                        }

                                        if ($appEntry.AppDefinition.CleanUp.RemoveRegistryKeys -eq $true) {
                                            $hiveName = $componentObj.HiveName
                                            if ($componentObj.RegistryKeys -and $componentObj.RegistryKeys.Count -gt 0) {
                                                Write-Teams-Log "$($MyInvocation.MyCommand): Removing component registry key(s)..."

                                                if ($componentObj.RegFile -and $hiveName) {
                                                    $regFile = $componentObj.RegFile
                                                    try {
                                                        $output = Start-Process "$($env:ComSpec)" -ArgumentList @('/c',"REG LOAD `"HKLM\$hiveName`" `"$regFile`"") -Wait -WindowStyle Hidden -PassThru
                                                        if ($output.ExitCode -eq 0) { $ScriptResult.RemoveApplicationProfilesLoadedSuccessfully++ } else { $ScriptResult.RemoveApplicationProfilesLoadedFailed++; Write-Teams-Log "Warning: Failed to load registry hive: exit code $($output.ExitCode)" }
                                                    } catch { $ScriptResult.RemoveApplicationProfilesLoadedFailed++; Write-Teams-Log "Warning: $($MyInvocation.MyCommand): Profile loading caught exception. An error occurred: $_" }
                                                }

                                                for ($r = 0; $r -lt $componentObj.RegistryKeys.Count; $r++) {
                                                    $regKey = "$($componentObj.RegistryKeys[$r].Replace('Microsoft.PowerShell.Core\Registry::',''))"
                                                    $null = Remove-Item "registry::$($regKey)" -Recurse -Force -ErrorAction SilentlyContinue
                                                }

                                                if ($componentObj.RegFile -and $hiveName) {
                                                    if (Unload-RegistryHive -HiveName $hiveName) { $ScriptResult.RemoveApplicationNumProfilesUnloadedSuccessfully++ } else { $ScriptResult.RemoveApplicationProfilesUnloadedFailed++ }
                                                }
                                            } else { Write-Teams-Log "Warning: $($MyInvocation.MyCommand): Component has no registry key(s)." }
                                        }
                                    }
                                }
                            }

                            $removedApplicationEntry = @{
                                AppDefinition = $appEntry.AppDefinition
                                Successful    = $true
                                Error         = $null
                            }
                            if ($removedApplicationEntry) { $removedApplicationList += $removedApplicationEntry }
                        }
                    }
                }
            }
        }
    }

    if ($removedApplicationList) { return @($removedApplicationList) }
    return $removedApplicationList
}

function Remove-DirectoryRecursively {
    param([string]$dirPath)
    if (Test-Path $dirPath) {
        try { Remove-Item -Path $dirPath -Recurse -Force -ErrorAction Stop; return $true } catch { Write-Teams-Log "Warning: Failed to remove directory $dirPath : $_"; return $false }
    } else { return $false }
}

function Remove-TeamsStaleUserProfileFileSystemEntries {
    $userProfiles = (Get-ChildItem "$($ENV:SystemDrive)\Users" -Directory -Exclude 'Public','Default','Default User').FullName
    foreach($profile in $userProfiles){
        $userProfileTeamsPath = Join-Path -Path $profile -ChildPath '\AppData\Local\Microsoft\Teams\'
        if (Remove-DirectoryRecursively -dirPath $userProfileTeamsPath) { $ScriptResult.StaleFileSystemEntryDeleted++; Write-Teams-Log 'Deleted stale file system entry successfully.' }

        $userProfileTeamsAppDataPath = Join-Path -Path $profile -ChildPath '\AppData\Roaming\Microsoft\Teams'
        if (Remove-DirectoryRecursively -dirPath $userProfileTeamsAppDataPath) { $ScriptResult.AppDataEntryDeleted++; Write-Teams-Log 'Deleted stale App data file system entry successfully.' }

        $userProfileSquirrelTempPath = Join-Path -Path $profile -ChildPath '\AppData\Local\Microsoft\SquirrelTemp'
        if (Remove-DirectoryRecursively -dirPath $userProfileSquirrelTempPath) { $ScriptResult.SquirrelTempDeleted++; Write-Teams-Log 'Deleted SquirrelTemp successfully.' }
    }
}

function Remove-TeamsMeetingAddin {
    $userProfiles = (Get-ChildItem "$($ENV:SystemDrive)\Users" -Directory -Exclude 'Public','Default','Default User').FullName
    foreach($profile in $userProfiles){
        $userProfileTMAPath = Join-Path -Path $profile -ChildPath '\AppData\Local\Microsoft\TeamsMeetingAddin'
        if (Remove-DirectoryRecursively -dirPath $userProfileTMAPath) { $ScriptResult.TeamsMeetingAddinDeleted++; Write-Teams-Log 'Deleted TMA successfully.' }
    }
}

function Remove-TeamsStaleRegKeys {
    $subkeys = (Get-ChildItem -Path 'registry::HKEY_USERS' -Exclude .DEFAULT).Name
    foreach($subkey in $subkeys){
        $regkey = "registry::$subkey\Software\Microsoft\Windows\CurrentVersion\Uninstall\Teams"
        if (Test-Path $regkey) { $null = Remove-Item "$regKey" -Recurse -Force -ErrorAction SilentlyContinue; Write-Teams-Log 'Deleted stale regkey entry from HKEY_USERS successfully.'; $ScriptResult.StaleRegkeyEntryDeleted++ }

        $associationKeyPath = "registry::$subkey\SOFTWARE\Microsoft\Office\Teams\Capabilities\URLAssociations"
        if (Test-Path $associationKeyPath) {
            $res = Get-ItemProperty -Path $associationKeyPath -Name 'msteams' -ErrorAction SilentlyContinue
            if ($res -ne $null) { $null = Remove-ItemProperty -Path $associationKeyPath -Name 'msteams' -ErrorAction SilentlyContinue; Write-Teams-Log 'Deleted URL association msteams entry.'; $ScriptResult.StaleUserAssociationRegkeyEntryDeleted++ }
        }

        $squirrelKeyPath = "registry::$subkey\Software\Microsoft\Windows\CurrentVersion\Run"
        if (Test-Path $squirrelKeyPath) {
            $res = Get-ItemProperty -Path $squirrelKeyPath -Name 'com.squirrel.Teams.Teams' -ErrorAction SilentlyContinue
            if ($res -ne $null) { $null = Remove-ItemProperty -Path $squirrelKeyPath -Name 'com.squirrel.Teams.Teams' -ErrorAction SilentlyContinue; Write-Teams-Log 'Deleted stale squirrel regkey entry.'; $ScriptResult.StaleSquirrelRegkeyEntryDeleted++ }
        }
    }
}

function Remove-TeamsWideInstallerRunKey {
    param([string]$valueName)

    $regPathWOW6432Node = 'registry::HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    if (Test-Path $regPathWOW6432Node) {
        $regValue = Get-ItemProperty -Path $regPathWOW6432Node -Name $valueName -ErrorAction SilentlyContinue
        if ($regValue -ne $null) { Remove-ItemProperty -Path $regPathWOW6432Node -Name $valueName -Force; $ScriptResult.TeamsWideInstallerRunKeyDeleted++; Write-Teams-Log "Teams wide installer uninstall step. The registry value '$valueName' has been deleted." }
    }

    $regPath = 'registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    if (Test-Path $regPath) {
        $regValue = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue
        if ($regValue -ne $null) { Remove-ItemProperty -Path $regPath -Name $valueName -Force; $ScriptResult.TeamsWideInstallerRunKeyDeleted++; Write-Teams-Log "Teams wide installer uninstall step. The registry value '$valueName' has been deleted." }
    }
}

function Remove-vdiCleanup {
    $processorArchitecture = $env:PROCESSOR_ARCHITECTURE
    $tmaPath = "${Env:ProgramFiles(x86)}\Microsoft\TeamsMeetingAddin"
    $presenceAddinPath = "${Env:ProgramFiles(x86)}\Microsoft\TeamsPresenceAddin"
    if ($processorArchitecture -eq 'x86') { $tmaPath = "${Env:ProgramFiles}\Microsoft\TeamsMeetingAddin"; $presenceAddinPath = "${Env:ProgramFiles}\Microsoft\TeamsPresenceAddin" }

    if (Remove-DirectoryRecursively -dirPath $tmaPath) { $ScriptResult.StaleVDITMAEntryDeleted++; Write-Teams-Log 'Deleted stale tma file system entry for vdi successfully.' }
    if (Remove-DirectoryRecursively -dirPath $presenceAddinPath) { $ScriptResult.StaleVDIPresenceAddinEntryDeleted++; Write-Teams-Log 'Deleted stale presence add-in file system entry for vdi successfully.' }
}

function Remove-TeamsWideInstallerUninstallKey {
    $processorArchitecture = $env:PROCESSOR_ARCHITECTURE
    if ($processorArchitecture -eq 'AMD64') {
        $regkey = 'registry::HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{731F6BAA-A986-45A4-8936-7C3AAAAA760B}'
        if (Test-Path $regkey) { $null = Remove-Item "$regKey" -Recurse -Force -ErrorAction SilentlyContinue; Write-Teams-Log 'Deleted machine wide installer uninstall keys'; $ScriptResult.MachineWideInstallerStaleRegkeyEntryDeleted++ }
    } elseif ($processorArchitecture -eq 'x86') {
        $regkey = 'registry::HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{39AF0813-FA7B-4860-ADBE-93B9B214B914}'
        if (Test-Path $regkey) { $null = Remove-Item "$regKey" -Recurse -Force -ErrorAction SilentlyContinue; Write-Teams-Log 'Deleted machine wide installer uninstall keys'; $ScriptResult.MachineWideInstallerStaleRegkeyEntryDeleted++ }
    }
}

function Remove-TeamsMachineWideBackupMsiInstaller {
    $regkey = 'registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData'
    $items = Get-ChildItem -Path $regkey -ErrorAction SilentlyContinue
    foreach ($item in $items) {
        if ($item.PSIsContainer) {
            $tempRegPath = Join-Path 'registry::' $item
            $regPath = Join-Path $tempRegPath 'Products\AAB6F137689A4A549863C7A3AAAA67B0\InstallProperties'
            if (Test-Path $regPath) {
                $res = Get-ItemProperty -Path $regPath -Name 'LocalPackage' -ErrorAction SilentlyContinue
                if ($res -ne $null) { if (Test-Path $res.LocalPackage) { Remove-Item -Path $res.LocalPackage -Force -ErrorAction SilentlyContinue; $ScriptResult.RemovedBackupMsiInstaller++ } }
                $regkeyToRemove = Join-Path $tempRegPath 'Products\AAB6F137689A4A549863C7A3AAAA67B0'
                $null = Remove-Item "$regkeyToRemove" -Recurse -Force -ErrorAction SilentlyContinue
                $ScriptResult.RemovedBackupMsiInstallerRegkeys++
            }
        }
    }
}

function Remove-PatchCacheFiles {
    # Only remove known Teams patch cache folders
    $patchCachePaths = @(
        'C:\\Windows\\Installer\\$PatchCache$\\Managed\\AD7E5E9D92C699247949F5DDF5A4D661\\',
        'C:\\Windows\\Installer\\$PatchCache$\\Managed\\3180FA93B7AF0684DAEB399B2B419B41\\'
    )
    foreach ($path in $patchCachePaths) {
        if (Test-Path $path) {
            try { Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue; Write-Teams-Log "Deleted: $path" } catch { Write-Teams-Log "Failed to delete: $path. Error: $_" }
        }
    }
}

function Remove-TeamsMachineWideInstaller {
    $processorArchitecture = $env:PROCESSOR_ARCHITECTURE
    if ($processorArchitecture -eq 'AMD64') {
        $msiProductCode = '{731F6BAA-A986-45A4-8936-7C3AAAAA760B}'
        Start-Process 'msiexec.exe' -ArgumentList "/x $msiProductCode /qn ALLUSERS=1" -Wait
        Write-Teams-Log 'Uninstalled machine wide 64-bit installer'
    } elseif ($processorArchitecture -eq 'x86') {
        $msiProductCode = '{39AF0813-FA7B-4860-ADBE-93B9B214B914}'
        Start-Process 'msiexec.exe' -ArgumentList "/x $msiProductCode /qn ALLUSERS=1" -Wait
        Write-Teams-Log 'Uninstalled machine wide x86 installer'
    }
    Remove-TeamsWideInstallerRunKey -valueName 'TeamsMachineInstaller'
    Remove-TeamsWideInstallerRunKey -valueName 'TeamsMachineUninstallerLocalAppData'
    Remove-TeamsWideInstallerRunKey -valueName 'TeamsMachineUninstallerProgramData'
    $msiExecPath = "${Env:ProgramFiles(x86)}\Teams Installer\"
    if (Test-Path $msiExecPath) { Remove-Item -Path $msiExecPath -Recurse -Force -ErrorAction SilentlyContinue }
    Remove-TeamsWideInstallerUninstallKey
}

function Remove-TeamsShortcuts {
    try {
        $TeamsIcon_old = "$($ENV:SystemDrive)\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Microsoft Teams\*.lnk"
        Get-Item $TeamsIcon_old -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
        Write-Teams-Log 'Removed Teams shortcuts'
    } catch { Write-Teams-Log "Warning: Error removing shortcuts: $_" }
}

function Create-PostScriptExecutionRegkeyEntry {
    $registryPath = 'registry::HKLM\Software\Microsoft\TeamsAdminLevelScript'
    $null = New-Item -Path $registryPath -Force -ErrorAction SilentlyContinue
    Write-Teams-Log 'Created post-script execution registry marker'
}

# =========================
# MAIN
# =========================
try {
    Write-Teams-Log '==================================='
    Write-Teams-Log 'Teams Classic Removal Script Started'
    Write-Teams-Log '=================================='
    Write-Teams-Log "Log file: $Logfile"
    Write-Teams-Log "Looking for application(s): $($applicationDefinitions.Name -join ', ')"

    $foundList = Find-WindowsApplication -ApplicationDefinitions $applicationDefinitions -AllUsers
    if ($foundList) {
        $ScriptResult.NumApplicationsFound = $foundList.Count
        Write-Teams-Log "Found $(@($foundList).Count) application(s)"
        $removeList = Remove-WindowsApplication -Applications @($foundList)
        if ($removeList -ne $null) {
            $ScriptResult.NumApplicationsRemoved = $removeList.Count
            $names = @($removeList | Where-Object { $_.Successful -eq $true }).AppDefinition.Name -join ', '
            Write-Teams-Log "Removed applications: $names"
        } else { Write-Teams-Log 'Warning: No application(s) were removed.' }
    } else { Write-Teams-Log 'No Teams Classic applications found in registry' }

    Write-Teams-Log 'Cleaning stale registry keys...'
    Remove-TeamsStaleRegKeys

    Write-Teams-Log 'Cleaning user profile file system entries...'
    Remove-TeamsStaleUserProfileFileSystemEntries

    Write-Teams-Log 'Removing Teams Meeting Add-in...'
    Remove-TeamsMeetingAddin

    Write-Teams-Log 'Removing machine-wide installer...'
    Remove-TeamsMachineWideInstaller

    Write-Teams-Log 'Removing patch cache files...'
    Remove-PatchCacheFiles

    Write-Teams-Log 'Removing backup MSI installer...'
    Remove-TeamsMachineWideBackupMsiInstaller

    if ($SkipAllArtifactsRemoval -eq $false) { Write-Teams-Log 'Performing VDI cleanup...'; Remove-vdiCleanup } else { Write-Teams-Log 'Skipping VDI cleanup (parameter set)' }

    Write-Teams-Log 'Removing Teams shortcuts...'
    Remove-TeamsShortcuts

    Write-Teams-Log 'Creating completion marker...'
    Create-PostScriptExecutionRegkeyEntry

    Write-Teams-Log '=================================='
    Write-Teams-Log 'SCRIPT EXECUTION SUMMARY'
    Write-Teams-Log '=================================='
    Write-Teams-Log "Profiles processed: $($ScriptResult.NumProfiles)"
    Write-Teams-Log "Applications found: $($ScriptResult.NumApplicationsFound)"
    Write-Teams-Log "Applications removed: $($ScriptResult.NumApplicationsRemoved)"
    Write-Teams-Log "Uninstallations performed: $($ScriptResult.RemoveApplicationUninstallionPerformed)"
    Write-Teams-Log "File system entries deleted: $($ScriptResult.StaleFileSystemEntryDeleted)"
    Write-Teams-Log "AppData entries deleted: $($ScriptResult.AppDataEntryDeleted)"
    Write-Teams-Log "Registry keys deleted: $($ScriptResult.StaleRegkeyEntryDeleted)"
    Write-Teams-Log "TMA entries deleted: $($ScriptResult.TeamsMeetingAddinDeleted)"
    Write-Teams-Log "SquirrelTemp deleted: $($ScriptResult.SquirrelTempDeleted)"
    Write-Teams-Log '=================================='
    Write-Teams-Log 'Teams Classic removal completed successfully'
    exit 0
} catch {
    $ScriptResult.ScriptErrors++
    Write-Teams-Log '=================================='
    Write-Teams-Log 'CRITICAL ERROR OCCURRED'
    Write-Teams-Log "Error: $_"
    Write-Teams-Log "Stack Trace: $($_.ScriptStackTrace)"
    Write-Teams-Log '=================================='
    exit 1
}




# SIG # Begin signature block
# MIIsVQYJKoZIhvcNAQcCoIIsRjCCLEICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUZYhDnct7kwi8e3U6BdmKtOcZ
# H4CggiauMIIFAzCCAuugAwIBAgIQHR4Hnvzqa75K+m6DORxCujANBgkqhkiG9w0B
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
# BAGCNwIBBDAjBgkqhkiG9w0BCQQxFgQUC3h0TShHWeBBtOSqiAFQHbLmp9owDQYJ
# KoZIhvcNAQEBBQAEggEARoRMg/uhsjx1rWa4BJYzUfOoQSADERvymK49b8jbHy0x
# 9ld8JdSWjPwUKVfUzlykC0vn+XR82YZtvZq/T5Aq+j0/R1/iXEqOmZO2mYB9Et8X
# Id4AcWTd878kwgrByLuyFiHiTAWB5AjXgP23tu0kRyDfOMAW/4AqYILrizAzen8C
# 0Pq71JO5g6PIb/Btwc9IaIOTeRxJ5cuX9JCJySPUru11FAdyp4OLhvnfADbVNmi4
# H+FU0daFxCJ6dZUgjfZydl8VrwJi7PVQIqEjGsxT0Zf1+Hr4hSziFycTUVKEBsMB
# 5AZanVXXyWBJ2/llOkgRdjVCw9/0Pu2XNnasbD0/FKGCAyYwggMiBgkqhkiG9w0B
# CQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2Vy
# dCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBp
# bmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJ
# YIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3
# DQEJBTEPFw0yNjAxMjYxNTQ2MjNaMC8GCSqGSIb3DQEJBDEiBCBTYvCOmpSJtjdX
# VwsH3ZOM32IBDBSBt7tTIirtEOf57DANBgkqhkiG9w0BAQEFAASCAgCStcPkyRjh
# LRhiT/dczOKYE7Amq7kz3oXWzVTE8FqfvXtPepcWH0mkfrux5jh13I9XNoPngCSA
# utj9LHR1ClzGfOneUAO4LJIvpAyOR57H/oOa4pTcE5EJpfJl5kQMdLGgXEcraj/a
# RegrzgSsIQkIAq3C6IS20AuLsA0iE0FSE3gXNGKce0I0cyjcZawW5Kq2prkSmgJQ
# xNyq7SUW6vSma56YsZZ4QRtDCqhkdJ2D+h6jM1SAo/Z6a7pNgaSPW3uS52LbwW3e
# N+GB9NwFypP1BNGJnYiaycVQB6rSMOvLGEPXe0LbvqkG5i0LYDomIBhQiOaVGQQ2
# 7zCzxsBCfTHyXEVQVHNJ/NzZ97ATb2M30LGwVdwvxfIL9Q5pjqKEysdxY4NFe+x+
# HS+5i+rsQA4q+xSlpO7uy0ZXVZp/Mg88NmYSPCqbDwYRbhrri/uUmPweJCwcaNtr
# 9q/G/0BPdTiKXD6FiaToD8x7Q+V6NOOk+UXBHnRrfNtPnZM8b8A5HpWZ9agml20m
# Yq5zwrpjtBu/Ivl2GCS7vMG1Q3bd8f4BGHExuLJLIqi8ukFVi3yC8TD83sKmCALr
# 5hLyIHapDhm9yI/fbzuwhtreTbBPphD/VnrEmG/EVuS+GLLWiJunr2RAAylJt7g/
# VhUyL/hOYl2hCyRZ2BCpjOe4cl57Hx6njA==
# SIG # End signature block
