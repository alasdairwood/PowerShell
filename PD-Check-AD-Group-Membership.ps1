Import-Module ActiveDirectory

$GroupName  = "LAN-Security-WUfB-Ring-1-Win11-C-Intune"

$ExclusionGroups = @(
    "LAN-Security-WUfB-Win11-Exclusion-C-Intune",
    "LAN-Security-WUfB-Ring-0-Win11-C-Intune"
)

$OutputFile = "C:\WorkArea\CSV\Computers-NotInGroup.csv"

# ------------------------------------------------------------
# Resolve the target group
# ------------------------------------------------------------

$Group = Get-ADGroup -Identity $GroupName -ErrorAction Stop
$GroupDN = $Group.DistinguishedName

Write-Host ""
Write-Host "Checking membership of: $($Group.Name)" -ForegroundColor Cyan

# AD recursive membership matching rule
$LDAPFilter = "(&(objectCategory=computer)(objectClass=computer)(memberOf:1.2.840.113556.1.4.1941:=$GroupDN))"

# Get computers that ARE members of the target group,
# including nested membership
$Members = Get-ADComputer -LDAPFilter $LDAPFilter `
    -Properties ObjectGUID

# Build fast GUID lookup
$MemberGuids = @{}

foreach ($Computer in $Members) {
    $MemberGuids[$Computer.ObjectGUID.Guid] = $true
}

Write-Host "Computer members found: $($MemberGuids.Count)" -ForegroundColor Cyan

# ------------------------------------------------------------
# Build exclusion group membership list
# ------------------------------------------------------------

$ExcludedComputerGuids = @{}

foreach ($ExclusionGroupName in $ExclusionGroups) {

    Write-Host ""
    Write-Host "Checking exclusion group: $ExclusionGroupName" -ForegroundColor Magenta

    # Resolve exclusion group
    $ExclusionGroup = Get-ADGroup -Identity $ExclusionGroupName -ErrorAction Stop
    $ExclusionGroupDN = $ExclusionGroup.DistinguishedName

    # Find computer members, including nested membership
    $ExclusionLDAPFilter = "(&(objectCategory=computer)(objectClass=computer)(memberOf:1.2.840.113556.1.4.1941:=$ExclusionGroupDN))"

    $ExcludedComputers = Get-ADComputer -LDAPFilter $ExclusionLDAPFilter `
        -Properties ObjectGUID

    Write-Host "Computer members found: $($ExcludedComputers.Count)" -ForegroundColor Magenta

    # Add them to the exclusion lookup
    foreach ($Computer in $ExcludedComputers) {
        $ExcludedComputerGuids[$Computer.ObjectGUID.Guid] = $true
    }
}

Write-Host ""
Write-Host "Unique computers in exclusion groups: $($ExcludedComputerGuids.Count)" -ForegroundColor Magenta

# ------------------------------------------------------------
# Find eligible computers
# ------------------------------------------------------------

# Get enabled workstation computers
#
# Exclude:
#   - Servers
#   - Computers already in Ring 1
#   - Computers in either exclusion group

$NotMembers = Get-ADComputer -Filter 'Enabled -eq $true' `
    -Properties DNSHostName, OperatingSystem, DistinguishedName, ObjectGUID |
    Where-Object {

        $_.OperatingSystem -notlike "*Server*" -and

        -not $MemberGuids.ContainsKey(
            $_.ObjectGUID.Guid
        ) -and

        -not $ExcludedComputerGuids.ContainsKey(
            $_.ObjectGUID.Guid
        )
    } |
    Select-Object Name,
                  DNSHostName,
                  OperatingSystem,
                  DistinguishedName |
    Sort-Object Name

# ------------------------------------------------------------
# Display results
# ------------------------------------------------------------

$NotMembers |
    Format-Table Name, DNSHostName, OperatingSystem -AutoSize

# ------------------------------------------------------------
# Export results
# ------------------------------------------------------------

$NotMembers |
    Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8

# ------------------------------------------------------------
# Summary
# ------------------------------------------------------------

Write-Host ""
Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "Summary" -ForegroundColor Cyan
Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray

Write-Host "Target group: $($Group.Name)" -ForegroundColor Cyan
Write-Host "Computers already in target group: $($MemberGuids.Count)" -ForegroundColor Cyan

Write-Host "Computers in exclusion groups: $($ExcludedComputerGuids.Count)" -ForegroundColor Magenta

Write-Host "Eligible workstations NOT in target group: $($NotMembers.Count)" -ForegroundColor Yellow

Write-Host "Exported to: $OutputFile" -ForegroundColor Green