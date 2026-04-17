<#
.SYNOPSIS
Import computers from CSV, check membership in two AD security groups, export computers that match.

.NOTES
- Requires RSAT ActiveDirectory module
- Run in a context that can query AD
#>

# -------------------------
# CONFIG
# -------------------------
$InputCsv        = "C:\WorkArea\Win10-LessThan-64GB-Free.csv"
$OutputCsv       = "C:\WorkArea\Win10-Excluded.csv"
$AuditCsv        = "C:\WorkArea\computers_audit_all_results.csv"   # optional, set $null to disable
$ComputerColumn  = "ComputerName"                              # CSV column name

$Group1          = "GG-Lanarkshire-Computers-Administrative-LocalDiskClean"
$Group2          = "LAN-Security-WUfB-Win11-Exclusion-C-Intune"

# Choose membership mode:
# $true  = include nested memberships (most accurate)
# $false = direct membership only (fast)
$IncludeNested   = $true

# If you want "member of either group" instead of "both", set to $true
$MatchEither     = $false

# -------------------------
# START
# -------------------------
Import-Module ActiveDirectory -ErrorAction Stop

# Resolve group DN once (fast + avoids name ambiguity)
try {
    $g1 = Get-ADGroup -Identity $Group1 -ErrorAction Stop
    $g2 = Get-ADGroup -Identity $Group2 -ErrorAction Stop
}
catch {
    throw "Failed to resolve one or both groups. Check names/IDs. Error: $($_.Exception.Message)"
}

$g1DN = $g1.DistinguishedName
$g2DN = $g2.DistinguishedName

# Read CSV
$input = Import-Csv -Path $InputCsv -ErrorAction Stop
if (-not $input) { throw "Input CSV appears empty: $InputCsv" }

$results = foreach ($row in $input) {

    $name = ($row.$ComputerColumn).Trim()

    if ([string]::IsNullOrWhiteSpace($name)) {
        [pscustomobject]@{
            Computer       = $null
            FoundInAD      = $false
            InGroup1       = $false
            InGroup2       = $false
            Match          = $false
            Mode           = if ($IncludeNested) { "Nested" } else { "Direct" }
            Notes          = "Blank computer name in CSV row"
        }
        continue
    }

    # Try resolve AD computer (accept PC001 or PC001$ in input)
    $lookup = $name.TrimEnd('$')

    $comp = $null
    try {
        $comp = Get-ADComputer -Identity $lookup -Properties MemberOf -ErrorAction Stop
    }
    catch {
        [pscustomobject]@{
            Computer       = $lookup
            FoundInAD      = $false
            InGroup1       = $false
            InGroup2       = $false
            Match          = $false
            Mode           = if ($IncludeNested) { "Nested" } else { "Direct" }
            Notes          = "Not found in AD (or no permission)"
        }
        continue
    }

    # Membership checks
    $inG1 = $false
    $inG2 = $false

    if ($IncludeNested) {
        # Includes nested membership
        try {
            $allGroups = Get-ADPrincipalGroupMembership -Identity $comp.DistinguishedName -ErrorAction Stop |
                         Select-Object -ExpandProperty DistinguishedName

            $inG1 = $allGroups -contains $g1DN
            $inG2 = $allGroups -contains $g2DN
        }
        catch {
            # Fallback to direct membership if principal group membership fails
            $inG1 = $comp.MemberOf -contains $g1DN
            $inG2 = $comp.MemberOf -contains $g2DN
        }
    }
    else {
        # Direct membership only
        $inG1 = $comp.MemberOf -contains $g1DN
        $inG2 = $comp.MemberOf -contains $g2DN
    }

    $match = if ($MatchEither) { ($inG1 -or $inG2) } else { ($inG1 -and $inG2) }

    [pscustomobject]@{
        Computer       = $comp.Name
        FoundInAD      = $true
        InGroup1       = $inG1
        InGroup2       = $inG2
        Match          = $match
        Mode           = if ($IncludeNested) { "Nested" } else { "Direct" }
        Notes          = $null
    }
}

# Export only matches
$results | Where-Object { $_.Match -eq $true } |
    Select-Object Computer, InGroup1, InGroup2, Mode |
    Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8

Write-Host "Exported matches to: $OutputCsv" -ForegroundColor Green

# Optional audit export (all results)
if ($AuditCsv) {
    $results | Export-Csv -Path $AuditCsv -NoTypeInformation -Encoding UTF8
    Write-Host "Exported audit file to: $AuditCsv" -ForegroundColor Cyan
}

# Summary
$summary = [pscustomobject]@{
    InputCount     = $input.Count
    FoundInAD      = ($results | Where-Object FoundInAD).Count
    NotFoundInAD   = ($results | Where-Object { -not $_.FoundInAD }).Count
    Matched        = ($results | Where-Object Match).Count
    Group1         = $Group1
    Group2         = $Group2
    MatchEither    = $MatchEither
    IncludeNested  = $IncludeNested
}
$summary | Format-List