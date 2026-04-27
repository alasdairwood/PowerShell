# List sizes for each folder under C:\Users (excluding junctions/reparse points)
$root = 'C:\Users'

Get-ChildItem -Path $root -Directory -Force |
Where-Object {
    $_.Name -notin @('Public','Default','Default User','All Users','defaultuser0') -and
    ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0
} |
ForEach-Object {
    $path = $_.FullName

    $bytes = (Get-ChildItem -Path $path -Recurse -Force -File -ErrorAction SilentlyContinue |
              Measure-Object -Property Length -Sum).Sum

    [pscustomobject]@{
        Profile = $_.Name
        Path    = $path
        SizeGB  = [math]::Round(($bytes / 1GB), 2)
        SizeMB  = [math]::Round(($bytes / 1MB), 0)
    }
} |
Sort-Object SizeGB -Descending |
Format-Table -AutoSize