# Creates multiple files of 100MB each in the target folder
$TargetFolder = "C:\Windows\Temp\TestFiles"
$FileCount    = 750
$FileSizeMB   = 100

# Ensure folder exists
New-Item -ItemType Directory -Path $TargetFolder -Force | Out-Null

$bytes = $FileSizeMB * 1MB

1..$FileCount | ForEach-Object {
    $filePath = Join-Path $TargetFolder ("File_{0:D3}.bin" -f $_)

    $fs = [System.IO.File]::Open($filePath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $fs.SetLength($bytes)
    }
    finally {
        $fs.Close()
    }
}

Write-Host "Created $FileCount files of $FileSizeMB MB in $TargetFolder"