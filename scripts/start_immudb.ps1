# Start immudb server standalone
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir
$BinPath = Join-Path $RootDir "bin\immudb.exe"
$DataDir = Join-Path $RootDir "data\immudb"

if (-not (Test-Path $BinPath)) {
    Write-Error "immudb.exe not found at $BinPath"
    exit 1
}

Write-Host "Starting immudb server on port 3322..." -ForegroundColor Cyan
& $BinPath --dir $DataDir --pgsql-server=false --web-server=false --port 3322
