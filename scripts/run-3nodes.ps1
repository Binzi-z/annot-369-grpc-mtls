# 本地三节点演练：起 3 个 server，打一遍 client，然后收掉
# 用法： powershell -NoProfile -File scripts\run-3nodes.ps1
$ErrorActionPreference = "Continue"
$env:PATH = "C:\Program Files\Go\bin;$env:PATH"
$repo = Split-Path $PSScriptRoot -Parent
Set-Location $repo

Write-Host "== build ==" -ForegroundColor Cyan
go build ./...
if ($LASTEXITCODE -ne 0) { Write-Host "build failed"; exit 1 }

$ports = @(50051, 50052, 50053)
$nodes = @("node-a", "node-b", "node-c")
$procs = @()

for ($i = 0; $i -lt $ports.Count; $i++) {
    $p = Start-Process -FilePath "go" `
        -ArgumentList "run", "./cmd/server", "-addr", "127.0.0.1:$($ports[$i])", "-node", $nodes[$i] `
        -PassThru -WindowStyle Hidden
    $procs += $p
    Write-Host ("started {0} on {1} (pid {2})" -f $nodes[$i], $ports[$i], $p.Id)
}

Start-Sleep -Seconds 8

foreach ($port in $ports) {
    Write-Host "== ping 127.0.0.1:$port ==" -ForegroundColor Cyan
    go run ./cmd/client -target "127.0.0.1:$port" -msg "hello-$port" 2>&1 | Select-Object -Last 2
}

Write-Host "== cleanup ==" -ForegroundColor Cyan
foreach ($p in $procs) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
Get-Process -Name server -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Write-Host "done"
