# 本地三节点 mTLS 验证脚本（node-c 为「轮换中」节点）
#
# 用法： powershell -NoProfile -File scripts\run-3nodes-mtls.ps1
#
# 流程：
#   1. 构建 server/client/gencerts，生成全部证书物料
#   2. 起 3 个节点：node-a/node-b 用稳态 bundle（仅旧 CA），node-c 用轮换 bundle（旧+新 CA）
#   3. 正向：ping × 3、health、reflection
#   4. 负向：明文客户端、CN-only 证书客户端 —— 都必须被拒绝
#   5. 指标：查看 node-c 的 /metrics（CA bundle=2、过期倒计时）
#   6. 轮换演练：对 node-a 按「bundle → 叶子证书 → 收尾 bundle」顺序热替换文件，
#      期间 loop 客户端持续打流量，验证零失败；最后验证旧 CA 客户端被关在窗外
#   7. 清理进程
$ErrorActionPreference = "Continue"
$env:PATH = "C:\Program Files\Go\bin;$env:PATH"
$repo = Split-Path $PSScriptRoot -Parent
Set-Location $repo

function Fail($msg) { Write-Host "ASSERT FAILED: $msg" -ForegroundColor Red; exit 1 }
function Expect-Ok($exitCode, $what) {
    if ($exitCode -ne 0) { Fail "$what 本应成功但失败了" }
    Write-Host "  [OK] $what" -ForegroundColor Green
}
function Expect-Fail($exitCode, $what) {
    if ($exitCode -eq 0) { Fail "$what 本应被拒绝但成功了" }
    Write-Host "  [OK] $what （按预期被拒绝）" -ForegroundColor Green
}

Write-Host "== 1. build ==" -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path bin, logs | Out-Null
go build -o bin\server.exe ./cmd/server;   if ($LASTEXITCODE -ne 0) { Fail "build server" }
go build -o bin\client.exe ./cmd/client;   if ($LASTEXITCODE -ne 0) { Fail "build client" }
go build -o bin\gencerts.exe ./cmd/gencerts; if ($LASTEXITCODE -ne 0) { Fail "build gencerts" }

Write-Host "== 2. gencerts ==" -ForegroundColor Cyan
.\bin\gencerts.exe -out certs -days 30
if ($LASTEXITCODE -ne 0) { Fail "gencerts" }

# 每个节点一个 live 目录，模拟真实部署里 per-node 的 secret 挂载；
# 热加载就是替换这个目录里的文件。
$nodes = @("node-a", "node-b", "node-c")
$ports = @(50051, 50052, 50053)
$mports = @(9101, 9102, 9103)
foreach ($n in $nodes) {
    New-Item -ItemType Directory -Force -Path "certs\live\$n" | Out-Null
    Copy-Item "certs\server-$n.pem"     "certs\live\$n\cert.pem"
    Copy-Item "certs\server-$n-key.pem" "certs\live\$n\key.pem"
    Copy-Item "certs\bundle-old.pem"    "certs\live\$n\ca.pem"
}
# node-c 是「轮换中」节点：CA bundle 同时信任旧+新 CA
Copy-Item "certs\bundle-rotation.pem" "certs\live\node-c\ca.pem" -Force

# loop 客户端也有自己的 live 目录：轮换演练中它的证书同样要热轮换
New-Item -ItemType Directory -Force -Path "certs\live\client" | Out-Null
Copy-Item "certs\client.pem"           "certs\live\client\cert.pem"
Copy-Item "certs\client-key.pem"       "certs\live\client\key.pem"
Copy-Item "certs\bundle-rotation.pem"  "certs\live\client\ca.pem"

Write-Host "== 3. start nodes (node-c = rotating) ==" -ForegroundColor Cyan
$procs = @()
for ($i = 0; $i -lt $nodes.Count; $i++) {
    $n = $nodes[$i]
    $p = Start-Process -FilePath ".\bin\server.exe" `
        -ArgumentList "-addr","127.0.0.1:$($ports[$i])","-node",$n, `
                      "-metrics-addr","127.0.0.1:$($mports[$i])", `
                      "-cert","certs\live\$n\cert.pem","-key","certs\live\$n\key.pem", `
                      "-ca","certs\live\$n\ca.pem" `
        -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput "logs\$n.out.log" -RedirectStandardError "logs\$n.err.log"
    $procs += $p
    Write-Host ("  started {0} grpc={1} metrics={2} pid={3}" -f $n, $ports[$i], $mports[$i], $p.Id)
}
Start-Sleep -Seconds 3

try {
    Write-Host "== 4. positive: ping / health / reflection ==" -ForegroundColor Cyan
    foreach ($port in $ports) {
        .\bin\client.exe -target "127.0.0.1:$port" -msg "hello-$port" -ca certs\bundle-old.pem 2>&1 | Out-Null
        Expect-Ok $LASTEXITCODE "ping :$port (mTLS, 旧 CA 客户端)"
    }
    .\bin\client.exe -target 127.0.0.1:50051 -mode health 2>&1 | Out-Null
    Expect-Ok $LASTEXITCODE "health check over mTLS"
    .\bin\client.exe -target 127.0.0.1:50051 -mode reflect 2>&1 | Out-Null
    Expect-Ok $LASTEXITCODE "reflection over mTLS"

    Write-Host "== 5. negative: 必须被拒绝 ==" -ForegroundColor Cyan
    .\bin\client.exe -target 127.0.0.1:50051 -insecure 2>&1 | Out-Null
    Expect-Fail $LASTEXITCODE "明文客户端"
    .\bin\client.exe -target 127.0.0.1:50051 -cert certs\client-cn-only.pem -key certs\client-cn-only-key.pem 2>&1 | Out-Null
    Expect-Fail $LASTEXITCODE "CN-only 证书（无 SAN）"

    Write-Host "== 6. metrics: node-c（轮换中） ==" -ForegroundColor Cyan
    $m = (Invoke-WebRequest -UseBasicParsing http://127.0.0.1:9103/metrics).Content
    $m -split "`n" | Where-Object { $_ -match "^mtls_" } | ForEach-Object { "  $_" }
    if ($m -notmatch 'mtls_ca_bundle_certs\{node="node-c"\} 2') { Fail "node-c 的 CA bundle 应为 2 张（轮换窗口）" }
    Write-Host "  [OK] node-c 同时信任旧+新 CA（bundle=2），证书过期倒计时在表" -ForegroundColor Green

    Write-Host "== 7. CA 轮换演练（node-a，热加载，不重启） ==" -ForegroundColor Cyan
    Write-Host "  顺序：① server 换入旧+新 bundle → ② server 换入新 CA 签的叶子证书"
    Write-Host "        → ③ client 换入新 CA 签的证书 → ④ server 换入仅新 CA bundle（关窗）"
    Write-Host "  期间 loop 客户端（每轮新建连接）持续打流量，期望零失败"

    $loop = Start-Process -FilePath ".\bin\client.exe" `
        -ArgumentList "-target","127.0.0.1:50051","-mode","loop","-duration","22s","-interval","300ms", `
                      "-cert","certs\live\client\cert.pem","-key","certs\live\client\key.pem", `
                      "-ca","certs\live\client\ca.pem" `
        -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput "logs\loop.out.log" -RedirectStandardError "logs\loop.err.log"

    Start-Sleep -Seconds 2
    Write-Host "  step 1: node-a 换入 bundle-rotation（旧+新 CA）"
    Copy-Item "certs\bundle-rotation.pem" "certs\live\node-a\ca.pem" -Force
    Start-Sleep -Seconds 4   # reload-interval=2s，留足一次轮询

    Write-Host "  step 2: node-a 换入新 CA 签发的 server 证书"
    Copy-Item "certs\server-node-a-new.pem"     "certs\live\node-a\cert.pem" -Force
    Copy-Item "certs\server-node-a-new-key.pem" "certs\live\node-a\key.pem" -Force
    Start-Sleep -Seconds 4

    Write-Host "  step 3: loop 客户端换入新 CA 签发的 client 证书（客户端同样热加载）"
    Copy-Item "certs\client-new.pem"     "certs\live\client\cert.pem" -Force
    Copy-Item "certs\client-new-key.pem" "certs\live\client\key.pem" -Force
    Start-Sleep -Seconds 4

    Write-Host "  step 4: node-a 换入 bundle-new（仅新 CA，关闭窗口）"
    Copy-Item "certs\bundle-new.pem" "certs\live\node-a\ca.pem" -Force
    Start-Sleep -Seconds 4

    Wait-Process -Id $loop.Id -Timeout 30 -ErrorAction SilentlyContinue
    $loopLog = Get-Content logs\loop.err.log
    $loopLog | Select-Object -Last 3 | ForEach-Object { "  $_" }
    if ($loopLog -match "loop done: (\d+) ok / 0 fail") {
        Write-Host "  [OK] 轮换全程 $($Matches[1]) 个请求零失败（正确顺序下窗口无缝）" -ForegroundColor Green
    } else {
        $loopLog | Select-Object -Last 10 | ForEach-Object { "  $_" }
        Fail "轮换期间出现了失败请求（顺序或热加载有问题）"
    }

    Write-Host "== 8. 窗口已关闭：旧 CA 客户端应被拒，新 CA 客户端应通过 ==" -ForegroundColor Cyan
    .\bin\client.exe -target 127.0.0.1:50051 -ca certs\bundle-old.pem 2>&1 | Out-Null
    Expect-Fail $LASTEXITCODE "旧 CA 客户端打已轮换的 node-a（客户端侧拒 server 证书）"
    # 这个方向让 server 侧稳定记录拒绝：客户端信任新 CA（能验过 server 证书），
    # 但持有的仍是旧 CA 签的客户端证书 → server 不再接受它
    # （Go 客户端发现证书不匹配 server 通告的 CA 列表时不出示证书，
    #   所以 server 侧记为 no_client_cert；其它语言栈直接出示则记 unknown_ca）
    .\bin\client.exe -target 127.0.0.1:50051 -ca certs\bundle-new.pem `
        -cert certs\client.pem -key certs\client-key.pem 2>&1 | Out-Null
    Expect-Fail $LASTEXITCODE "信任新 CA 但持旧 CA 客户端证书（server 拒绝）"
    .\bin\client.exe -target 127.0.0.1:50051 -ca certs\bundle-new.pem `
        -cert certs\client-new.pem -key certs\client-new-key.pem 2>&1 | Out-Null
    Expect-Ok $LASTEXITCODE "新 CA 客户端打已轮换的 node-a"

    Write-Host "== 9. metrics: node-a 轮换后 ==" -ForegroundColor Cyan
    $m = (Invoke-WebRequest -UseBasicParsing http://127.0.0.1:9101/metrics).Content
    $m -split "`n" | Where-Object { $_ -match "^mtls_" } | ForEach-Object { "  $_" }
    if ($m -notmatch 'mtls_cert_reload_total\{node="node-a",result="ok"\} [3-9]') { Fail "node-a 应有 >=3 次成功热加载" }
    if ($m -notmatch 'reason="no_client_cert"') { Fail "node-a 应记录到关窗后旧证书客户端的握手失败" }
    Write-Host "  [OK] 热加载次数、握手失败分类、过期倒计时均已入表" -ForegroundColor Green

    Write-Host ""
    Write-Host "ALL CHECKS PASSED" -ForegroundColor Green
}
finally {
    Write-Host "== cleanup ==" -ForegroundColor Cyan
    foreach ($p in $procs) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    Get-Process -Name server -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}
