# grpc-echo (mTLS)

内部 echo 服务（Go + gRPC），**已上 mTLS**：双向证书校验、SAN 服务身份、证书/CA 热加载、
CA 轮换窗口、握手与证书过期指标。health 与 reflection 契约不变。

## 结构

```
cmd/server              gRPC 服务：echo.Echo/Ping、health、reflection、/metrics
cmd/client              客户端：ping / health / reflect / loop 四种模式
cmd/gencerts            生成 CA×2 + 各级 bundle + server/client 证书 + CN-only 负向证书
internal/api            消息体与 ServiceDesc（JSON codec，不依赖 protoc）
internal/mtls           热加载 TransportCredentials + Prometheus 文本指标
internal/config         环境变量(ECHO_*) + 命令行双来源配置
scripts/run-3nodes-mtls.ps1   三节点（含「轮换中」节点）全流程验证
deploy/mtls-alerts.yaml       Prometheus 告警规则
```

## 快速开始

```bash
go build ./...
go run ./cmd/gencerts -out certs -days 30     # 生成全部证书物料

# server（flag 优先，缺省读 ECHO_* 环境变量）
go run ./cmd/server -addr 127.0.0.1:50051 -node node-a \
    -cert certs/server-node-a.pem -key certs/server-node-a-key.pem -ca certs/bundle-old.pem

# client
go run ./cmd/client -target 127.0.0.1:50051 -msg hello
go run ./cmd/client -target 127.0.0.1:50051 -mode health    # 健康检查
go run ./cmd/client -target 127.0.0.1:50051 -mode reflect   # reflection 列服务
```

一键验证（构建 → 起 3 节点 → 正/负向用例 → 轮换演练 → 指标断言）：

```powershell
powershell -NoProfile -File scripts\run-3nodes-mtls.ps1
```

## 设计要点

### 双向校验与 SAN 身份

- server 要求客户端必须出证书且能过链验证（`RequireAndVerifyClientCert`），client 同样验 server。
- **身份只认 SAN**：握手成功后额外检查对端叶子证书必须带 SAN（DNS/IP/URI 任一），
  CN-only 证书直接拒连（指标记 `reason="san_rejected"`）；server 自己的 CN-only 证书连加载都不让。
  主机名验证走 crypto/tls 标准实现（Go ≥1.15 起 CN 本就不参与），这里再加一道显式防线。
- 可选 `-allowed-client-sans` 白名单（URI/DNS SAN），空 = 信任 CA 签出的任意带 SAN 证书。
- 证书里用 URI SAN 做 SPIFFE 风格身份：`spiffe://annot/node/<node>`、`spiffe://annot/client`。

### 热加载（不重启进程）

- `internal/mtls.Reloader` 每 `-reload-interval`（默认 2s）轮询 cert/key/ca 三个文件的
  mtime+size，变了就整体重载；**加载全成功才原子替换快照**，失败保留旧证书并记
  `mtls_cert_reload_total{result="error"}`。
- 每次握手用当前快照现造 `tls.Config`，链验证/主机名验证全部走标准库，
  不会出现「证书是新的、CA 还是旧的」的撕裂状态。
- 已建立的连接不受影响（TLS 握手只发生在建连时），热加载对存量长连接零打扰。

### CA 轮换窗口

`gencerts` 一次生成新旧两个 CA 和三档 bundle：

| 文件 | 内容 | 用途 |
|---|---|---|
| `bundle-old.pem` | 仅旧 CA | 稳态（轮换前） |
| `bundle-rotation.pem` | 旧+新 CA | **轮换窗口**，全集群分发 |
| `bundle-new.pem` | 仅新 CA | 稳态（轮换后） |

轮换顺序（脚本第 7 步完整演示，全程零失败）：

1. 全集群 CA bundle 换成 `bundle-rotation`（旧+新都信）——此时任何人还没换证书，无影响；
2. 各节点换入新 CA 签发的叶子证书——对端 bundle 里有新 CA，照样认；
3. 客户端同样换入新 CA 签发的证书；
4. 全集群 bundle 换成 `bundle-new`，关闭窗口——旧 CA 签的证书从此被拒。

窗口是否开着可以用指标直接看：`mtls_ca_bundle_certs == 2` 即窗口打开中。

### 指标与告警

server 在 `-metrics-addr`（默认 `127.0.0.1:9100`）暴露 `/metrics`（Prometheus 文本格式）：

| 指标 | 类型 | 说明 |
|---|---|---|
| `mtls_handshake_failures_total{node,side,reason}` | counter | 握手失败；reason ∈ `unknown_ca / expired / no_client_cert / plaintext / san_rejected / other` |
| `mtls_cert_expiry_seconds{node,cert}` | gauge | 叶子证书过期倒计时（秒） |
| `mtls_cert_reload_total{node,result}` | counter | 热加载成功/失败次数 |
| `mtls_ca_bundle_certs{node}` | gauge | 当前 CA bundle 里 CA 数量（窗口期=2） |

告警规则见 `deploy/mtls-alerts.yaml`：握手失败速率、证书 7 天/24h 过期、
热加载连续失败、轮换窗口超 24h 未收尾。

### reflection 与 health check

两者是普通 gRPC 服务，跑在同一条 mTLS 通道上，**契约不变**——但探活/调试方现在也
必须持证书（这正是目的：未授权方连 health 都不该能调）。`cmd/client -mode health|reflect`
即是带证书的探活示例；grpcurl 等价用法：`grpcurl -cert client.pem -key client-key.pem -cacert bundle-old.pem ...`。

## 轮换期间哪类请求会短暂失败、为何可接受

**已建立的连接：不失败。** TLS 握手只发生在建连时，换证书、换 bundle 都不碰存量
HTTP/2 连接，长连接上的在途请求无感。

**新建连接：只有「顺序错了」或「窗口外」才会失败，且都可自愈：**

1. **窗口内按正确顺序操作 → 零失败**（脚本第 7 步实测 72/72 成功）。bundle 里旧+新 CA
   并存期间，无论对端出示新证书还是旧证书都能验过。
2. **热加载轮询间隙（最长一个 `-reload-interval`，默认 2s）**：如果客户端先换了新 CA
   证书、而 server 还没轮询到新 bundle，这几秒内的新建连会失败一次，客户端重试即成功。
   可接受原因：gRPC 客户端对 `Unavailable` 有内建重试/退避，调用方通常无感；
   且窗口期任意时刻只会有一个方向短暂错位，不会出现双向同时不通。
3. **窗口关闭后仍持旧 CA 证书的连接 → 持续失败，这是设计意图**（安全语义：旧 CA 不再
   受信），指标里体现为 `no_client_cert`/`unknown_ca` 上涨，告警据此提示还有节点没换完。

简言之：**失败的只有「新建连接的 TLS 握手」这一类，且仅限于操作顺序错位或轮询间隙的
几秒窗口；存量连接与窗口内的正常流量不受影响，失败均可由客户端重试自愈。**

## 配置双来源

所有参数都是「flag > 环境变量 > 默认值」，环境变量统一 `ECHO_` 前缀：

| flag | 环境变量 | 默认 |
|---|---|---|
| `-addr` | `ECHO_ADDR` | `127.0.0.1:50051` |
| `-node` | `ECHO_NODE` | `node-a` |
| `-metrics-addr` | `ECHO_METRICS_ADDR` | `127.0.0.1:9100` |
| `-cert` / `-key` / `-ca` | `ECHO_CERT` / `ECHO_KEY` / `ECHO_CA` | `certs/...` |
| `-allowed-client-sans` | `ECHO_ALLOWED_CLIENT_SANS` | 空（不限制） |
| `-reload-interval` | `ECHO_RELOAD_INTERVAL` | `2s` |

## 约定

- 不提交 `certs/`、`bin/`、`*.pem`、`*.key`（见 `.gitignore`）；
- 保留 `echo.Echo/Ping`、health、reflection 三条对外契约。
