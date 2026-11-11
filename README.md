# grpc-echo

内部 echo 服务（Go + gRPC）。**当前是明文通信**：不加密、不校验客户端身份。

## 结构

```
cmd/server       gRPC 服务：echo.Echo/Ping、health、reflection
cmd/client       客户端：连上去发一条 ping
cmd/gencerts     生成 CA + server/client 证书（改造阶段用）
internal/api     消息体与 ServiceDesc（用 JSON codec，不依赖 protoc）
scripts/run-3nodes.ps1   起 3 个节点并打一遍
```

## 运行

```bash
go build ./...

# 生成证书（基线不读，改造时用）
go run ./cmd/gencerts -out certs -days 30

# 起服务
go run ./cmd/server -addr 127.0.0.1:50051 -node node-a

# 客户端
go run ./cmd/client -target 127.0.0.1:50051 -msg hello
# → response: msg="pong:hello" node="node-a"
```

## 现状（要解决的）

- 全程 `insecure`，抓包可见明文；
- 服务端不验证客户端身份，任何人连上来都能调用；
- 没有 SAN 校验（现在连证书都没有）；
- 证书不热加载，`-cert/-key/-ca` 参数只是占位；
- 没有 CA 轮换能力，也没有握手/过期相关指标。

## 约定

- 不提交 `certs/`、`*.pem`、`*.key`；
- 保留 `echo.Echo/Ping`、health、reflection 三条对外契约；
- 配置支持环境变量（`GREET_ADDR` 等可自行增加）与命令行双来源。
