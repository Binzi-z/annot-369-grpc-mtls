// echo-server：mTLS gRPC 服务。
//
// 相对基线的变化：
//   - 双向 TLS：客户端必须持 CA 签发的证书，server 也出证书；
//   - 服务身份只认 SAN（CN-only 证书拒绝加载/拒绝握手）；
//   - 证书与 CA bundle 热加载（轮询文件，默认 2s），不重启进程；
//   - /metrics 暴露握手失败、证书过期倒计时、CA bundle 数量；
//   - health 与 reflection 照旧注册（走同一条 mTLS 通道，契约不变）。
//
// 配置双来源：flag 优先，缺省读 ECHO_* 环境变量。
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	"annot-grpc-mtls/internal/api"
	"annot-grpc-mtls/internal/config"
	"annot-grpc-mtls/internal/mtls"
)

var (
	addr        = config.String("addr", "ADDR", "127.0.0.1:50051", "listen address")
	nodeID      = config.String("node", "NODE", "node-a", "node id reported in responses")
	metricsAddr = config.String("metrics-addr", "METRICS_ADDR", "127.0.0.1:9100", "metrics http listen address")

	certFile = config.String("cert", "CERT", "certs/server.pem", "server certificate (PEM)")
	keyFile  = config.String("key", "KEY", "certs/server-key.pem", "server private key (PEM)")
	caFile   = config.String("ca", "CA", "certs/bundle-old.pem", "client CA bundle (PEM, may contain old+new CA during rotation)")

	allowedSANs = config.String("allowed-client-sans", "ALLOWED_CLIENT_SANS", "",
		"comma-separated client SAN allowlist (URI/DNS); empty = any SAN from a trusted CA")
	reloadInterval = config.Duration("reload-interval", "RELOAD_INTERVAL", 2*time.Second, "cert file poll interval, e.g. 2s")
)

type echoServer struct{ node string }

func (s *echoServer) Ping(ctx context.Context, in *api.PingRequest) (*api.PingResponse, error) {
	return &api.PingResponse{Msg: "pong:" + in.Msg, Node: s.node}, nil
}

func main() {
	flag.Parse()
	api.RegisterCodec()

	metrics := mtls.NewMetrics(*nodeID)

	var allow []string
	if *allowedSANs != "" {
		allow = strings.Split(*allowedSANs, ",")
	}
	creds, err := mtls.NewServer(*nodeID, *certFile, *keyFile, *caFile, allow, *reloadInterval, metrics)
	if err != nil {
		log.Fatalf("[%s] load certs: %v", *nodeID, err)
	}
	defer creds.Close()

	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	s := grpc.NewServer(grpc.Creds(creds))
	s.RegisterService(api.ServiceDesc(), &echoServer{node: *nodeID})

	// health 与 reflection 是普通 gRPC 服务，注册在同一条 mTLS 通道上：
	// 传输层加密+双向认证对它们透明，契约不变（探活方同样需要证书，见 README）。
	hs := health.NewServer()
	hs.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(s, hs)
	reflection.Register(s)

	// 指标端点（明文 HTTP，仅回环/内网；不暴露业务数据）
	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", metrics.Handler())
		if err := http.ListenAndServe(*metricsAddr, mux); err != nil {
			log.Printf("[%s] metrics http stopped: %v", *nodeID, err)
		}
	}()

	log.Printf("[%s] mTLS gRPC listening on %s (metrics on %s/metrics)", *nodeID, *addr, *metricsAddr)
	if err := s.Serve(lis); err != nil {
		log.Printf("serve stopped: %v", err)
		os.Exit(1)
	}
}
