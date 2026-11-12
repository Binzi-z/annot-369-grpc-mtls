// echo-client：mTLS 客户端 + 验证工具。
//
// 模式（-mode）：
//
//	ping     发一条 echo.Echo/Ping（默认）
//	health   调 grpc.health.v1.Health/Check，验证健康检查在 mTLS 下可用
//	reflect  走 server reflection 列出服务，验证 reflection 在 mTLS 下可用
//	loop     按 -interval 持续 ping -duration，统计成功/失败（轮换演练用）
//
// -insecure 退回明文，仅用于「明文客户端应被拒绝」的负向测试。
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	rpb "google.golang.org/grpc/reflection/grpc_reflection_v1"

	"annot-grpc-mtls/internal/api"
	"annot-grpc-mtls/internal/config"
	"annot-grpc-mtls/internal/mtls"
)

var (
	target = config.String("target", "TARGET", "127.0.0.1:50051", "server address")
	msg    = config.String("msg", "MSG", "hello", "message to send")
	mode   = config.String("mode", "MODE", "ping", "ping|health|reflect|loop")

	certFile = config.String("cert", "CERT", "certs/client.pem", "client certificate (PEM)")
	keyFile  = config.String("key", "KEY", "certs/client-key.pem", "client private key (PEM)")
	caFile   = config.String("ca", "CA", "certs/bundle-old.pem", "server CA bundle (PEM)")

	serverName = config.String("server-name", "SERVER_NAME", "localhost", "expected server SAN (TLS server name)")
	plain      = flag.Bool("insecure", false, "plaintext connection (negative test only)")
	duration   = config.Duration("duration", "DURATION", 10*time.Second, "loop mode total duration")
	interval   = config.Duration("interval", "INTERVAL", 200*time.Millisecond, "loop mode ping interval")
)

func main() {
	flag.Parse()
	api.RegisterCodec()

	conn, err := dial()
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	switch *mode {
	case "ping":
		err = doPing(conn, *msg)
	case "health":
		err = doHealth(conn)
	case "reflect":
		err = doReflect(conn)
	case "loop":
		err = doLoop()
	default:
		err = fmt.Errorf("unknown mode %q", *mode)
	}
	if err != nil {
		log.Printf("FAILED: %v", err)
		os.Exit(1)
	}
}

// dial 建一条连接。loop 模式每次调用都新建连接，直接暴露握手层的变化。
//
// 注意：不给整条连接强制 JSON subtype —— health/reflection 是 proto 消息，
// 全局强制 JSON 会让它们解码失败。JSON codec 只在 echo 调用上按次指定。
func dial() (*grpc.ClientConn, error) {
	if *plain {
		return grpc.NewClient(*target,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
	}
	metrics := mtls.NewMetrics("client")
	creds, err := mtls.NewClient("client", *certFile, *keyFile, *caFile, nil, 2*time.Second, metrics)
	if err != nil {
		return nil, fmt.Errorf("load certs: %w", err)
	}
	return grpc.NewClient(*target,
		grpc.WithTransportCredentials(creds),
	)
}

func doPing(conn *grpc.ClientConn, m string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var resp api.PingResponse
	if err := conn.Invoke(ctx, api.FullMethod, &api.PingRequest{Msg: m}, &resp,
		grpc.CallContentSubtype("json")); err != nil {
		return err
	}
	log.Printf("response: msg=%q node=%q", resp.Msg, resp.Node)
	return nil
}

func doHealth(conn *grpc.ClientConn) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		return err
	}
	log.Printf("health: %s", resp.Status)
	if resp.Status != healthpb.HealthCheckResponse_SERVING {
		return fmt.Errorf("unexpected status %s", resp.Status)
	}
	return nil
}

func doReflect(conn *grpc.ClientConn) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := rpb.NewServerReflectionClient(conn).ServerReflectionInfo(ctx)
	if err != nil {
		return err
	}
	if err := stream.Send(&rpb.ServerReflectionRequest{
		MessageRequest: &rpb.ServerReflectionRequest_ListServices{ListServices: "*"},
	}); err != nil {
		return err
	}
	resp, err := stream.Recv()
	if err != nil {
		return err
	}
	log.Printf("reflection: services visible over mTLS:")
	for _, s := range resp.GetListServicesResponse().Service {
		log.Printf("  - %s", s.Name)
	}
	return nil
}

// doLoop 持续 ping 并统计成败。每轮新建连接，让每次都走完整 TLS 握手，
// 这样轮换演练时能直接观察到「哪一刻的新连接会失败、是否自愈」。
func doLoop() error {
	deadline := time.Now().Add(*duration)
	var ok, fail int
	for time.Now().Before(deadline) {
		conn, err := dial()
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			var resp api.PingResponse
			err = conn.Invoke(ctx, api.FullMethod, &api.PingRequest{Msg: "tick"}, &resp,
				grpc.CallContentSubtype("json"))
			cancel()
			_ = conn.Close()
		}
		if err != nil {
			fail++
			log.Printf("loop: FAIL (%d ok / %d fail): %v", ok, fail, err)
		} else {
			ok++
			log.Printf("loop: ok   (%d ok / %d fail)", ok, fail)
		}
		time.Sleep(*interval)
	}
	log.Printf("loop done: %d ok / %d fail", ok, fail)
	if fail > 0 {
		return fmt.Errorf("%d requests failed", fail)
	}
	return nil
}
