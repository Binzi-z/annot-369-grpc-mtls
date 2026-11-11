// echo-server：明文 gRPC 服务（基线）。
//
// 现在：不加密、不校验客户端身份、证书一概没有。
// 已经具备：health 服务、reflection 服务、可配置监听地址。
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	"annot-grpc-mtls/internal/api"
)

var (
	addr    = flag.String("addr", "127.0.0.1:50051", "listen address")
	nodeID  = flag.String("node", "node-a", "node id reported in responses")
        // 证书相关参数为改造预留，基线不读取
	certFile = flag.String("cert", "", "server certificate (unused in baseline)")
	keyFile  = flag.String("key", "", "server key (unused in baseline)")
	caFile   = flag.String("ca", "", "client CA bundle (unused in baseline)")
)

type echoServer struct{ node string }

func (s *echoServer) Ping(ctx context.Context, in *api.PingRequest) (*api.PingResponse, error) {
	return &api.PingResponse{Msg: "pong:" + in.Msg, Node: s.node}, nil
}

func main() {
	flag.Parse()
	api.RegisterCodec()

	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	s := grpc.NewServer()
	s.RegisterService(api.ServiceDesc(), &echoServer{node: *nodeID})

	hs := health.NewServer()
	hs.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(s, hs)

	reflection.Register(s)

	log.Printf("[%s] plaintext gRPC listening on %s", *nodeID, *addr)
	if err := s.Serve(lis); err != nil {
		log.Printf("serve stopped: %v", err)
		os.Exit(1)
	}
}
