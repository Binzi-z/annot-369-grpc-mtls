// echo-client：明文连接（基线）。
//
// 现在：insecure 连接，不带任何证书。
// 预留：-cert/-key/-ca 参数，改造后用于 mTLS。
package main

import (
	"context"
	"flag"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"annot-grpc-mtls/internal/api"
)

var (
	target   = flag.String("target", "127.0.0.1:50051", "server address")
	msg      = flag.String("msg", "hello", "message to send")
	certFile = flag.String("cert", "", "client certificate (unused in baseline)")
	keyFile  = flag.String("key", "", "client key (unused in baseline)")
	caFile   = flag.String("ca", "", "CA bundle (unused in baseline)")
)

func main() {
	flag.Parse()
	api.RegisterCodec()

	conn, err := grpc.NewClient(*target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.CallContentSubtype("json")),
	)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var resp api.PingResponse
	if err := conn.Invoke(ctx, api.FullMethod, &api.PingRequest{Msg: *msg}, &resp); err != nil {
		log.Fatalf("invoke: %v", err)
	}
	log.Printf("response: msg=%q node=%q", resp.Msg, resp.Node)
}
