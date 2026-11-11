// Package api 定义 echo 服务的请求/响应与 grpc 服务描述。
//
// 为了不依赖 protoc，这里用 JSON 作为传输编码（自定义 codec），
// 服务描述手写在 ServiceDesc 里。
package api

import (
	"context"
	"encoding/json"

	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding"
)

// ServiceName 与 MethodName 是客户端调用时使用的全名。
const (
	ServiceName = "echo.Echo"
	MethodPing  = "Ping"
	FullMethod  = "/" + ServiceName + "/" + MethodPing
)

// PingRequest / PingResponse 是 JSON 编解码的消息体。
type PingRequest struct {
	Msg string `json:"msg"`
}

type PingResponse struct {
	Msg  string `json:"msg"`
	Node string `json:"node"`
}

// EchoServer 是服务端要实现的方法集。
type EchoServer interface {
	Ping(ctx context.Context, in *PingRequest) (*PingResponse, error)
}

// JSONCodec 让 grpc 用 JSON 而不是 protobuf 编解码。
type JSONCodec struct{}

func (JSONCodec) Name() string { return "json" }

func (JSONCodec) Marshal(v any) ([]byte, error) { return json.Marshal(v) }

func (JSONCodec) Unmarshal(data []byte, v any) error { return json.Unmarshal(data, v) }

// RegisterCodec 在进程内注册一次 JSON codec。
func RegisterCodec() { encoding.RegisterCodec(JSONCodec{}) }

// ServiceDesc 描述 echo 服务（无流式方法）。
func ServiceDesc() *grpc.ServiceDesc {
	handler := func(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
		in := new(PingRequest)
		if err := dec(in); err != nil {
			return nil, err
		}
		s := srv.(EchoServer)
		if interceptor == nil {
			return s.Ping(ctx, in)
		}
		info := &grpc.UnaryServerInfo{Server: srv, FullMethod: FullMethod}
		return interceptor(ctx, in, info, func(ctx context.Context, req any) (any, error) {
			return s.Ping(ctx, req.(*PingRequest))
		})
	}
	return &grpc.ServiceDesc{
		ServiceName: ServiceName,
		HandlerType: (*EchoServer)(nil),
		Methods: []grpc.MethodDesc{
			{MethodName: MethodPing, Handler: handler},
		},
		Streams:  []grpc.StreamDesc{},
		Metadata: "echo.json",
	}
}
