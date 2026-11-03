package rpc

import (
	"net"

	"google.golang.org/grpc"

	"github.com/nezhahq/nezha/proto"
	rpcService "github.com/nezhahq/nezha/service/rpc"
	"github.com/nezhahq/nezha/service/singleton"
)

func SetReceiptGateListener(listener net.Listener) {
	rpcService.SetReceiptGateListener(listener)
}

func CloseReceiptGate() {
	rpcService.CloseReceiptGate()
}

// SetMCPKillSwitchObserver re-exports the service/rpc hook so cmd/dashboard
// can wire singleton.Conf.EnableMCP without importing the inner rpc package
// (cmd/dashboard already imports cmd/dashboard/rpc for ServeRPC).
func SetMCPKillSwitchObserver(fn func() bool) {
	rpcService.SetMCPKillSwitchObserver(fn)
}

func ServeRPC() *grpc.Server {
	// Streaming RPCs (RequestTask, IOStream) need the same real-IP resolution
	// as unary calls; without the stream interceptor authHandler.check sees
	// an empty real IP and brute-force BlockIP counters never key on a source.
	// The WAF gate lives in authHandler.check (every RPC authenticates first)
	// so it only consults gRPC-scope bans and, unless waf.grpc_strict_block is
	// set, never rejects an agent presenting valid credentials.
	server := grpc.NewServer(
		grpc.ChainUnaryInterceptor(getRealIp),
		grpc.ChainStreamInterceptor(getRealIpStream),
	)
	rpcService.NezhaHandlerSingleton = rpcService.NewNezhaHandler()
	// Install the IOStream revocation hook so ServerTransferShared can tear
	// down terminal/FM/NAT sessions held by the previous owner on every
	// ownership rotation (Register/revertTransition/OnServersDeleted).
	singleton.ServerTransferStreamRevocationHook = rpcService.NezhaHandlerSingleton.RevokeStreamsForServer
	proto.RegisterNezhaServiceServer(server, rpcService.NezhaHandlerSingleton)
	return server
}
