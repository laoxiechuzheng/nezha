package rpc

import (
	"context"
	"fmt"
	"log"
	"net/netip"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/pkg/utils"
	"github.com/nezhahq/nezha/service/singleton"
)

// ctxWithRealIP stores the TCP peer (CtxKeyConnectingIP) and the address the
// WAF keys on (CtxKeyRealIP): the peer, or agent_real_ip_header when the peer
// is a trusted proxy. The WAF itself is applied in authHandler.check, after
// credentials are evaluated, so bans only ever come from gRPC auth failures.
func ctxWithRealIP(ctx context.Context) (context.Context, error) {
	var connectingIp string
	var peerAddr netip.Addr
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		if addr, ok := utils.ParseRemoteAddr(p.Addr.String()); ok {
			peerAddr = addr
			connectingIp = addr.String()
		}
	}
	ctx = context.WithValue(ctx, model.CtxKeyConnectingIP{}, connectingIp)

	header := singleton.Conf.AgentRealIPHeader
	if header == model.ConfigUsePeerIP {
		header = ""
	}
	var vals []string
	if header != "" {
		vals = metadata.ValueFromIncomingContext(ctx, header)
	}
	addr, ok := utils.ResolveClientIP(peerAddr, header, vals, singleton.Conf.TrustedProxyPrefixes())
	if !ok {
		return ctx, fmt.Errorf("connecting ip not found")
	}
	ip := addr.String()

	if singleton.Conf.Debug {
		log.Printf("NEZHA>> gRPC Agent Real IP: %s, connecting IP: %s\n", ip, connectingIp)
	}

	return context.WithValue(ctx, model.CtxKeyRealIP{}, ip), nil
}

func getRealIp(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	ctx, err := ctxWithRealIP(ctx)
	if err != nil {
		return nil, err
	}
	return handler(ctx, req)
}

type realIPServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *realIPServerStream) Context() context.Context { return s.ctx }

func getRealIpStream(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	ctx, err := ctxWithRealIP(ss.Context())
	if err != nil {
		return err
	}
	return handler(srv, &realIPServerStream{ServerStream: ss, ctx: ctx})
}
