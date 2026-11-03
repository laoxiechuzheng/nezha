package rpc

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/service/singleton"
)

// peerCtx builds a context carrying a gRPC peer address the same way the
// real transport does, so ctxWithRealIP's peer.FromContext + netip parsing
// path is exercised end-to-end.
func peerCtx(addr string) context.Context {
	tcp, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		panic(err)
	}
	return peer.NewContext(context.Background(), &peer.Peer{Addr: tcp})
}

func withRealIPHeader(t *testing.T, header string) {
	t.Helper()
	conf := &model.Config{}
	conf.AgentRealIPHeader = header
	orig := singleton.Conf
	singleton.Conf = &singleton.ConfigClass{Config: conf}
	t.Cleanup(func() { singleton.Conf = orig })
}

// TestCtxWithRealIP_PeerIPModePopulatesRealIP pins the regression: in
// AgentRealIPHeader == ConfigUsePeerIP mode the resolved real IP must equal
// the connecting peer IP. If it stays empty, model.CheckIP / model.BlockIP
// short-circuit on "" and the gRPC WAF + brute-force blocking are bypassed.
func TestCtxWithRealIP_PeerIPModePopulatesRealIP(t *testing.T) {
	withRealIPHeader(t, model.ConfigUsePeerIP)

	ctx, err := ctxWithRealIP(peerCtx("203.0.113.7:54321"))
	if err != nil {
		t.Fatalf("ctxWithRealIP returned error: %v", err)
	}

	realIP, _ := ctx.Value(model.CtxKeyRealIP{}).(string)
	if realIP != "203.0.113.7" {
		t.Fatalf("CtxKeyRealIP = %q, want %q (empty defeats WAF/BlockIP)", realIP, "203.0.113.7")
	}

	connIP, _ := ctx.Value(model.CtxKeyConnectingIP{}).(string)
	if connIP != "203.0.113.7" {
		t.Fatalf("CtxKeyConnectingIP = %q, want %q", connIP, "203.0.113.7")
	}
}

// TestCtxWithRealIP_PeerIPModeIPv6 confirms the port is stripped and the IPv6
// literal is normalized for the peer-IP path.
func TestCtxWithRealIP_PeerIPModeIPv6(t *testing.T) {
	withRealIPHeader(t, model.ConfigUsePeerIP)

	ctx, err := ctxWithRealIP(peerCtx("[2001:db8::1]:443"))
	if err != nil {
		t.Fatalf("ctxWithRealIP returned error: %v", err)
	}

	realIP, _ := ctx.Value(model.CtxKeyRealIP{}).(string)
	if realIP != "2001:db8::1" {
		t.Fatalf("CtxKeyRealIP = %q, want %q", realIP, "2001:db8::1")
	}
}

// TestCtxWithRealIP_PeerIPModeNoPeer keeps the documented failure behaviour
// when no connecting IP can be derived.
func TestCtxWithRealIP_PeerIPModeNoPeer(t *testing.T) {
	withRealIPHeader(t, model.ConfigUsePeerIP)

	_, err := ctxWithRealIP(context.Background())
	if err == nil {
		t.Fatal("expected error when connecting IP cannot be resolved in peer-IP mode")
	}
}

// TestCtxWithRealIP_NoHeaderUsesPeer pins the always-on WAF: with no real-IP
// header configured the WAF must still key on the TCP peer instead of
// silently skipping (an empty CtxKeyRealIP made CheckIP/BlockIP no-ops).
func TestCtxWithRealIP_NoHeaderUsesPeer(t *testing.T) {
	withRealIPHeader(t, "")

	ctx, err := ctxWithRealIP(peerCtx("203.0.113.7:54321"))
	if err != nil {
		t.Fatalf("no-header mode must not error, got %v", err)
	}

	realIP, _ := ctx.Value(model.CtxKeyRealIP{}).(string)
	if realIP != "203.0.113.7" {
		t.Fatalf("CtxKeyRealIP = %q, want the peer 203.0.113.7", realIP)
	}

	connIP, _ := ctx.Value(model.CtxKeyConnectingIP{}).(string)
	if connIP != "203.0.113.7" {
		t.Fatalf("CtxKeyConnectingIP = %q, want %q", connIP, "203.0.113.7")
	}
}

func withTrustedProxies(t *testing.T, header string, proxies ...string) {
	t.Helper()
	conf := &model.Config{}
	conf.AgentRealIPHeader = header
	if err := conf.SetTrustedProxies(proxies); err != nil {
		t.Fatalf("trusted proxies: %v", err)
	}
	orig := singleton.Conf
	singleton.Conf = &singleton.ConfigClass{Config: conf}
	t.Cleanup(func() { singleton.Conf = orig })
}

func headerPeerCtx(addr, header, value string) context.Context {
	return metadata.NewIncomingContext(peerCtx(addr), metadata.Pairs(header, value))
}

// An agent connecting directly cannot choose the address it is banned under.
func TestCtxWithRealIP_HeaderFromUntrustedPeerIgnored(t *testing.T) {
	withRealIPHeader(t, "x-real-ip")

	ctx, err := ctxWithRealIP(headerPeerCtx("203.0.113.7:54321", "x-real-ip", "198.51.100.1"))
	if err != nil {
		t.Fatal(err)
	}
	if realIP, _ := ctx.Value(model.CtxKeyRealIP{}).(string); realIP != "203.0.113.7" {
		t.Fatalf("CtxKeyRealIP = %q, want peer 203.0.113.7 (header from untrusted peer must be ignored)", realIP)
	}
}

// Header missing from a trusted proxy falls back to the peer instead of
// rejecting the RPC (the old behaviour returned "real ip header not found").
func TestCtxWithRealIP_TrustedPeerMissingHeaderFallsBack(t *testing.T) {
	withRealIPHeader(t, "x-real-ip")

	ctx, err := ctxWithRealIP(peerCtx("127.0.0.1:40000"))
	if err != nil {
		t.Fatal(err)
	}
	if realIP, _ := ctx.Value(model.CtxKeyRealIP{}).(string); realIP != "127.0.0.1" {
		t.Fatalf("CtxKeyRealIP = %q, want 127.0.0.1", realIP)
	}
}

func TestCtxWithRealIP_HeaderFromTrustedProxyHonoured(t *testing.T) {
	withTrustedProxies(t, "x-real-ip", "172.24.0.1/32")

	ctx, err := ctxWithRealIP(headerPeerCtx("172.24.0.1:40000", "x-real-ip", "198.51.100.1"))
	if err != nil {
		t.Fatal(err)
	}
	if realIP, _ := ctx.Value(model.CtxKeyRealIP{}).(string); realIP != "198.51.100.1" {
		t.Fatalf("CtxKeyRealIP = %q, want 198.51.100.1", realIP)
	}
	if connIP, _ := ctx.Value(model.CtxKeyConnectingIP{}).(string); connIP != "172.24.0.1" {
		t.Fatalf("CtxKeyConnectingIP = %q, want 172.24.0.1", connIP)
	}
}
