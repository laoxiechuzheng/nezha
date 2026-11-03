package rpc

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/service/singleton"
)

func withWAFConfig(t *testing.T, c model.WAFConfig) {
	t.Helper()
	prev := model.CurrentWAFConfig()
	model.SetWAFConfig(c)
	t.Cleanup(func() { model.SetWAFConfig(prev) })
}

// The incident: an attacker brute-forced the web login through the owner's
// own proxy nodes, whose egress IPs also run nezha-agent. The resulting web
// ban must not take those agents offline.
func TestAuthWebBanDoesNotBlockAgentOnSameIP(t *testing.T) {
	defer setupAuthHandshakeFixture(t)()
	withWAFConfig(t, model.WAFConfig{})
	const nodeIP = "198.51.100.40"

	for range 10 {
		if err := model.BlockIP(singleton.DB, nodeIP, model.WAFBlockReasonTypeLoginFail, 1); err != nil {
			t.Fatal(err)
		}
	}
	if err := model.CheckIP(singleton.DB, nodeIP, model.WAFScopeWeb); err == nil {
		t.Fatal("precondition: node IP must be banned for web")
	}

	cid, err := authCheckFromIP("alice-global", authHandshakeUUID, nodeIP)
	if err != nil || cid != 11 {
		t.Fatalf("agent with valid secret on a web-banned IP must authenticate, got cid=%d err=%v", cid, err)
	}
	if err := model.CheckIP(singleton.DB, nodeIP, model.WAFScopeWeb); err == nil {
		t.Fatal("a successful agent auth must not lift the web ban")
	}
}

// Even a gRPC-scope ban (someone sending bad agent secrets from the shared
// egress IP) must not lock out the real agent on that IP by default.
func TestAuthGRPCBanAdmitsValidAgentByDefault(t *testing.T) {
	defer setupAuthHandshakeFixture(t)()
	withWAFConfig(t, model.WAFConfig{})
	const nodeIP = "198.51.100.41"

	for range 3 {
		if _, err := authCheckFromIP("wrong-secret", authHandshakeUUID, nodeIP); err == nil {
			t.Fatal("bad secret must fail")
		}
	}
	if got := wafAgentAuthFailCount(t, nodeIP); got == 0 {
		t.Fatal("precondition: failures must be counted")
	}

	cid, err := authCheckFromIP("alice-global", authHandshakeUUID, nodeIP)
	if err != nil || cid != 11 {
		t.Fatalf("valid agent must authenticate despite a gRPC ban, got cid=%d err=%v", cid, err)
	}
	if got := wafAgentAuthFailCount(t, nodeIP); got != 0 {
		t.Fatalf("successful auth must clear the gRPC counter, got %d", got)
	}
}

// A banned address that keeps presenting bad credentials is told it is
// banned and is not counted again (same as the web WAF, which rejects before
// the handler runs).
func TestAuthBannedBadSecretGetsPermissionDeniedWithoutRecount(t *testing.T) {
	defer setupAuthHandshakeFixture(t)()
	withWAFConfig(t, model.WAFConfig{})
	const attackerIP = "203.0.113.42"

	if _, err := authCheckFromIP("wrong-secret", authHandshakeUUID, attackerIP); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("first failure must be Unauthenticated, got %v", err)
	}
	before := wafAgentAuthFailCount(t, attackerIP)

	_, err := authCheckFromIP("wrong-secret-2", authHandshakeUUID, attackerIP)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("banned address must get PermissionDenied, got %v", err)
	}
	if got := wafAgentAuthFailCount(t, attackerIP); got != before {
		t.Fatalf("attempts while banned must not escalate the counter: %d -> %d", before, got)
	}
}

func TestAuthGRPCStrictBlockRejectsValidAgent(t *testing.T) {
	defer setupAuthHandshakeFixture(t)()
	withWAFConfig(t, model.WAFConfig{GRPCStrictBlock: true})
	const ip = "198.51.100.43"

	if err := model.BlockIP(singleton.DB, ip, model.WAFBlockReasonTypeAgentAuthFail, model.BlockIDgRPC); err != nil {
		t.Fatal(err)
	}
	if _, err := authCheckFromIP("alice-global", authHandshakeUUID, ip); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("grpc_strict_block must reject even valid agents while banned, got %v", err)
	}

	// Strict mode still only looks at the gRPC scope.
	const webBanned = "198.51.100.44"
	if err := model.BlockIP(singleton.DB, webBanned, model.WAFBlockReasonTypeLoginFail, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := authCheckFromIP("alice-global", authHandshakeUUID, webBanned); err != nil {
		t.Fatalf("strict gRPC mode must ignore web bans unless shared_scope is set, got %v", err)
	}
}
