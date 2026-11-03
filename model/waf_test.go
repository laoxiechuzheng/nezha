package model

import (
	"errors"
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/nezhahq/nezha/pkg/utils"
)

func newWAFTestDB(t *testing.T, conf WAFConfig) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("db handle: %v", err)
	}
	sqlDB.SetMaxOpenConns(1) // one :memory: database for every query
	if err := db.AutoMigrate(&WAF{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	prev := CurrentWAFConfig()
	SetWAFConfig(conf)
	t.Cleanup(func() {
		SetWAFConfig(prev)
		_ = sqlDB.Close()
	})
	return db
}

// ageWAFRows moves every row of ip back in time so a ban can expire without
// sleeping.
func ageWAFRows(t *testing.T, db *gorm.DB, ip string, by time.Duration) {
	t.Helper()
	b, err := wafKeyBinary(ip)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("UPDATE nz_waf SET block_timestamp = block_timestamp - ? WHERE ip = ?", uint64(by.Seconds()), b).Error; err != nil {
		t.Fatal(err)
	}
}

func isBlocked(t *testing.T, db *gorm.DB, ip string, scope WAFScope) bool {
	t.Helper()
	err := CheckIP(db, ip, scope)
	if err != nil && !errors.Is(err, ErrWAFBlocked) {
		t.Fatalf("CheckIP(%s): unexpected error %v", ip, err)
	}
	return err != nil
}

func TestWAFStateDefaultsMatchUpstream(t *testing.T) {
	p := WAFConfig{}.policy(WAFScopeWeb)
	const ts = 1_000_000
	for count, want := range map[uint64]uint64{1: 3, 2: 16, 3: 81, 4: 256, 10: 10000} {
		until, permanent, stale := wafState([]WAF{{BlockIdentifier: 1, BlockTimestamp: ts, Count: count}}, ts, p)
		if permanent || stale || until != ts+want {
			t.Fatalf("count=%d: until=%d permanent=%v stale=%v, want ts+%d", count, until, permanent, stale, want)
		}
	}
	// Counters of every identifier in scope add up, latest timestamp wins.
	until, _, _ := wafState([]WAF{
		{BlockIdentifier: 1, BlockTimestamp: ts - 50, Count: 2},
		{BlockIdentifier: BlockIDUnknownUser, BlockTimestamp: ts, Count: 1},
	}, ts, p)
	if until != ts+81 {
		t.Fatalf("aggregate until=%d, want ts+81", until)
	}
	// Huge counters saturate instead of wrapping into an unblock.
	until, _, _ = wafState([]WAF{{BlockIdentifier: 1, BlockTimestamp: ts, Count: 1 << 40}}, ts, p)
	if until != ^uint64(0) {
		t.Fatalf("overflow until=%d, want max uint64", until)
	}
}

func TestWAFStateThresholdCapAndReset(t *testing.T) {
	p := WAFConfig{Web: WAFPolicy{
		FailThreshold:     5,
		BlockExponent:     2,
		MinBlockSeconds:   60,
		MaxBlockSeconds:   3600,
		ResetAfterSeconds: 600,
	}}.policy(WAFScopeWeb)
	const ts = 1_000_000
	row := func(count uint64) []WAF { return []WAF{{BlockIdentifier: 1, BlockTimestamp: ts, Count: count}} }

	if until, _, _ := wafState(row(4), ts, p); until != 0 {
		t.Fatalf("below threshold must not ban, until=%d", until)
	}
	if until, _, _ := wafState(row(5), ts, p); until != ts+60 {
		t.Fatalf("threshold hit: until=%d want ts+60 (min)", until)
	}
	if until, _, _ := wafState(row(14), ts, p); until != ts+100 {
		t.Fatalf("escalation: until=%d want ts+(14-5+1)^2=ts+100", until)
	}
	if until, _, _ := wafState(row(1000), ts, p); until != ts+3600 {
		t.Fatalf("cap: until=%d want ts+3600", until)
	}
	// Reset: quiet for reset_after_seconds after the ban ended.
	if _, _, stale := wafState(row(14), ts+100+599, p); stale {
		t.Fatal("must not be stale before the reset window elapsed")
	}
	if _, _, stale := wafState(row(14), ts+100+600, p); !stale {
		t.Fatal("must be stale once the reset window elapsed after the ban")
	}
	// Below threshold the window runs from the last failure.
	if _, _, stale := wafState(row(3), ts+600, p); !stale {
		t.Fatal("sub-threshold counters must be forgotten after reset_after_seconds")
	}
}

func TestWAFStateManualIsPermanent(t *testing.T) {
	p := WAFConfig{Web: WAFPolicy{MaxBlockSeconds: 10, ResetAfterSeconds: 10}}.policy(WAFScopeWeb)
	_, permanent, _ := wafState([]WAF{{BlockIdentifier: BlockIDManual, BlockTimestamp: 1, Count: 99999}}, 1_000_000, p)
	if !permanent {
		t.Fatal("manual bans must stay permanent regardless of max_block_seconds / reset_after_seconds")
	}
}

// CRITICAL scope separation: an attacker who fails web logins through an
// egress IP shared with a real agent must not cut the agent's gRPC off, and
// agent auth failures must not lock the web UI.
func TestWAFScopesAreSeparatedByDefault(t *testing.T) {
	db := newWAFTestDB(t, WAFConfig{})
	const shared = "198.51.100.20"

	for range 5 {
		if err := BlockIP(db, shared, WAFBlockReasonTypeLoginFail, 1); err != nil {
			t.Fatal(err)
		}
	}
	if !isBlocked(t, db, shared, WAFScopeWeb) {
		t.Fatal("web login failures must ban the web scope")
	}
	if isBlocked(t, db, shared, WAFScopeGRPC) {
		t.Fatal("web login failures must not ban agent gRPC")
	}

	if err := BlockIP(db, shared, WAFBlockReasonTypeManual, BlockIDManual); err != nil {
		t.Fatal(err)
	}
	if isBlocked(t, db, shared, WAFScopeGRPC) {
		t.Fatal("a manual (web) ban must not ban agent gRPC")
	}

	const agentIP = "198.51.100.21"
	for range 3 {
		if err := BlockIP(db, agentIP, WAFBlockReasonTypeAgentAuthFail, BlockIDgRPC); err != nil {
			t.Fatal(err)
		}
	}
	if !isBlocked(t, db, agentIP, WAFScopeGRPC) {
		t.Fatal("agent auth failures must ban the gRPC scope")
	}
	if isBlocked(t, db, agentIP, WAFScopeWeb) {
		t.Fatal("agent auth failures must not ban the web UI")
	}
}

func TestWAFSharedScopeRestoresUpstreamBehaviour(t *testing.T) {
	db := newWAFTestDB(t, WAFConfig{SharedScope: true})
	const ip = "198.51.100.22"
	if err := BlockIP(db, ip, WAFBlockReasonTypeLoginFail, 1); err != nil {
		t.Fatal(err)
	}
	if !isBlocked(t, db, ip, WAFScopeGRPC) || !isBlocked(t, db, ip, WAFScopeWeb) {
		t.Fatal("shared_scope must apply a web ban to both scopes")
	}
}

func TestWAFBanExpiresAndEscalates(t *testing.T) {
	db := newWAFTestDB(t, WAFConfig{})
	const ip = "2001:db8::77"

	if err := BlockIP(db, ip, WAFBlockReasonTypeLoginFail, BlockIDUnknownUser); err != nil {
		t.Fatal(err)
	}
	if !isBlocked(t, db, ip, WAFScopeWeb) {
		t.Fatal("first failure bans for max(1^4,3)=3s by default")
	}
	ageWAFRows(t, db, ip, 4*time.Second)
	if isBlocked(t, db, ip, WAFScopeWeb) {
		t.Fatal("ban must expire after 3s")
	}
	if err := BlockIP(db, ip, WAFBlockReasonTypeLoginFail, BlockIDUnknownUser); err != nil {
		t.Fatal(err)
	}
	ageWAFRows(t, db, ip, 10*time.Second)
	if !isBlocked(t, db, ip, WAFScopeWeb) {
		t.Fatal("second failure bans for 2^4=16s")
	}

	if err := UnblockIP(db, ip, BlockIDUnknownUser); err != nil {
		t.Fatal(err)
	}
	if isBlocked(t, db, ip, WAFScopeWeb) {
		t.Fatal("unblock must lift the ban")
	}
}

func TestWAFResetAfterRestartsCounter(t *testing.T) {
	db := newWAFTestDB(t, WAFConfig{Web: WAFPolicy{ResetAfterSeconds: 60}})
	const ip = "198.51.100.23"
	for range 4 {
		if err := BlockIP(db, ip, WAFBlockReasonTypeLoginFail, 1); err != nil {
			t.Fatal(err)
		}
	}
	// 4^4 = 256s ban, then 60s of quiet.
	ageWAFRows(t, db, ip, 256*time.Second+61*time.Second)
	if isBlocked(t, db, ip, WAFScopeWeb) {
		t.Fatal("stale counters must not ban")
	}
	if err := BlockIP(db, ip, WAFBlockReasonTypeLoginFail, 1); err != nil {
		t.Fatal(err)
	}
	var w WAF
	b, _ := utils.IPStringToBinary(ip)
	if err := db.Where("ip = ? AND block_identifier = ?", b, 1).First(&w).Error; err != nil {
		t.Fatal(err)
	}
	if w.Count != 1 {
		t.Fatalf("counter after reset = %d, want 1", w.Count)
	}
}

func TestWAFRowsStayCompatibleWithAdminList(t *testing.T) {
	db := newWAFTestDB(t, WAFConfig{})
	if err := BlockIP(db, "198.51.100.24", WAFBlockReasonTypeAgentAuthFail, BlockIDgRPC); err != nil {
		t.Fatal(err)
	}
	if err := BlockIP(db, "198.51.100.24", WAFBlockReasonTypeLoginFail, 7); err != nil {
		t.Fatal(err)
	}
	var rows []WAF
	if err := db.Order("block_identifier").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].BlockIdentifier != BlockIDgRPC || rows[0].BlockReason != WAFBlockReasonTypeAgentAuthFail ||
		rows[1].BlockIdentifier != 7 || rows[1].Count != 1 {
		t.Fatalf("unexpected rows %+v", rows)
	}
	if err := BatchUnblockIP(db, []string{"198.51.100.24"}); err != nil {
		t.Fatal(err)
	}
	var n int64
	db.Model(&WAF{}).Count(&n)
	if n != 0 {
		t.Fatalf("batch unblock left %d rows", n)
	}
}

func storedWAFKeys(t *testing.T, db *gorm.DB) []string {
	t.Helper()
	var rows []WAF
	if err := db.Order("ip").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range rows {
		out = append(out, utils.BinaryToIPString(r.IP))
	}
	return out
}

// One IPv6 host normally owns a whole /64; rotating the interface ID must not
// reset its failure counter or dodge its ban.
func TestWAFIPv6PrefixAggregatesBothScopes(t *testing.T) {
	db := newWAFTestDB(t, WAFConfig{})

	for _, ip := range []string{"2001:db8:1:2::1", "2001:db8:1:2:aaaa::9"} {
		if err := BlockIP(db, ip, WAFBlockReasonTypeLoginFail, BlockIDUnknownUser); err != nil {
			t.Fatal(err)
		}
	}
	if err := BlockIP(db, "2001:db8:1:2::77", WAFBlockReasonTypeAgentAuthFail, BlockIDgRPC); err != nil {
		t.Fatal(err)
	}
	keys := storedWAFKeys(t, db)
	if len(keys) != 2 || keys[0] != "2001:db8:1:2::" || keys[1] != "2001:db8:1:2::" {
		t.Fatalf("stored keys = %v, want the /64 for both the web and the gRPC row", keys)
	}
	var web WAF
	if err := db.Where("block_identifier = ?", BlockIDUnknownUser).First(&web).Error; err != nil {
		t.Fatal(err)
	}
	if web.Count != 2 {
		t.Fatalf("web count = %d, want 2 (two addresses of one /64)", web.Count)
	}
	if !isBlocked(t, db, "2001:db8:1:2:ffff::1", WAFScopeWeb) || !isBlocked(t, db, "2001:db8:1:2::5", WAFScopeGRPC) {
		t.Fatal("any address of the banned /64 must be blocked in both scopes")
	}
	if isBlocked(t, db, "2001:db8:1:3::1", WAFScopeWeb) {
		t.Fatal("the neighbouring /64 must not be affected")
	}

	// UnblockIP (successful login) maps to the same key.
	if err := UnblockIP(db, "2001:db8:1:2::abcd", BlockIDUnknownUser); err != nil {
		t.Fatal(err)
	}
	if isBlocked(t, db, "2001:db8:1:2::1", WAFScopeWeb) {
		t.Fatal("unblock from another address of the /64 must clear the web row")
	}
	// The admin list shows the stored key; unblocking by it removes the row.
	if err := BatchUnblockIP(db, []string{"2001:db8:1:2::"}); err != nil {
		t.Fatal(err)
	}
	if keys := storedWAFKeys(t, db); len(keys) != 0 {
		t.Fatalf("rows left after admin unblock: %v", keys)
	}
}

func TestWAFIPv6PrefixExactAndIPv4(t *testing.T) {
	db := newWAFTestDB(t, WAFConfig{IPv6Prefix: 128})
	if err := BlockIP(db, "2001:db8::1", WAFBlockReasonTypeLoginFail, 1); err != nil {
		t.Fatal(err)
	}
	if isBlocked(t, db, "2001:db8::2", WAFScopeWeb) {
		t.Fatal("ipv6_prefix: 128 must key on the exact address")
	}

	SetWAFConfig(WAFConfig{IPv6Prefix: 48})
	if err := BlockIP(db, "198.51.100.7", WAFBlockReasonTypeLoginFail, 1); err != nil {
		t.Fatal(err)
	}
	if isBlocked(t, db, "198.51.100.8", WAFScopeWeb) {
		t.Fatal("IPv4 is always keyed on the exact address")
	}
	if got := WAFKey("2001:db8:aa:bb::1"); got != "2001:db8:aa::" {
		t.Fatalf("WAFKey with /48 = %s", got)
	}
	if got := WAFKey("::ffff:198.51.100.7"); got != "198.51.100.7" {
		t.Fatalf("WAFKey must unmap IPv4-mapped addresses, got %s", got)
	}
}
