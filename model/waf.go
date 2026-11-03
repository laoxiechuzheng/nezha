package model

import (
	"errors"
	"math/big"
	"sync/atomic"
	"time"

	"github.com/nezhahq/nezha/pkg/utils"
	"gorm.io/gorm"
)

const (
	_ uint8 = iota
	WAFBlockReasonTypeLoginFail
	WAFBlockReasonTypeBruteForceToken
	WAFBlockReasonTypeAgentAuthFail
	WAFBlockReasonTypeManual
	WAFBlockReasonTypeBruteForceOauth2
)

const (
	BlockIDgRPC = -127 + iota
	BlockIDToken
	BlockIDUnknownUser
	BlockIDManual
)

// ErrWAFBlocked is returned by CheckIP when the address is currently banned.
var ErrWAFBlocked = errors.New("you were blocked by nezha WAF")

// WAFScope selects which nz_waf rows gate a request.
//
// Web (HTTP: login, PAT, OAuth2, JWT, manual) and agent gRPC failures are
// separate scopes by default: a dashboard reached through the owner's own
// proxy nodes must not lose those nodes' agents just because somebody failed
// web logins from the same egress IP. Rows with block_identifier ==
// BlockIDgRPC belong to the gRPC scope, every other row to the web scope.
type WAFScope uint8

const (
	WAFScopeWeb WAFScope = iota + 1
	WAFScopeGRPC
)

// WAFPolicy controls how failures turn into a ban. Zero values select the
// historical upstream behaviour: every failure counts, the ban lasts
// max(n^4, 3) seconds after the latest failure, it never caps and counters
// are only cleared by a successful authentication or a manual unblock.
type WAFPolicy struct {
	// FailThreshold: the n-th failure is the first one that bans (0/1 = first).
	FailThreshold uint64 `koanf:"fail_threshold" json:"fail_threshold,omitempty"`
	// BlockExponent: ban seconds = (failures - FailThreshold + 1) ^ BlockExponent (0 = 4).
	BlockExponent uint64 `koanf:"block_exponent" json:"block_exponent,omitempty"`
	// MinBlockSeconds: lower bound of a ban (0 = 3).
	MinBlockSeconds uint64 `koanf:"min_block_seconds" json:"min_block_seconds,omitempty"`
	// MaxBlockSeconds: upper bound of an automatic ban (0 = unlimited).
	// Manual bans are always permanent.
	MaxBlockSeconds uint64 `koanf:"max_block_seconds" json:"max_block_seconds,omitempty"`
	// ResetAfterSeconds: forget the failure counter once the address has
	// been quiet this long after its ban expired (0 = never forget).
	ResetAfterSeconds uint64 `koanf:"reset_after_seconds" json:"reset_after_seconds,omitempty"`
}

// WAFConfig is the `waf:` section of config.yaml.
type WAFConfig struct {
	// SharedScope restores the upstream single ban list: web failures also
	// ban agent gRPC and vice versa.
	SharedScope bool `koanf:"shared_scope" json:"shared_scope,omitempty"`
	// GRPCStrictBlock rejects even agents presenting valid credentials while
	// their address is banned (upstream behaviour). Default false: a banned
	// address may still authenticate with a valid agent secret, so an
	// attacker sharing an egress IP with a real agent cannot knock it offline.
	// Agent secrets are 32 random alphanumerics, so the ban is not what keeps
	// them from being guessed.
	GRPCStrictBlock bool      `koanf:"grpc_strict_block" json:"grpc_strict_block,omitempty"`
	Web             WAFPolicy `koanf:"web" json:"web"`
	GRPC            WAFPolicy `koanf:"grpc" json:"grpc"`
}

var wafConfig atomic.Pointer[WAFConfig]

// SetWAFConfig installs the policy used by CheckIP / BlockIP.
func SetWAFConfig(c WAFConfig) {
	wafConfig.Store(&c)
}

// CurrentWAFConfig returns the active policy (zero value = upstream defaults).
func CurrentWAFConfig() WAFConfig {
	if c := wafConfig.Load(); c != nil {
		return *c
	}
	return WAFConfig{}
}

func (c WAFConfig) policy(scope WAFScope) WAFPolicy {
	p := c.Web
	if scope == WAFScopeGRPC {
		p = c.GRPC
	}
	if p.FailThreshold == 0 {
		p.FailThreshold = 1
	}
	if p.BlockExponent == 0 {
		p.BlockExponent = 4
	}
	if p.MinBlockSeconds == 0 {
		p.MinBlockSeconds = 3
	}
	return p
}

func scopeOfIdentifier(uid int64) WAFScope {
	if uid == BlockIDgRPC {
		return WAFScopeGRPC
	}
	return WAFScopeWeb
}

func (c WAFConfig) scoped(db *gorm.DB, scope WAFScope) *gorm.DB {
	if c.SharedScope {
		return db
	}
	if scope == WAFScopeGRPC {
		return db.Where("block_identifier = ?", BlockIDgRPC)
	}
	return db.Where("block_identifier <> ?", BlockIDgRPC)
}

type WAFApiMock struct {
	IP              string `json:"ip,omitempty"`
	BlockIdentifier int64  `json:"block_identifier,omitempty"`
	BlockReason     uint8  `json:"block_reason,omitempty"`
	BlockTimestamp  uint64 `json:"block_timestamp,omitempty"`
	Count           uint64 `json:"count,omitempty"`
}

type WAF struct {
	IP              []byte `gorm:"type:binary(16);primaryKey" json:"ip,omitempty"`
	BlockIdentifier int64  `gorm:"primaryKey" json:"block_identifier,omitempty"`
	BlockReason     uint8  `json:"block_reason,omitempty"`
	BlockTimestamp  uint64 `gorm:"index" json:"block_timestamp,omitempty"`
	Count           uint64 `json:"count,omitempty"`
}

func (w *WAF) TableName() string {
	return "nz_waf"
}

// wafState folds one address' rows (already filtered to a scope) into a
// verdict. until is the unix second the ban ends (0 = no ban); stale reports
// that the counters are older than ResetAfterSeconds and must be ignored.
func wafState(rows []WAF, now uint64, p WAFPolicy) (until uint64, permanent, stale bool) {
	var sum, latest uint64
	for _, r := range rows {
		if r.BlockIdentifier == BlockIDManual {
			return 0, true, false
		}
		sum = satAdd(sum, r.Count)
		latest = max(latest, r.BlockTimestamp)
	}
	if len(rows) == 0 {
		return 0, false, false
	}

	end := latest
	if sum >= p.FailThreshold {
		n := sum - p.FailThreshold + 1
		d := max(pow(n, p.BlockExponent), p.MinBlockSeconds)
		if p.MaxBlockSeconds > 0 {
			d = min(d, p.MaxBlockSeconds)
		}
		end = satAdd(latest, d)
		until = end
	}
	if p.ResetAfterSeconds > 0 && now >= satAdd(end, p.ResetAfterSeconds) {
		return 0, false, true
	}
	return until, false, false
}

// CheckIP reports ErrWAFBlocked when ip is banned in scope. Other errors are
// storage/parse failures.
func CheckIP(db *gorm.DB, ip string, scope WAFScope) error {
	if ip == "" {
		return nil
	}
	ipBinary, err := utils.IPStringToBinary(ip)
	if err != nil {
		return err
	}

	conf := CurrentWAFConfig()
	var rows []WAF
	q := db.Model(&WAF{}).Select("block_identifier", "block_timestamp", "count").Where("ip = ?", ipBinary)
	if err := conf.scoped(q, scope).Find(&rows).Error; err != nil {
		return err
	}

	until, permanent, _ := wafState(rows, uint64(time.Now().Unix()), conf.policy(scope))
	if permanent || until > uint64(time.Now().Unix()) {
		return ErrWAFBlocked
	}
	return nil
}

func UnblockIP(db *gorm.DB, ip string, uid int64) error {
	if ip == "" {
		return nil
	}
	ipBinary, err := utils.IPStringToBinary(ip)
	if err != nil {
		return err
	}
	return db.Unscoped().Delete(&WAF{}, "ip = ? and block_identifier = ?", ipBinary, uid).Error
}

func BatchUnblockIP(db *gorm.DB, ip []string) error {
	if len(ip) < 1 {
		return nil
	}
	ips := make([][]byte, 0, len(ip))
	for _, s := range ip {
		ipBinary, err := utils.IPStringToBinary(s)
		if err != nil {
			continue
		}
		ips = append(ips, ipBinary)
	}
	return db.Unscoped().Delete(&WAF{}, "ip in (?)", ips).Error
}

// BlockIP records one failure (or a manual ban) for ip under identifier uid.
func BlockIP(db *gorm.DB, ip string, reason uint8, uid int64) error {
	if ip == "" {
		return nil
	}
	ipBinary, err := utils.IPStringToBinary(ip)
	if err != nil {
		return err
	}
	w := WAF{
		IP:              ipBinary,
		BlockIdentifier: uid,
	}
	now := uint64(time.Now().Unix())

	var count any
	if reason == WAFBlockReasonTypeManual {
		count = 99999
	} else {
		count = gorm.Expr("count + 1")
	}

	conf := CurrentWAFConfig()
	scope := scopeOfIdentifier(uid)
	p := conf.policy(scope)

	return db.Transaction(func(tx *gorm.DB) error {
		if p.ResetAfterSeconds > 0 && reason != WAFBlockReasonTypeManual {
			var rows []WAF
			q := tx.Model(&WAF{}).Select("block_identifier", "block_timestamp", "count").Where("ip = ?", ipBinary)
			if err := conf.scoped(q, scope).Find(&rows).Error; err != nil {
				return err
			}
			if _, _, stale := wafState(rows, now, p); stale {
				if err := conf.scoped(tx.Model(&WAF{}).Where("ip = ?", ipBinary), scope).
					Where("block_identifier <> ?", BlockIDManual).
					Update("count", 0).Error; err != nil {
					return err
				}
			}
		}
		if err := tx.Where(&w).Attrs(WAF{
			BlockReason:    reason,
			BlockTimestamp: now,
		}).FirstOrCreate(&w).Error; err != nil {
			return err
		}
		return tx.Exec("UPDATE nz_waf SET count = ?, block_reason = ?, block_timestamp = ? WHERE ip = ? and block_identifier = ?", count, reason, now, ipBinary, uid).Error
	})
}

func satAdd(a, b uint64) uint64 {
	if a > ^uint64(0)-b {
		return ^uint64(0)
	}
	return a + b
}

func pow(x, y uint64) uint64 {
	result := big.NewInt(0).Exp(big.NewInt(0).SetUint64(x), big.NewInt(0).SetUint64(y), nil)
	if !result.IsUint64() {
		return ^uint64(0) // saturate on overflow
	}
	return result.Uint64()
}
