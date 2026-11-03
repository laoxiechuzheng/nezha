package controller

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/nezhahq/nezha/cmd/dashboard/controller/waf"
	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/service/singleton"
)

// countBcrypt swaps compareHashAndPassword for a counting (and optionally
// slow) wrapper for the duration of the test.
func countBcrypt(t *testing.T, delay time.Duration) *atomic.Int32 {
	t.Helper()
	var n atomic.Int32
	orig := compareHashAndPassword
	compareHashAndPassword = func(hash, pw []byte) error {
		n.Add(1)
		time.Sleep(delay)
		return orig(hash, pw)
	}
	t.Cleanup(func() { compareHashAndPassword = orig })
	return &n
}

func withLoginLimiter(t *testing.T, l *loginLimiter) {
	t.Helper()
	orig := loginLimiterShared
	loginLimiterShared = l
	t.Cleanup(func() { loginLimiterShared = orig })
}

// guardedLoginEngine is the production order RealIp -> Waf -> loginGuard ->
// login handler.
func guardedLoginEngine(t *testing.T) *gin.Engine {
	t.Helper()
	pw, err := bcrypt.GenerateFromPassword([]byte("correct horse"), bcrypt.MinCost)
	require.NoError(t, err)
	require.NoError(t, singleton.DB.Model(&model.User{}).Where("id = ?", 100).Update("password", string(pw)).Error)
	sqlDB, err := singleton.DB.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1) // one :memory: database across goroutines

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(waf.RealIp, waf.Waf)
	r.POST("/api/v1/login", loginGuard(), func(c *gin.Context) {
		if _, err := authenticator()(c); err != nil {
			c.JSON(http.StatusOK, model.CommonResponse[any]{Success: false, Error: err.Error()})
			return
		}
		c.JSON(http.StatusOK, model.CommonResponse[any]{Success: true})
	})
	return r
}

func loginAs(r *gin.Engine, remoteAddr, username, password string) int {
	body, _ := json.Marshal(model.LoginRequest{Username: username, Password: password})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/login", bytes.NewReader(body))
	req.RemoteAddr = remoteAddr
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

// Concurrent wrong-password logins from one address all pass the WAF before
// the first failure is recorded. The in-flight guard must let exactly one of
// them run bcrypt and turn the rest away without counting them.
func TestLoginConcurrentSameIPRunsBcryptOnce(t *testing.T) {
	defer setupJWTSessionTest(t)()
	model.SetWAFConfig(model.WAFConfig{})
	withLoginLimiter(t, newLoginLimiter(8, 2*time.Second))
	calls := countBcrypt(t, 300*time.Millisecond)
	r := guardedLoginEngine(t)

	const n = 12
	codes := make([]int, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			codes[i] = loginAs(r, "203.0.113.50:1000", "victim", "wrong")
		}()
	}
	close(start)
	wg.Wait()

	ran := int(calls.Load())
	var ok, rejected int
	for _, c := range codes {
		switch c {
		case http.StatusOK:
			ok++
		case http.StatusTooManyRequests, http.StatusForbidden:
			rejected++
		default:
			t.Fatalf("unexpected status %d", c)
		}
	}
	// One goroutine can in theory pass CheckIP during the first bcrypt and
	// reach the guard only after it was released; allow that, nothing more.
	assert.GreaterOrEqual(t, ran, 1)
	assert.LessOrEqual(t, ran, 2, "concurrent logins from one address must not each run bcrypt")
	assert.Equal(t, ran, ok, "only requests that ran bcrypt get a login answer")
	assert.Equal(t, n-ran, rejected)
	assert.Equal(t, uint64(ran), wafCount(t, "203.0.113.50"), "every executed password check counts once, rejected ones never")
}

// The global bcrypt slots are shared by all addresses; when they stay busy
// past the wait, further logins get 429 without running bcrypt or counting.
func TestLoginGlobalBcryptSlotsReject(t *testing.T) {
	defer setupJWTSessionTest(t)()
	model.SetWAFConfig(model.WAFConfig{})
	withLoginLimiter(t, newLoginLimiter(1, 50*time.Millisecond))
	calls := countBcrypt(t, 400*time.Millisecond)
	r := guardedLoginEngine(t)

	done := make(chan int)
	go func() { done <- loginAs(r, "203.0.113.60:1", "victim", "wrong") }()
	require.Eventually(t, func() bool { return calls.Load() == 1 }, time.Second, 5*time.Millisecond)

	assert.Equal(t, http.StatusTooManyRequests, loginAs(r, "198.51.100.61:1", "victim", "wrong"))
	assert.Equal(t, http.StatusOK, <-done)
	assert.Equal(t, int32(1), calls.Load())
	assert.Equal(t, uint64(0), wafCount(t, "198.51.100.61"), "a 429 is not a failed login")

	// Slots free again: the other address proceeds normally.
	assert.Equal(t, http.StatusOK, loginAs(r, "198.51.100.61:2", "victim", "correct horse"))
}

// IPv6 clients of one /64 share an in-flight slot as they share a WAF key.
func TestLoginGuardKeysOnWAFPrefix(t *testing.T) {
	model.SetWAFConfig(model.WAFConfig{})
	l := newLoginLimiter(2, time.Second)
	require.True(t, l.enter(model.WAFKey("2001:db8:5:6::1")))
	assert.False(t, l.enter(model.WAFKey("2001:db8:5:6:ffff::2")))
	assert.True(t, l.enter(model.WAFKey("2001:db8:5:7::1")))
}

// Unknown usernames cost a bcrypt like a wrong password and still count.
func TestLoginUnknownUserRunsDummyBcrypt(t *testing.T) {
	defer setupJWTSessionTest(t)()
	model.SetWAFConfig(model.WAFConfig{})
	withLoginLimiter(t, newLoginLimiter(2, time.Second))
	calls := countBcrypt(t, 0)
	r := guardedLoginEngine(t)

	assert.Equal(t, http.StatusOK, loginAs(r, "203.0.113.70:1", "nobody", "whatever"))
	assert.Equal(t, int32(1), calls.Load(), "unknown user must run exactly one dummy bcrypt")
	assert.Equal(t, uint64(1), wafCount(t, "203.0.113.70"))
	assert.Error(t, bcrypt.CompareHashAndPassword(dummyPasswordHash(), []byte("whatever")))
}

func patRequest(t *testing.T, plain, ip string) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c.Request.Header.Set("Authorization", "Bearer "+plain)
	c.Set(model.CtxKeyRealIPStr, ip)
	return c, w
}

// Only unknown PATs are guessing; stale real tokens must not ban the owner.
func TestAPITokenStaleTokenIsNotCountedAsBruteForce(t *testing.T) {
	cleanup, uid := setupMCPTest(t)
	defer cleanup()
	model.SetWAFConfig(model.WAFConfig{})

	past := time.Now().Add(-time.Hour)
	expired := "nzp_" + strings.Repeat("x", 32)
	tok := model.APIToken{UserID: uid, Name: "expired", TokenHash: model.HashAPIToken(expired), ExpiresAt: &past}
	tok.SetScopes([]string{model.ScopeServerRead})
	require.NoError(t, singleton.DB.Create(&tok).Error)

	orphan := "nzp_" + strings.Repeat("y", 32)
	tok2 := model.APIToken{UserID: 4242, Name: "orphan", TokenHash: model.HashAPIToken(orphan)}
	tok2.SetScopes([]string{model.ScopeServerRead})
	require.NoError(t, singleton.DB.Create(&tok2).Error)

	for _, plain := range []string{expired, orphan} {
		c, w := patRequest(t, plain, "198.51.100.80")
		apiTokenAuthMiddleware()(c)
		assert.True(t, c.IsAborted())
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	}
	assert.Equal(t, uint64(0), wafCount(t, "198.51.100.80"), "expired / owner-less tokens are a plain 401")

	c, w := patRequest(t, "nzp_"+strings.Repeat("z", 32), "198.51.100.80")
	apiTokenAuthMiddleware()(c)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, uint64(1), wafCount(t, "198.51.100.80"), "an unknown token is counted")
}

func verifySession(t *testing.T, claims map[string]interface{}, ip string) (any, *gin.Context) {
	t.Helper()
	verify := newCtxForUser(0, ip, "ua")
	verify.Set("JWT_PAYLOAD", jwt.MapClaims{
		jwtClaimUserID: claims[jwtClaimUserID],
		jwtClaimKeyID:  claims[jwtClaimKeyID],
	})
	return identityHandler()(verify), verify
}

func TestSessionIPBindingModes(t *testing.T) {
	defer setupJWTSessionTest(t)()
	user := model.User{Common: model.Common{ID: 100}, TokenVersion: 7}

	claims, err := issueJWTSession(newCtxForUser(0, "198.51.100.10", "ua"), &user, 1)
	require.NoError(t, err)
	claims6, err := issueJWTSession(newCtxForUser(0, "2001:db8:1:2::10", "ua"), &user, 1)
	require.NoError(t, err)

	// default: prefix (/24, /64)
	id, _ := verifySession(t, claims, "198.51.100.200")
	assert.NotNil(t, id, "same /24 must pass in prefix mode")
	id, _ = verifySession(t, claims6, "2001:db8:1:2:ffff::1")
	assert.NotNil(t, id, "same /64 must pass in prefix mode")
	id, ctx := verifySession(t, claims, "198.51.101.10")
	assert.Nil(t, id)
	assert.True(t, ctx.GetBool(model.CtxKeyIsIPMismatch))
	id, _ = verifySession(t, claims6, "2001:db8:1:3::10")
	assert.Nil(t, id)

	singleton.Conf.JWTIPBinding = model.JWTIPBindingExact
	id, _ = verifySession(t, claims, "198.51.100.200")
	assert.Nil(t, id, "exact mode rejects a different address in the same /24")
	id, _ = verifySession(t, claims, "198.51.100.10")
	assert.NotNil(t, id)

	singleton.Conf.JWTIPBinding = model.JWTIPBindingOff
	id, _ = verifySession(t, claims, "203.0.113.1")
	assert.NotNil(t, id, "off disables IP binding")
}

// Sessions stored before the client IP was always resolved have IP "" and
// were never bound. They bind to the first IP that uses them.
func TestSessionLegacyEmptyIPBindsOnFirstUse(t *testing.T) {
	defer setupJWTSessionTest(t)()
	user := model.User{Common: model.Common{ID: 100}, TokenVersion: 7}
	claims, err := issueJWTSession(newCtxForUser(0, "", "ua"), &user, 1)
	require.NoError(t, err)
	keyID := claims[jwtClaimKeyID].(string)

	id, _ := verifySession(t, claims, "203.0.113.40")
	require.NotNil(t, id, "legacy session must keep working after upgrade")
	var sess model.JWTSession
	require.NoError(t, singleton.DB.First(&sess, "key_id = ?", keyID).Error)
	assert.Equal(t, "203.0.113.40", sess.IP)

	id, ctx := verifySession(t, claims, "198.51.100.40")
	assert.Nil(t, id, "once bound, another network is a mismatch")
	assert.True(t, ctx.GetBool(model.CtxKeyIsIPMismatch))
}

func TestSessionIPMatches(t *testing.T) {
	assert.True(t, sessionIPMatches("::ffff:198.51.100.1", "198.51.100.1", model.JWTIPBindingExact))
	assert.False(t, sessionIPMatches("198.51.100.1", "2001:db8::1", model.JWTIPBindingPrefix))
	assert.False(t, sessionIPMatches("garbage", "198.51.100.1", model.JWTIPBindingPrefix))
	assert.True(t, sessionIPMatches("garbage", "other", model.JWTIPBindingOff))
}

// With MCP off the transfer URLs answer 404 before any token parsing or
// audit write.
func TestMCPTransferRoutes404WhenDisabled(t *testing.T) {
	cleanup, _ := setupMCPTest(t)
	defer cleanup()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/mcp/download/:token", mcpTransferEnabledGuard(), mcpOriginGuard(), transferDownloadHandler)
	r.POST("/mcp/upload/:token", mcpTransferEnabledGuard(), mcpOriginGuard(), transferUploadHandler)

	do := func(method, path string) int {
		req := httptest.NewRequest(method, path, strings.NewReader(""))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}

	singleton.Conf.SetMCPEnabled(false)
	assert.Equal(t, http.StatusNotFound, do(http.MethodGet, "/mcp/download/garbage"))
	assert.Equal(t, http.StatusNotFound, do(http.MethodPost, "/mcp/upload/garbage"))
	assert.Equal(t, int64(0), countAuditRows(t, "fs.download", ""))
	assert.Equal(t, int64(0), countAuditRows(t, "fs.upload", ""))

	singleton.Conf.SetMCPEnabled(true)
	assert.Equal(t, http.StatusUnauthorized, do(http.MethodGet, "/mcp/download/garbage"))
}

// Behind a trusted proxy the real-IP header counts only together with the
// proxy secret, so hairpinned Internet clients and other containers that
// also arrive from the bridge gateway cannot pick their WAF key.
func TestClientIPRequiresProxySecret(t *testing.T) {
	defer setupJWTSessionTest(t)()
	singleton.Conf.WebRealIPHeader = "X-Real-IP"
	require.NoError(t, singleton.Conf.SetTrustedProxies([]string{"172.24.0.1/32"}))
	singleton.Conf.TrustedProxySecret = "proxy-secret-for-test"

	ip := func(headers map[string]string) string {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "172.24.0.1:4000"
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		got, ok := waf.ClientIP(req)
		require.True(t, ok)
		return got
	}

	assert.Equal(t, "172.24.0.1", ip(map[string]string{"X-Real-IP": "198.51.100.5"}), "no secret: header ignored")
	assert.Equal(t, "172.24.0.1", ip(map[string]string{"X-Real-IP": "198.51.100.5", "X-Nezha-Proxy-Auth": "wrong"}))
	assert.Equal(t, "198.51.100.5", ip(map[string]string{"X-Real-IP": "198.51.100.5", "X-Nezha-Proxy-Auth": "proxy-secret-for-test"}))

	singleton.Conf.TrustedProxySecretHeader = "X-Edge-Auth"
	assert.Equal(t, "172.24.0.1", ip(map[string]string{"X-Real-IP": "198.51.100.5", "X-Nezha-Proxy-Auth": "proxy-secret-for-test"}))
	assert.Equal(t, "198.51.100.5", ip(map[string]string{"X-Real-IP": "198.51.100.5", "X-Edge-Auth": "proxy-secret-for-test"}))

	// The secret never makes an untrusted peer trusted.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.9:1"
	req.Header.Set("X-Real-IP", "198.51.100.5")
	req.Header.Set("X-Edge-Auth", "proxy-secret-for-test")
	got, _ := waf.ClientIP(req)
	assert.Equal(t, "203.0.113.9", got)
}
