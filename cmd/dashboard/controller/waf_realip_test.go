package controller

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/nezhahq/nezha/cmd/dashboard/controller/waf"
	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/pkg/idcodec"
	"github.com/nezhahq/nezha/pkg/utils"
	"github.com/nezhahq/nezha/service/singleton"
)

// loginTestEngine mirrors ServeWeb's middleware order (RealIp -> Waf ->
// handler) in front of the real authenticator, counting how often the
// handler — and therefore bcrypt — actually runs.
func loginTestEngine(t *testing.T, calls *int) *gin.Engine {
	t.Helper()
	pw, err := bcrypt.GenerateFromPassword([]byte("correct horse"), bcrypt.MinCost)
	require.NoError(t, err)
	require.NoError(t, singleton.DB.Model(&model.User{}).Where("id = ?", 100).Update("password", string(pw)).Error)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(waf.RealIp, waf.Waf)
	r.POST("/api/v1/login", func(c *gin.Context) {
		*calls++
		if _, err := authenticator()(c); err != nil {
			c.JSON(http.StatusOK, model.CommonResponse[any]{Success: false, Error: err.Error()})
			return
		}
		c.JSON(http.StatusOK, model.CommonResponse[any]{Success: true})
	})
	return r
}

func login(r *gin.Engine, remoteAddr, password string, headers map[string]string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(model.LoginRequest{Username: "victim", Password: password})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/login", bytes.NewReader(body))
	req.RemoteAddr = remoteAddr
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func wafCount(t *testing.T, ip string) uint64 {
	t.Helper()
	b, err := utils.IPStringToBinary(ip)
	require.NoError(t, err)
	var total uint64
	require.NoError(t, singleton.DB.Model(&model.WAF{}).Select("COALESCE(SUM(count),0)").Where("ip = ?", b).Scan(&total).Error)
	return total
}

// The incident configuration: no web_real_ip_header at all. Failures must
// still be counted against the TCP peer and the ban must stop the next
// attempt before bcrypt runs, whatever X-Real-IP the attacker invents.
func TestLoginBruteForceThrottledWithoutRealIPHeader(t *testing.T) {
	defer setupJWTSessionTest(t)()
	model.SetWAFConfig(model.WAFConfig{})
	var calls int
	r := loginTestEngine(t, &calls)

	w := login(r, "203.0.113.9:40001", "wrong", nil)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 1, calls)
	assert.Equal(t, uint64(1), wafCount(t, "203.0.113.9"), "failed login must be counted against the peer IP")

	w = login(r, "203.0.113.9:40002", "correct horse", map[string]string{"X-Real-IP": "1.1.1.1", "X-Forwarded-For": "1.1.1.1"})
	assert.Equal(t, http.StatusForbidden, w.Code, "banned peer must be stopped even with a spoofed header")
	assert.Equal(t, 1, calls, "WAF must reject before the login handler (bcrypt) runs")
	assert.Equal(t, uint64(0), wafCount(t, "1.1.1.1"))

	w = login(r, "198.51.100.10:40003", "correct horse", nil)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 2, calls, "an unrelated client must not be affected")
}

// Behind the docker-host nginx (peer 172.24.0.1) with X-Real-IP and
// trusted_proxies configured, bans land on the real client, not on the proxy.
func TestLoginThroughTrustedProxyBansRealClient(t *testing.T) {
	defer setupJWTSessionTest(t)()
	model.SetWAFConfig(model.WAFConfig{})
	singleton.Conf.WebRealIPHeader = "X-Real-IP"
	require.NoError(t, singleton.Conf.SetTrustedProxies([]string{"172.24.0.1/32"}))
	var calls int
	r := loginTestEngine(t, &calls)

	login(r, "172.24.0.1:50001", "wrong", map[string]string{"X-Real-IP": "198.51.100.66"})
	assert.Equal(t, uint64(1), wafCount(t, "198.51.100.66"))
	assert.Equal(t, uint64(0), wafCount(t, "172.24.0.1"), "the proxy itself must not collect the ban")

	w := login(r, "172.24.0.1:50002", "wrong", map[string]string{"X-Real-IP": "198.51.100.66"})
	assert.Equal(t, http.StatusForbidden, w.Code)

	w = login(r, "172.24.0.1:50003", "correct horse", map[string]string{"X-Real-IP": "198.51.100.67"})
	assert.Equal(t, http.StatusOK, w.Code, "other clients behind the same proxy keep working")
	assert.Equal(t, 2, calls)

	// A direct (untrusted) client cannot borrow the header to escape its ban.
	login(r, "203.0.113.70:1", "wrong", map[string]string{"X-Real-IP": "198.51.100.200"})
	assert.Equal(t, uint64(1), wafCount(t, "203.0.113.70"))
	assert.Equal(t, uint64(0), wafCount(t, "198.51.100.200"))
}

func TestWebClientIPRequiresPeer(t *testing.T) {
	defer setupJWTSessionTest(t)()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = ""
	_, ok := waf.ClientIP(req)
	assert.False(t, ok, "no peer and no trusted header must not resolve to an empty/unknown IP silently")

	req.RemoteAddr = "[::ffff:203.0.113.5]:9"
	ip, ok := waf.ClientIP(req)
	assert.True(t, ok)
	assert.Equal(t, "203.0.113.5", ip)
}

// A token we signed but whose session is gone (logout, password change,
// expiry) is not brute force: the fallback middleware must continue as a
// guest without feeding the WAF, now that the WAF always sees an IP.
func TestFallbackAuthStaleSessionIsNotCountedAsBruteForce(t *testing.T) {
	defer setupJWTSessionTest(t)()
	model.SetWAFConfig(model.WAFConfig{})
	singleton.Conf.JWTSecretKey = "fallback-test-secret"

	mw, err := jwt.New(initParams())
	require.NoError(t, err)
	encodedUID, err := idcodec.Encode(100)
	require.NoError(t, err)
	token, _, err := mw.TokenGenerator(map[string]interface{}{
		jwtClaimUserID: encodedUID,
		jwtClaimKeyID:  "session-that-was-revoked",
	})
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(waf.RealIp, waf.Waf)
	var reached int
	r.GET("/api/v1/setting", fallbackAuthMiddleware(mw), func(c *gin.Context) {
		reached++
		_, authed := c.Get(model.CtxKeyAuthorizedUser)
		assert.False(t, authed)
		c.Status(http.StatusOK)
	})

	for range 5 {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/setting", nil)
		req.RemoteAddr = "198.51.100.90:1234"
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	}
	assert.Equal(t, 5, reached)
	assert.Equal(t, uint64(0), wafCount(t, "198.51.100.90"), "stale sessions must not ban the owner's IP")
}
