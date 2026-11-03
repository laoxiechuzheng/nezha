package controller

import (
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/nezhahq/nezha/cmd/dashboard/controller/waf"
	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/service/singleton"
)

// loginLimiter bounds the bcrypt work an unauthenticated client can cause.
//
// The WAF bans an address after a failed login, but only once that failure
// has been recorded; requests fired concurrently from the same address all
// pass CheckIP before the first one fails, so without this every one of them
// would run bcrypt. inflight allows a single password check per WAF key at a
// time and turns the rest away with 429 before any work (and without
// counting them as failures). slots caps bcrypt globally so many addresses
// together cannot pin every CPU.
type loginLimiter struct {
	mu       sync.Mutex
	inflight map[string]struct{}
	slots    chan struct{}
	wait     time.Duration
}

func newLoginLimiter(slots int, wait time.Duration) *loginLimiter {
	return &loginLimiter{
		inflight: make(map[string]struct{}),
		slots:    make(chan struct{}, slots),
		wait:     wait,
	}
}

var loginLimiterShared = newLoginLimiter(max(2, runtime.NumCPU()), 2*time.Second)

// loginGuard wraps the login handler; it must run after waf.RealIp/waf.Waf.
func loginGuard() gin.HandlerFunc {
	return func(c *gin.Context) {
		loginLimiterShared.handle(c)
	}
}

func (l *loginLimiter) enter(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, busy := l.inflight[key]; busy {
		return false
	}
	l.inflight[key] = struct{}{}
	return true
}

func (l *loginLimiter) leave(key string) {
	l.mu.Lock()
	delete(l.inflight, key)
	l.mu.Unlock()
}

func (l *loginLimiter) handle(c *gin.Context) {
	ip := c.GetString(model.CtxKeyRealIPStr)
	key := model.WAFKey(ip)
	if !l.enter(key) {
		abortTooManyLogins(c)
		return
	}
	defer l.leave(key)

	// waf.Waf checked the address before this request queued here; a login
	// from the same key that finished in between may have banned it since.
	if err := model.CheckIP(singleton.DB, ip, model.WAFScopeWeb); err != nil {
		waf.ShowBlockPage(c, err)
		return
	}

	timer := time.NewTimer(l.wait)
	defer timer.Stop()
	select {
	case l.slots <- struct{}{}:
	case <-timer.C:
		abortTooManyLogins(c)
		return
	case <-c.Request.Context().Done():
		c.Abort()
		return
	}
	defer func() { <-l.slots }()

	c.Next()
}

func abortTooManyLogins(c *gin.Context) {
	c.Header("Retry-After", "1")
	c.AbortWithStatusJSON(http.StatusTooManyRequests, model.CommonResponse[any]{
		Success: false,
		Error:   "too many concurrent login attempts",
	})
}
