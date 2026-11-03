package waf

import (
	_ "embed"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/pkg/utils"
	"github.com/nezhahq/nezha/service/singleton"
)

//go:embed waf.html
var errorPageTemplate string

// ClientIP resolves the address WAF accounting and session binding key on:
// the TCP peer, or web_real_ip_header when the peer is a trusted proxy.
func ClientIP(r *http.Request) (string, bool) {
	header := singleton.Conf.WebRealIPHeader
	if header == model.ConfigUsePeerIP {
		header = ""
	}
	var vals []string
	if header != "" {
		vals = r.Header.Values(header)
	}
	peer, _ := utils.ParseRemoteAddr(r.RemoteAddr)
	ip, ok := utils.ResolveClientIP(peer, header, vals, singleton.Conf.TrustedProxyPrefixes())
	if !ok {
		return "", false
	}
	return ip.String(), true
}

// RealIp always populates CtxKeyRealIPStr so the WAF can never be skipped.
func RealIp(c *gin.Context) {
	ip, ok := ClientIP(c.Request)
	if !ok {
		c.AbortWithStatusJSON(http.StatusBadRequest, model.CommonResponse[any]{Success: false, Error: "cannot determine client ip"})
		return
	}
	c.Set(model.CtxKeyRealIPStr, ip)
	c.Next()
}

// Waf runs before every handler, so a banned address never reaches bcrypt
// in the login handler.
func Waf(c *gin.Context) {
	if err := model.CheckIP(singleton.DB, c.GetString(model.CtxKeyRealIPStr), model.WAFScopeWeb); err != nil {
		ShowBlockPage(c, err)
		return
	}
	c.Next()
}

func ShowBlockPage(c *gin.Context, err error) {
	var errMsg string
	if err != nil {
		errMsg = err.Error()
	} else {
		errMsg = "you were blocked by nezha WAF"
	}
	c.Writer.WriteHeader(http.StatusForbidden)
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Writer.WriteString(strings.Replace(errorPageTemplate, "{error}", errMsg, 1))
	c.Abort()
}
