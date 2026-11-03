package model

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestReadConfig(t *testing.T) {
	t.Run("ReadEmptyConfig", func(t *testing.T) {
		file := newTempConfig(t, "")
		c := &Config{}

		if err := c.Read(file, nil); err != nil {
			t.Fatalf("read empty config failed: %v", err)
		}

		testFields := []struct {
			Name  string
			Value any
			Cond  bool
		}{
			{"jwt_secret_key", c.JWTSecretKey, c.JWTSecretKey != ""},
			{"user_template", c.UserTemplate, c.UserTemplate == "user-dist"},
			{"admin_template", c.AdminTemplate, c.AdminTemplate == "admin-dist"},
			{"agent_secret_key", c.AgentSecretKey, c.AgentSecretKey != ""},
		}

		for _, field := range testFields {
			if !field.Cond {
				t.Fatalf("%s did not passed check, value: %v", field.Name, field.Value)
			}
		}

		os.Remove(file)
	})

	t.Run("ReadFile", func(t *testing.T) {
		const testCfg = "jwt_secret_key: test\nuser_template: um\nadmin_template: am\nagent_secret_key: none\nsite_name: lowkick"

		var testFrontendTemplates = []FrontendTemplate{
			{Path: "um"},
			{Path: "am", IsAdmin: true},
		}
		file := newTempConfig(t, testCfg)
		c := &Config{}

		if err := c.Read(file, testFrontendTemplates); err != nil {
			t.Fatalf("read config failed: %v", err)
		}

		testFields := []struct {
			Name  string
			Value any
			Cond  bool
		}{
			{"jwt_secret_key", c.JWTSecretKey, c.JWTSecretKey == "test"},
			{"user_template", c.UserTemplate, c.UserTemplate == "um"},
			{"admin_template", c.AdminTemplate, c.AdminTemplate == "am"},
			{"agent_secret_key", c.AgentSecretKey, c.AgentSecretKey == "none"},
			{"site_name", c.SiteName, c.SiteName == "lowkick"},
		}

		for _, field := range testFields {
			if !field.Cond {
				t.Fatalf("%s did not passed check, value: %v", field.Name, field.Value)
			}
		}

		os.Remove(file)
	})

	t.Run("ReadEnv", func(t *testing.T) {
		os.Setenv("NZ_JWTSECRETKEY", "test")
		os.Setenv("NZ_USERTEMPLATE", "um")
		os.Setenv("NZ_ADMINTEMPLATE", "am")
		os.Setenv("NZ_AGENTSECRETKEY", "none")
		os.Setenv("NZ_HTTPS_LISTENPORT", "9876")

		var testFrontendTemplates = []FrontendTemplate{
			{Path: "um"},
			{Path: "am", IsAdmin: true},
		}
		file := newTempConfig(t, "")
		c := &Config{}

		if err := c.Read(file, testFrontendTemplates); err != nil {
			t.Fatalf("read empty config failed: %v", err)
		}

		testFields := []struct {
			Name  string
			Value any
			Cond  bool
		}{
			{"jwt_secret_key", c.JWTSecretKey, c.JWTSecretKey == "test"},
			{"user_template", c.UserTemplate, c.UserTemplate == "um"},
			{"admin_template", c.AdminTemplate, c.AdminTemplate == "am"},
			{"agent_secret_key", c.AgentSecretKey, c.AgentSecretKey == "none"},
			{"https.listenport", c.HTTPS.ListenPort, c.HTTPS.ListenPort == 9876},
		}

		for _, field := range testFields {
			if !field.Cond {
				t.Fatalf("%s did not passed check, value: %v", field.Name, field.Value)
			}
		}

		os.Remove(file)
	})

	t.Run("ReadEnvFile", func(t *testing.T) {
		t.Setenv("NZ_JWTSECRETKEY", "test1")
		t.Setenv("NZ_USERTEMPLATE", "um1")
		t.Setenv("NZ_ADMINTEMPLATE", "am1")
		t.Setenv("NZ_AGENTSECRETKEY", "none1")
		t.Setenv("NZ_SITENAME", "lowkick1")

		const testCfg = "jwt_secret_key: test\nuser_template: um\nadmin_template: am\nagent_secret_key: none\nsite_name: lowkick"

		var testFrontendTemplates = []FrontendTemplate{
			{Path: "um"},
			{Path: "am", IsAdmin: true},
			{Path: "um1"},
			{Path: "am1", IsAdmin: true},
		}
		file := newTempConfig(t, testCfg)
		c := &Config{}

		if err := c.Read(file, testFrontendTemplates); err != nil {
			t.Fatalf("read empty config failed: %v", err)
		}

		testFields := []struct {
			Name  string
			Value any
			Cond  bool
		}{
			{"jwt_secret_key", c.JWTSecretKey, c.JWTSecretKey == "test1"},
			{"jwt_secret_from_env", c.jwtSecretFromEnv, c.jwtSecretFromEnv},
			{"user_template", c.UserTemplate, c.UserTemplate == "um1" || c.UserTemplate == "um"},
			{"admin_template", c.AdminTemplate, c.AdminTemplate == "am1" || c.AdminTemplate == "am"},
			{"agent_secret_key", c.AgentSecretKey, c.AgentSecretKey == "none" || c.AgentSecretKey == "none1"},
			{"site_name", c.SiteName, c.SiteName == "lowkick" || c.SiteName == "lowkick1"},
		}

		for _, field := range testFields {
			if !field.Cond {
				t.Fatalf("%s did not passed check, value: %v", field.Name, field.Value)
			}
		}

		os.Remove(file)
	})
}

func TestRotateJWTSecretKeyIfNeeded(t *testing.T) {
	tests := []struct {
		name               string
		initialMarker      string
		currentVersion     string
		wantRotated        bool
		wantStoredVersion  string
		wantSecretChanged  bool
		wantSavedConfigKey bool
	}{
		{
			name:               "empty marker rotates leaked secret",
			currentVersion:     "v2.0.13",
			wantRotated:        true,
			wantStoredVersion:  "v2.0.13",
			wantSecretChanged:  true,
			wantSavedConfigKey: true,
		},
		{
			name:               "old marker rotates leaked secret",
			initialMarker:      "v2.0.12",
			currentVersion:     "v2.0.14",
			wantRotated:        true,
			wantStoredVersion:  "v2.0.14",
			wantSecretChanged:  true,
			wantSavedConfigKey: true,
		},
		{
			name:               "threshold marker keeps secret and advances marker",
			initialMarker:      "v2.0.13",
			currentVersion:     "v2.0.14",
			wantStoredVersion:  "v2.0.14",
			wantSavedConfigKey: true,
		},
		{
			name:              "current marker keeps secret",
			initialMarker:     "v2.0.14",
			currentVersion:    "v2.0.14",
			wantStoredVersion: "v2.0.14",
		},
		{
			name:           "debug version skips rotation and marker update",
			currentVersion: "debug",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := newTempConfig(t, "")
			t.Cleanup(func() { os.Remove(file) })

			c := &Config{
				JWTSecretKey:                   "leaked-secret",
				JWTSecretKeyLastRotatedVersion: tt.initialMarker,
				filePath:                       file,
			}

			rotated, err := c.RotateJWTSecretKeyIfNeeded(tt.currentVersion)
			if err != nil {
				t.Fatalf("rotate jwt secret key failed: %v", err)
			}
			if rotated != tt.wantRotated {
				t.Fatalf("rotated = %v, want %v", rotated, tt.wantRotated)
			}
			if c.JWTSecretKeyLastRotatedVersion != tt.wantStoredVersion {
				t.Fatalf("jwt secret key marker = %q, want %q", c.JWTSecretKeyLastRotatedVersion, tt.wantStoredVersion)
			}
			secretChanged := c.JWTSecretKey != "leaked-secret"
			if secretChanged != tt.wantSecretChanged {
				t.Fatalf("secret changed = %v, want %v", secretChanged, tt.wantSecretChanged)
			}

			saved, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("read saved config: %v", err)
			}
			hasMarker := strings.Contains(string(saved), "jwt_secret_key_last_rotated_version")
			if hasMarker != tt.wantSavedConfigKey {
				t.Fatalf("saved marker present = %v, want %v, config = %s", hasMarker, tt.wantSavedConfigKey, saved)
			}
		})
	}
}

// Mirrors the upstream single-block declaration so iota lines up exactly:
// ConfigUsePeerIP occupies iota=0 (as a typed string), ConfigCoverAll=1,
// ConfigCoverIgnoreAll=2. Pins persisted `cover` semantics.
const (
	originalConfigUsePeerIP = "NZ::Use-Peer-IP"
	originalConfigCoverAll  = iota
	originalConfigCoverIgnoreAll
)

func TestConfigCoverConstantValues(t *testing.T) {
	if ConfigUsePeerIP != originalConfigUsePeerIP {
		t.Fatalf("ConfigUsePeerIP = %q, want %q", ConfigUsePeerIP, originalConfigUsePeerIP)
	}
	if ConfigCoverAll != originalConfigCoverAll {
		t.Fatalf("ConfigCoverAll = %d, want original value %d", ConfigCoverAll, originalConfigCoverAll)
	}
	if ConfigCoverIgnoreAll != originalConfigCoverIgnoreAll {
		t.Fatalf("ConfigCoverIgnoreAll = %d, want original value %d", ConfigCoverIgnoreAll, originalConfigCoverIgnoreAll)
	}
}

func newTempConfig(t *testing.T, cfg string) string {
	t.Helper()

	file, err := os.CreateTemp(os.TempDir(), "nezha-test-config-*.yml")
	if err != nil {
		t.Fatalf("create temp file failed: %v", err)
	}
	defer file.Close()

	_, err = file.ReadFrom(strings.NewReader(cfg))
	if err != nil {
		t.Fatalf("write to temp file failed: %v", err)
	}

	return file.Name()
}

func TestReadConfigWAFAndProxyKeys(t *testing.T) {
	const cfg = `
agent_secret_key: abcdefghijklmnopqrstuvwxyz012345
trusted_proxies:
  - 172.24.0.1/32
  - 127.0.0.1
trusted_proxy_secret: s3cr3t-value
trusted_proxy_secret_header: X-Edge-Auth
jwt_ip_binding: exact
waf:
  ipv6_prefix: 56
  web:
    max_block_seconds: 3600
    reset_after_seconds: 86400
`
	file := newTempConfig(t, cfg)
	defer os.Remove(file)
	prev := CurrentWAFConfig()
	defer SetWAFConfig(prev)

	c := &Config{}
	if err := c.Read(file, nil); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !reflect.DeepEqual(c.TrustedProxies, []string{"172.24.0.1/32", "127.0.0.1"}) {
		t.Fatalf("trusted_proxies = %v", c.TrustedProxies)
	}
	if got := c.TrustedProxyPrefixes(); len(got) != 2 || got[0].String() != "172.24.0.1/32" || got[1].String() != "127.0.0.1/32" {
		t.Fatalf("parsed trusted proxies = %v", got)
	}
	if c.TrustedProxySecret != "s3cr3t-value" || c.ProxySecretHeaderName() != "X-Edge-Auth" {
		t.Fatalf("secret/header = %q/%q", c.TrustedProxySecret, c.ProxySecretHeaderName())
	}
	if c.SessionIPBinding() != JWTIPBindingExact {
		t.Fatalf("jwt_ip_binding = %q", c.SessionIPBinding())
	}
	w := CurrentWAFConfig()
	if w.IPv6Prefix != 56 || w.Web.MaxBlockSeconds != 3600 || w.Web.ResetAfterSeconds != 86400 {
		t.Fatalf("waf = %+v", w)
	}
	if len(c.StartupWarnings()) != 0 {
		t.Fatalf("unexpected warnings: %v", c.StartupWarnings())
	}
}

func TestReadConfigProxyDefaultsAndScalarList(t *testing.T) {
	file := newTempConfig(t, "agent_secret_key: abcdefghijklmnopqrstuvwxyz012345\ntrusted_proxies: 172.24.0.1/32, 10.0.0.0/8\n")
	defer os.Remove(file)
	prev := CurrentWAFConfig()
	defer SetWAFConfig(prev)

	c := &Config{}
	if err := c.Read(file, nil); err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := c.TrustedProxyPrefixes(); len(got) != 2 || got[0].String() != "172.24.0.1/32" || got[1].String() != "10.0.0.0/8" {
		t.Fatalf("scalar trusted_proxies parsed as %v", got)
	}
	if c.ProxySecretHeaderName() != DefaultTrustedProxySecretHeader {
		t.Fatalf("default secret header = %q", c.ProxySecretHeaderName())
	}
	if c.SessionIPBinding() != JWTIPBindingPrefix {
		t.Fatalf("default jwt_ip_binding = %q", c.SessionIPBinding())
	}
	if CurrentWAFConfig().ipv6Prefix() != 64 {
		t.Fatalf("default ipv6 prefix = %d", CurrentWAFConfig().ipv6Prefix())
	}
	if !c.ProxyAuthenticated(nil) {
		t.Fatal("with no trusted_proxy_secret every trusted proxy is accepted")
	}
}

func TestReadConfigRejectsBadProxyKeys(t *testing.T) {
	prev := CurrentWAFConfig()
	defer SetWAFConfig(prev)
	for _, cfg := range []string{
		"jwt_ip_binding: strict\n",
		"waf:\n  ipv6_prefix: 129\n",
		"trusted_proxies: not-an-ip\n",
	} {
		file := newTempConfig(t, cfg)
		if err := (&Config{}).Read(file, nil); err == nil {
			t.Errorf("config %q must be rejected", cfg)
		}
		os.Remove(file)
	}
}

func TestConfigStartupWarnings(t *testing.T) {
	c := &Config{}
	c.WebRealIPHeader = "X-Real-IP"
	c.AgentSecretKey = "short"
	ws := strings.Join(c.StartupWarnings(), "\n")
	if !strings.Contains(ws, "trusted_proxy_secret is empty") || !strings.Contains(ws, "docker-proxy") {
		t.Fatalf("missing real-ip header warning: %s", ws)
	}
	if !strings.Contains(ws, "agent_secret_key is only 5 characters") {
		t.Fatalf("missing short agent secret warning: %s", ws)
	}

	c.TrustedProxySecret = "do-not-print-me"
	c.AgentSecretKey = strings.Repeat("a", 32)
	if ws := c.StartupWarnings(); len(ws) != 0 {
		t.Fatalf("unexpected warnings: %v", ws)
	}
	c.WebRealIPHeader = ConfigUsePeerIP
	c.TrustedProxySecret = ""
	if ws := c.StartupWarnings(); len(ws) != 0 {
		t.Fatalf("NZ::Use-Peer-IP is not a header: %v", ws)
	}
}

func TestConfigRealIPHeaderWarning(t *testing.T) {
	c := &Config{}
	if w := c.RealIPHeaderWarning("web_real_ip_header", "", "X-Real-IP"); !strings.Contains(w, "trusted_proxies is empty") {
		t.Fatalf("want warning, got %q", w)
	}
	if w := c.RealIPHeaderWarning("web_real_ip_header", "X-Real-IP", "X-Real-IP"); w != "" {
		t.Fatalf("unchanged header must not warn: %q", w)
	}
	if w := c.RealIPHeaderWarning("web_real_ip_header", "X-Real-IP", ""); w != "" {
		t.Fatalf("clearing the header must not warn: %q", w)
	}
	if err := c.SetTrustedProxies([]string{"172.24.0.1"}); err != nil {
		t.Fatal(err)
	}
	if w := c.RealIPHeaderWarning("web_real_ip_header", "", "X-Real-IP"); w != "" {
		t.Fatalf("configured trusted_proxies must not warn: %q", w)
	}
}

func TestProxyAuthenticatedConstantTimeMatch(t *testing.T) {
	c := &Config{TrustedProxySecret: "correct-secret"}
	cases := []struct {
		vals []string
		want bool
	}{
		{nil, false},
		{[]string{""}, false},
		{[]string{"wrong"}, false},
		{[]string{"correct-secret-but-longer"}, false},
		{[]string{"correct-secret", "correct-secret"}, false},
		{[]string{"correct-secret"}, true},
		{[]string{" correct-secret "}, true},
	}
	for _, tc := range cases {
		if got := c.ProxyAuthenticated(tc.vals); got != tc.want {
			t.Errorf("ProxyAuthenticated(%q) = %v, want %v", tc.vals, got, tc.want)
		}
	}
}
