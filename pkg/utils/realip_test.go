package utils

import (
	"net/netip"
	"testing"
)

func mustPrefixes(t *testing.T, entries ...string) []netip.Prefix {
	t.Helper()
	p, err := ParseTrustedProxies(entries)
	if err != nil {
		t.Fatalf("ParseTrustedProxies(%v): %v", entries, err)
	}
	return p
}

func TestParseTrustedProxies(t *testing.T) {
	got := mustPrefixes(t, "172.24.0.1", "10.0.0.0/8, ::1", "::ffff:192.168.0.0/112", " ")
	want := []string{"172.24.0.1/32", "10.0.0.0/8", "::1/128", "192.168.0.0/16"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Fatalf("entry %d = %s, want %s", i, got[i], want[i])
		}
	}

	for _, bad := range []string{"not-an-ip", "10.0.0.0/33", "::ffff:0:0/64"} {
		if _, err := ParseTrustedProxies([]string{bad}); err == nil {
			t.Fatalf("ParseTrustedProxies(%q) must fail", bad)
		}
	}
}

func TestParseRemoteAddr(t *testing.T) {
	cases := map[string]string{
		"203.0.113.7:54321":       "203.0.113.7",
		"[2001:db8::1]:443":       "2001:db8::1",
		"[::ffff:203.0.113.7]:80": "203.0.113.7",
		"[fe80::1%eth0]:80":       "fe80::1",
		"2001:db8::2":             "2001:db8::2",
		"[2001:db8::3]":           "2001:db8::3",
		"198.51.100.1":            "198.51.100.1",
	}
	for in, want := range cases {
		got, ok := ParseRemoteAddr(in)
		if !ok || got.String() != want {
			t.Fatalf("ParseRemoteAddr(%q) = %v,%v want %s", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "unknown", "0.0.0.0:1", "[::]:80", "@", "pipe"} {
		if got, ok := ParseRemoteAddr(bad); ok {
			t.Fatalf("ParseRemoteAddr(%q) = %v, want failure", bad, got)
		}
	}
}

func TestResolveClientIP(t *testing.T) {
	trusted := mustPrefixes(t, "127.0.0.0/8", "::1/128", "172.24.0.1/32", "2001:db8:ffff::/48")
	addr := func(s string) netip.Addr { return netip.MustParseAddr(s) }

	cases := []struct {
		name   string
		peer   netip.Addr
		header string
		values []string
		want   string
	}{
		{"no header configured uses peer", addr("203.0.113.7"), "", []string{"1.1.1.1"}, "203.0.113.7"},
		{"untrusted peer cannot spoof header", addr("203.0.113.7"), "X-Real-IP", []string{"1.1.1.1"}, "203.0.113.7"},
		{"untrusted peer spoofing loopback", addr("203.0.113.7"), "X-Real-IP", []string{"127.0.0.1"}, "203.0.113.7"},
		{"trusted docker gateway with X-Real-IP", addr("172.24.0.1"), "X-Real-IP", []string{"198.51.100.9"}, "198.51.100.9"},
		{"neighbouring bridge address is not trusted", addr("172.24.0.2"), "X-Real-IP", []string{"198.51.100.9"}, "172.24.0.2"},
		{"trusted loopback, header missing -> peer", addr("127.0.0.1"), "X-Real-IP", nil, "127.0.0.1"},
		{"trusted peer, garbage header -> peer", addr("127.0.0.1"), "X-Real-IP", []string{"garbage"}, "127.0.0.1"},
		{"trusted peer, unspecified header -> peer", addr("127.0.0.1"), "X-Real-IP", []string{"0.0.0.0"}, "127.0.0.1"},
		{"XFF right-most untrusted wins over client-supplied left entries", addr("127.0.0.1"), "X-Forwarded-For",
			[]string{"6.6.6.6, 7.7.7.7, 198.51.100.9"}, "198.51.100.9"},
		{"XFF skips trusted hops from the right", addr("127.0.0.1"), "X-Forwarded-For",
			[]string{"6.6.6.6, 198.51.100.9, 172.24.0.1, 127.0.0.1"}, "198.51.100.9"},
		{"XFF split across header lines", addr("127.0.0.1"), "X-Forwarded-For",
			[]string{"6.6.6.6", "198.51.100.9"}, "198.51.100.9"},
		{"XFF all trusted -> left-most", addr("127.0.0.1"), "X-Forwarded-For",
			[]string{"127.0.0.2, 172.24.0.1"}, "127.0.0.2"},
		{"XFF malformed right-most -> peer", addr("127.0.0.1"), "X-Forwarded-For",
			[]string{"198.51.100.9, unknown"}, "127.0.0.1"},
		{"header value with port", addr("127.0.0.1"), "X-Real-IP", []string{"198.51.100.9:61000"}, "198.51.100.9"},
		{"IPv6 client via IPv4 proxy", addr("172.24.0.1"), "X-Real-IP", []string{"2001:db8::42"}, "2001:db8::42"},
		{"bracketed IPv6 with port", addr("::1"), "X-Real-IP", []string{"[2001:db8::42]:443"}, "2001:db8::42"},
		{"IPv4-mapped peer is unmapped before trust check", addr("::ffff:172.24.0.1"), "X-Real-IP", []string{"198.51.100.9"}, "198.51.100.9"},
		{"IPv4-mapped client is unmapped", addr("172.24.0.1"), "X-Real-IP", []string{"::ffff:198.51.100.9"}, "198.51.100.9"},
		{"trusted IPv6 proxy prefix", addr("2001:db8:ffff::5"), "X-Real-IP", []string{"203.0.113.50"}, "203.0.113.50"},
		{"untrusted IPv6 peer", addr("2001:db8:1::5"), "X-Real-IP", []string{"203.0.113.50"}, "2001:db8:1::5"},
		{"quoted value", addr("127.0.0.1"), "X-Real-IP", []string{`"198.51.100.9"`}, "198.51.100.9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ResolveClientIP(tc.peer, tc.header, tc.values, trusted)
			if !ok || got.String() != tc.want {
				t.Fatalf("ResolveClientIP = %v,%v want %s", got, ok, tc.want)
			}
		})
	}
}

func TestResolveClientIPDefaultsTrustLoopbackOnly(t *testing.T) {
	got, _ := ResolveClientIP(netip.MustParseAddr("172.24.0.1"), "X-Real-IP", []string{"198.51.100.9"}, DefaultTrustedProxies)
	if got.String() != "172.24.0.1" {
		t.Fatalf("docker gateway must not be trusted by default, got %s", got)
	}
	got, _ = ResolveClientIP(netip.MustParseAddr("127.0.0.1"), "X-Real-IP", []string{"198.51.100.9"}, DefaultTrustedProxies)
	if got.String() != "198.51.100.9" {
		t.Fatalf("loopback proxy must be trusted by default, got %s", got)
	}
}

func TestResolveClientIPInvalidPeer(t *testing.T) {
	if _, ok := ResolveClientIP(netip.Addr{}, "", nil, DefaultTrustedProxies); ok {
		t.Fatal("an unparsable peer without a trusted header must not resolve")
	}
	if _, ok := ResolveClientIP(netip.Addr{}, "X-Real-IP", []string{"198.51.100.9"}, DefaultTrustedProxies); ok {
		t.Fatal("an unknown peer is never a trusted proxy, so its header must not be used")
	}
}

func TestMaskAddr(t *testing.T) {
	cases := []struct {
		in     string
		v4, v6 int
		want   string
	}{
		{"198.51.100.77", 24, 64, "198.51.100.0"},
		{"198.51.100.77", 32, 64, "198.51.100.77"},
		{"::ffff:198.51.100.77", 24, 64, "198.51.100.0"},
		{"2001:db8:1:2:3:4:5:6", 24, 64, "2001:db8:1:2::"},
		{"2001:db8:1:2:3:4:5:6", 24, 128, "2001:db8:1:2:3:4:5:6"},
		{"fe80::1%eth0", 24, 64, "fe80::"},
	}
	for _, tc := range cases {
		if got := MaskAddr(netip.MustParseAddr(tc.in), tc.v4, tc.v6).String(); got != tc.want {
			t.Errorf("MaskAddr(%s,%d,%d) = %s, want %s", tc.in, tc.v4, tc.v6, got, tc.want)
		}
	}
}

func TestProxySecretMatches(t *testing.T) {
	if ProxySecretMatches("", []string{""}) {
		t.Fatal("empty secret must never match")
	}
	if !ProxySecretMatches("abc", []string{"abc"}) || ProxySecretMatches("abc", []string{"abcd"}) || ProxySecretMatches("abc", []string{"abc", "abc"}) {
		t.Fatal("unexpected match result")
	}
}
