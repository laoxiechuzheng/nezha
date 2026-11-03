package utils

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net/netip"
	"strings"
)

// DefaultTrustedProxies is used when trusted_proxies is not configured: only
// a reverse proxy on the same host (loopback) may vouch for the client IP.
var DefaultTrustedProxies = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
}

// ParseTrustedProxies parses CIDRs or bare IPs (a bare IP means a single
// host). Entries may also be comma separated inside one string.
func ParseTrustedProxies(entries []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, entry := range entries {
		for _, raw := range strings.Split(entry, ",") {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			if strings.Contains(raw, "/") {
				p, err := netip.ParsePrefix(raw)
				if err != nil {
					return nil, fmt.Errorf("invalid trusted proxy %q: %w", raw, err)
				}
				addr := p.Addr()
				if addr.Is4In6() {
					// ::ffff:a.b.c.d/N (N>=96) describes IPv4 space; peers are
					// unmapped before matching, so store the IPv4 form.
					if p.Bits() < 96 {
						return nil, fmt.Errorf("invalid trusted proxy %q: IPv4-mapped prefix shorter than /96", raw)
					}
					p = netip.PrefixFrom(addr.Unmap(), p.Bits()-96)
				}
				out = append(out, p.Masked())
				continue
			}
			addr, err := netip.ParseAddr(raw)
			if err != nil {
				return nil, fmt.Errorf("invalid trusted proxy %q: %w", raw, err)
			}
			addr = addr.Unmap().WithZone("")
			out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}
	return out, nil
}

// ParseRemoteAddr extracts the IP from a transport peer address such as
// "1.2.3.4:5678", "[2001:db8::1]:443" or a bare IP. IPv4-mapped IPv6
// addresses are unmapped and zones dropped so one host always maps to one key.
func ParseRemoteAddr(addr string) (netip.Addr, bool) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return netip.Addr{}, false
	}
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		return normalizeAddr(ap.Addr())
	}
	// Bare IPs, optionally bracketed ("[2001:db8::1]").
	if ip, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]")); err == nil {
		return normalizeAddr(ip)
	}
	return netip.Addr{}, false
}

func normalizeAddr(ip netip.Addr) (netip.Addr, bool) {
	ip = ip.Unmap().WithZone("")
	if !ip.IsValid() || ip.IsUnspecified() {
		return netip.Addr{}, false
	}
	return ip, true
}

func isTrusted(ip netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// ResolveClientIP returns the client IP that WAF accounting and session
// binding must key on.
//
//   - The transport peer is the default and the only thing an untrusted
//     client cannot forge.
//   - header is honoured only when the peer itself is a trusted proxy;
//     otherwise any client could rotate the header to dodge bans or frame
//     other addresses.
//   - headerValues may hold several values and/or comma separated lists
//     (X-Forwarded-For style). They are walked right to left and the first
//     address that is not a trusted proxy wins, because entries to its left
//     were appended by parties we do not trust.
//   - A missing header falls back to the peer; a malformed entry also falls
//     back to the peer (fail towards the unforgeable value).
//
// ok is false only when the peer itself cannot be parsed and no trusted
// header could replace it.
func ResolveClientIP(peer netip.Addr, header string, headerValues []string, trusted []netip.Prefix) (netip.Addr, bool) {
	peer, peerOK := normalizeAddr(peer)
	if !peerOK || header == "" || !isTrusted(peer, trusted) {
		return peer, peerOK
	}

	var entries []string
	for _, v := range headerValues {
		entries = append(entries, strings.Split(v, ",")...)
	}

	var leftmostTrusted netip.Addr
	sawEntry := false
	for i := len(entries) - 1; i >= 0; i-- {
		raw := strings.TrimSpace(entries[i])
		if raw == "" {
			continue
		}
		sawEntry = true
		ip, ok := ParseRemoteAddr(strings.Trim(raw, `"`))
		if !ok {
			return peer, true
		}
		if !isTrusted(ip, trusted) {
			return ip, true
		}
		leftmostTrusted = ip
	}
	if sawEntry && leftmostTrusted.IsValid() {
		// Every hop is a trusted proxy: the request originated on a trusted
		// host, use the original client entry.
		return leftmostTrusted, true
	}
	return peer, true
}

// ProxySecretMatches reports whether values carries exactly one value equal
// to secret. It is the shared-secret check a trusted reverse proxy must pass
// before its real-IP header is believed. Both sides are hashed first so the
// comparison is constant time regardless of the presented length; an empty
// secret never matches.
func ProxySecretMatches(secret string, values []string) bool {
	if secret == "" || len(values) != 1 {
		return false
	}
	got := sha256.Sum256([]byte(strings.TrimSpace(values[0])))
	want := sha256.Sum256([]byte(secret))
	return subtle.ConstantTimeCompare(got[:], want[:]) == 1
}

// MaskAddr truncates ip to v4Bits (IPv4) or v6Bits (IPv6) leading bits.
// Out of range values leave the address untouched. IPv4-mapped IPv6 is
// treated as IPv4 and zones are dropped.
func MaskAddr(ip netip.Addr, v4Bits, v6Bits int) netip.Addr {
	ip = ip.Unmap().WithZone("")
	bits := v6Bits
	if ip.Is4() {
		bits = v4Bits
	}
	if !ip.IsValid() || bits < 0 || bits >= ip.BitLen() {
		return ip
	}
	return netip.PrefixFrom(ip, bits).Masked().Addr()
}
