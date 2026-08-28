package model

import "testing"

func newIPChangeServer(id uint64, ipv4, ipv6 string) *Server {
	s := &Server{Common: Common{ID: id}}
	s.GeoIP = &GeoIP{IP: IP{IPv4Addr: ipv4, IPv6Addr: ipv6}}
	return s
}

func TestRuleIPChange_BaselineDoesNotTrigger(t *testing.T) {
	u := &Rule{Type: "ip_change"}
	s := newIPChangeServer(1, "42.200.172.158", "")

	if got := u.Snapshot(nil, s, nil); !got {
		t.Fatalf("first observation must establish a baseline without failing")
	}
	if got := u.LastIP[1]; got != "42.200.172.158" {
		t.Fatalf("baseline IP not recorded: %q", got)
	}
	if _, ok := u.LastIPChange[1]; ok {
		t.Fatalf("baseline must not record a change")
	}
}

func TestRuleIPChange_TriggersOncePerChange(t *testing.T) {
	u := &Rule{Type: "ip_change"}
	s := newIPChangeServer(1, "42.200.172.158", "")

	if got := u.Snapshot(nil, s, nil); !got {
		t.Fatal("baseline snapshot must pass")
	}

	s.GeoIP.IP.IPv4Addr = "42.200.231.72"
	if got := u.Snapshot(nil, s, nil); got {
		t.Fatal("changed IP must fail the snapshot")
	}
	change, ok := u.LastIPChange[1]
	if !ok || change.Previous != "42.200.172.158" || change.Current != "42.200.231.72" {
		t.Fatalf("unexpected change record: %+v ok=%v", change, ok)
	}

	if got := u.Snapshot(nil, s, nil); !got {
		t.Fatal("unchanged IP must pass on the next snapshot")
	}
	if _, ok := u.LastIPChange[1]; ok {
		t.Fatal("change record must be cleared once the IP is stable")
	}

	s.GeoIP.IP.IPv4Addr = "42.200.240.10"
	if got := u.Snapshot(nil, s, nil); got {
		t.Fatal("a second change must fail again")
	}
}

func TestRuleIPChange_EmptyValuesDoNotTrigger(t *testing.T) {
	u := &Rule{Type: "ip_change"}
	s := newIPChangeServer(1, "", "")

	if got := u.Snapshot(nil, s, nil); !got {
		t.Fatal("empty baseline must pass")
	}

	s.GeoIP.IP.IPv4Addr = "42.200.172.158"
	if got := u.Snapshot(nil, s, nil); !got {
		t.Fatal("first non-empty report must establish a baseline without failing")
	}

	s.GeoIP.IP.IPv4Addr = ""
	if got := u.Snapshot(nil, s, nil); !got {
		t.Fatal("empty report must not be treated as a change")
	}

	s.GeoIP.IP.IPv4Addr = "42.200.231.72"
	if got := u.Snapshot(nil, s, nil); !got {
		t.Fatal("re-report after an empty state must establish a baseline without failing")
	}
}

func TestRuleIPChange_IPv6Fallback(t *testing.T) {
	u := &Rule{Type: "ip_change"}
	s := newIPChangeServer(1, "", "2400:abcd::1")

	if got := u.Snapshot(nil, s, nil); !got {
		t.Fatal("IPv6 baseline must pass")
	}

	s.GeoIP.IP.IPv6Addr = "2400:abcd::2"
	if got := u.Snapshot(nil, s, nil); got {
		t.Fatal("IPv6 change must fail when IPv4 is empty")
	}
	change, ok := u.LastIPChange[1]
	if !ok || change.Previous != "2400:abcd::1" || change.Current != "2400:abcd::2" {
		t.Fatalf("unexpected IPv6 change record: %+v ok=%v", change, ok)
	}
}

func TestRuleIPChange_CoverIgnore(t *testing.T) {
	s := newIPChangeServer(1, "42.200.172.158", "")

	excluded := &Rule{Type: "ip_change", Cover: RuleCoverAll, Ignore: map[uint64]bool{1: true}}
	if got := excluded.Snapshot(nil, s, nil); !got {
		t.Fatal("ignored server must pass")
	}
	s.GeoIP.IP.IPv4Addr = "42.200.231.72"
	if got := excluded.Snapshot(nil, s, nil); !got {
		t.Fatal("ignored server must keep passing even after an IP change")
	}

	notIncluded := &Rule{Type: "ip_change", Cover: RuleCoverIgnoreAll, Ignore: map[uint64]bool{2: true}}
	if got := notIncluded.Snapshot(nil, s, nil); !got {
		t.Fatal("non-included server must pass")
	}
	s.GeoIP.IP.IPv4Addr = "42.200.240.10"
	if got := notIncluded.Snapshot(nil, s, nil); !got {
		t.Fatal("non-included server must keep passing even after an IP change")
	}
}
