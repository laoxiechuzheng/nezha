package singleton

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/nezhahq/nezha/model"
)

func TestAcceptGeoIPReportConcurrentDuplicateChangesOnce(t *testing.T) {
	servers := NewEmptyServerClassForTest()
	server := &model.Server{
		Common: model.Common{ID: 7},
		GeoIP:  &model.GeoIP{IP: model.IP{IPv4Addr: "209.9.201.57"}},
	}
	servers.InsertForTest(server)

	const reporters = 64
	var changed atomic.Int32
	var wg sync.WaitGroup
	wg.Add(reporters)
	for range reporters {
		go func() {
			defer wg.Done()
			_, previous, accepted, err := servers.AcceptGeoIPReport(7, model.GeoIP{
				IP: model.IP{IPv4Addr: "42.200.172.209"},
			})
			if err != nil {
				t.Errorf("AcceptGeoIPReport: %v", err)
				return
			}
			if accepted {
				if previous.IP.IPv4Addr != "209.9.201.57" {
					t.Errorf("previous IPv4 = %q, want original address", previous.IP.IPv4Addr)
				}
				changed.Add(1)
			}
		}()
	}
	wg.Wait()

	if got := changed.Load(); got != 1 {
		t.Fatalf("accepted changes = %d, want exactly 1", got)
	}
	if got := server.GeoIP.IP.IPv4Addr; got != "42.200.172.209" {
		t.Fatalf("stored IPv4 = %q, want new address", got)
	}
}

func TestConfiguredDNSServersTrimsWhitespaceAndEmptyEntries(t *testing.T) {
	got := configuredDNSServers("1.1.1.1:53, 8.8.8.8:53,,")
	want := []string{"1.1.1.1:53", "8.8.8.8:53"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("configured DNS servers = %v, want %v", got, want)
	}
}

func TestAcceptGeoIPReportIgnoresIPv6OnlyChange(t *testing.T) {
	servers := NewEmptyServerClassForTest()
	server := &model.Server{
		Common: model.Common{ID: 8},
		GeoIP: &model.GeoIP{IP: model.IP{
			IPv4Addr: "192.0.2.10",
			IPv6Addr: "2001:db8::10",
		}},
	}
	servers.InsertForTest(server)

	_, _, changed, err := servers.AcceptGeoIPReport(8, model.GeoIP{IP: model.IP{
		IPv4Addr: "192.0.2.10",
		IPv6Addr: "2001:db8::20",
	}})
	if err != nil {
		t.Fatalf("AcceptGeoIPReport: %v", err)
	}
	if changed {
		t.Fatal("IPv6-only change must not trigger IPv4 DDNS or notification")
	}
}
