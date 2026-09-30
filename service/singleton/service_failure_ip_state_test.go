package singleton

import "testing"

func TestUpdateServiceFailureIPTriggersOnceForChangedICMPAddress(t *testing.T) {
	status := &serviceTaskStatus{inFailureState: true, lastFailureIP: "192.0.2.10"}
	changedIP := extractServiceFailureIP("icmp ping target=192.0.2.20: packets recv 0")
	if !updateServiceFailureIP(status, changedIP) {
		t.Fatal("changed ICMP failure IP did not request a repeated failure action")
	}
	if status.lastFailureIP != "192.0.2.20" {
		t.Fatalf("last failure IP = %q, want 192.0.2.20", status.lastFailureIP)
	}
	if updateServiceFailureIP(status, changedIP) {
		t.Fatal("unchanged ICMP failure IP requested a duplicate failure action")
	}
}

func TestUpdateServiceFailureIPDoesNotRetriggerWithoutKnownFailedAddress(t *testing.T) {
	tests := []struct {
		name       string
		inFailure  bool
		previousIP string
		currentIP  string
		wantIP     string
	}{
		{name: "healthy service", previousIP: "192.0.2.10", currentIP: "192.0.2.20", wantIP: "192.0.2.10"},
		{name: "unresolved failure", inFailure: true, previousIP: "192.0.2.10", wantIP: "192.0.2.10"},
		{name: "first known IP", inFailure: true, currentIP: "192.0.2.20", wantIP: "192.0.2.20"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := &serviceTaskStatus{inFailureState: tt.inFailure, lastFailureIP: tt.previousIP}
			if updateServiceFailureIP(status, tt.currentIP) {
				t.Fatal("failure action retriggered without a change between known failed IPs")
			}
			if status.lastFailureIP != tt.wantIP {
				t.Fatalf("last failure IP = %q, want %q", status.lastFailureIP, tt.wantIP)
			}
		})
	}
}
