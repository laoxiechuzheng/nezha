package singleton

import "testing"

func TestExtractServiceFailureIP(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{name: "legacy TCP error", data: "dial tcp 192.0.2.10:443: connect: connection refused", want: "192.0.2.10"},
		{name: "ICMP IPv4 failure", data: "icmp ping target=192.0.2.20: packets recv 0", want: "192.0.2.20"},
		{name: "ICMP IPv6 failure", data: "icmp ping target=2001:db8::20: packets recv 0", want: "2001:db8::20"},
		{name: "invalid target is ignored", data: "icmp ping target=not-an-ip: packets recv 0"},
		{name: "unrecognized error is ignored", data: "pockets recv 0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractServiceFailureIP(tt.data); got != tt.want {
				t.Fatalf("extractServiceFailureIP(%q) = %q, want %q", tt.data, got, tt.want)
			}
		})
	}
}
