package geoip

import "testing"

func TestLookupCountryCode(t *testing.T) {
	tests := []struct {
		name   string
		record map[string]any
		want   string
	}{
		{
			name:   "ipinfo country string",
			record: map[string]any{"country": "US"},
			want:   "US",
		},
		{
			name: "geolite2 country object",
			record: map[string]any{
				"country": map[string]any{"iso_code": "CN"},
			},
			want: "CN",
		},
		{
			name:   "ipinfo continent fallback",
			record: map[string]any{"continent": "EU"},
			want:   "EU",
		},
		{
			name: "geolite2 continent fallback",
			record: map[string]any{
				"continent": map[string]any{"code": "AS"},
			},
			want: "AS",
		},
		{
			name: "country takes precedence",
			record: map[string]any{
				"country":   map[string]any{"iso_code": "JP"},
				"continent": map[string]any{"code": "AS"},
			},
			want: "JP",
		},
		{
			name:   "missing",
			record: map[string]any{},
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := lookupCountryCode(tt.record); got != tt.want {
				t.Fatalf("lookupCountryCode() = %q, want %q", got, tt.want)
			}
		})
	}
}
