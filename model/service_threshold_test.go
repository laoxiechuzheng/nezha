package model

import "testing"

func TestServiceEffectiveFailureThreshold(t *testing.T) {
	if got := (&Service{}).EffectiveFailureThreshold(); got != DefaultServiceFailureThreshold {
		t.Fatalf("zero threshold resolved to %d, want %d", got, DefaultServiceFailureThreshold)
	}

	if got := (&Service{FailureThreshold: 12}).EffectiveFailureThreshold(); got != 12 {
		t.Fatalf("configured threshold resolved to %d, want 12", got)
	}
}
