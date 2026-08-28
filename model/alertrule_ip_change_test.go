package model

import "testing"

func TestAlertRuleIPChange_CheckUsesLastSampleOnly(t *testing.T) {
	rule := &AlertRule{Rules: []*Rule{{Type: "ip_change"}}}

	if got := rule.RetentionWindow(); got != 1 {
		t.Fatalf("RetentionWindow()=%d, want 1", got)
	}

	if d, passed := rule.Check([][]bool{{true}, {false}}); d != 1 || passed {
		t.Fatalf("a failing last sample must fail the check: d=%d passed=%v", d, passed)
	}
	if _, passed := rule.Check([][]bool{{false}, {true}}); !passed {
		t.Fatal("a passing last sample must pass the check")
	}

	// Duration 对 ip_change 无意义：即使为 0，也必须只看最后一个采样点。
	rule.Rules[0].Duration = 0
	if _, passed := rule.Check([][]bool{{false}}); passed {
		t.Fatal("Duration:0 ip_change rule must still fail on the last sample")
	}
}

func TestAlertRuleIPChange_IPChangeFor(t *testing.T) {
	rule := &AlertRule{Rules: []*Rule{{Type: "ip_change", LastIPChange: map[uint64]IPChange{
		7: {Previous: "a", Current: "b"},
	}}}}

	change, ok := rule.IPChangeFor(7)
	if !ok || change.Previous != "a" || change.Current != "b" {
		t.Fatalf("IPChangeFor: %+v ok=%v", change, ok)
	}
	if _, ok := rule.IPChangeFor(8); ok {
		t.Fatal("IPChangeFor must not invent a change for unknown servers")
	}
}

func TestAlertRuleIPChange_FailedOnlyOnIPChange(t *testing.T) {
	cases := []struct {
		name  string
		rules []*Rule
		point []bool
		want  bool
	}{
		{"single ip_change fail", []*Rule{{Type: "ip_change"}}, []bool{false}, true},
		{"single ip_change pass", []*Rule{{Type: "ip_change"}}, []bool{true}, false},
		{"mixed both fail", []*Rule{{Type: "ip_change"}, {Type: "cpu", Duration: 10}}, []bool{false, false}, false},
		{"mixed only ip_change fails", []*Rule{{Type: "ip_change"}, {Type: "cpu", Duration: 10}}, []bool{false, true}, true},
		{"mixed only cpu fails", []*Rule{{Type: "ip_change"}, {Type: "cpu", Duration: 10}}, []bool{true, false}, false},
	}
	for _, c := range cases {
		rule := &AlertRule{Rules: c.rules}
		if got := rule.FailedOnlyOnIPChange(c.point); got != c.want {
			t.Fatalf("%s: FailedOnlyOnIPChange()=%v want %v", c.name, got, c.want)
		}
	}
}
