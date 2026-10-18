package model

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func offlineTestServer(id uint64, reportedAt time.Time) *Server {
	return &Server{
		Common:     Common{ID: id},
		Host:       &Host{},
		State:      &HostState{},
		LastActive: reportedAt,
	}
}

func offlineTestRule(duration uint64) *AlertRule {
	return &AlertRule{Rules: []*Rule{{
		Type:     "offline",
		Duration: duration,
		Cover:    RuleCoverAll,
	}}}
}

func offlineTestSamples(count int) [][]bool {
	samples := make([][]bool, count)
	for i := range samples {
		samples[i] = []bool{}
	}
	return samples
}

func offlineTestRepeatedSamples(count int, values ...bool) [][]bool {
	samples := make([][]bool, count)
	for i := range samples {
		samples[i] = append([]bool(nil), values...)
	}
	return samples
}

func TestRuleOfflineSnapshotUsesConfiguredDuration(t *testing.T) {
	tests := []struct {
		name     string
		duration uint64
		age      time.Duration
		want     bool
	}{
		{name: "duration 10 before threshold", duration: 10, age: 9 * time.Second, want: true},
		{name: "duration 10 after threshold", duration: 10, age: 11 * time.Second, want: false},
		{name: "duration 30 before threshold", duration: 30, age: 29 * time.Second, want: true},
		{name: "duration 30 after threshold", duration: 30, age: 31 * time.Second, want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := offlineTestServer(1, time.Now().Add(-test.age))
			rule := offlineTestRule(test.duration).Rules[0]

			require.Equal(t, test.want, rule.Snapshot(nil, server, nil))
		})
	}
}

func TestRuleOfflineSnapshotHonorsCover(t *testing.T) {
	tests := []struct {
		name   string
		server uint64
		cover  uint64
		ignore map[uint64]bool
		want   bool
	}{
		{
			name:   "cover all excludes ignored server",
			server: 25,
			cover:  RuleCoverAll,
			ignore: map[uint64]bool{25: true},
			want:   true,
		},
		{
			name:   "cover all monitors other server",
			server: 26,
			cover:  RuleCoverAll,
			ignore: map[uint64]bool{25: true},
			want:   false,
		},
		{
			name:   "ignore all monitors selected server",
			server: 25,
			cover:  RuleCoverIgnoreAll,
			ignore: map[uint64]bool{25: true},
			want:   false,
		},
		{
			name:   "ignore all skips unselected server",
			server: 26,
			cover:  RuleCoverIgnoreAll,
			ignore: map[uint64]bool{25: true},
			want:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := offlineTestServer(test.server, time.Now().Add(-4*time.Second))
			rule := &Rule{
				Type:     "offline",
				Duration: 3,
				Cover:    test.cover,
				Ignore:   test.ignore,
			}

			require.Equal(t, test.want, rule.Snapshot(nil, server, nil))
		})
	}
}

func TestRuleOfflineSnapshotFallbacksAreHealthy(t *testing.T) {
	t.Run("nil state is evaluated from report time", func(t *testing.T) {
		server := offlineTestServer(1, time.Now())
		server.State = nil
		rule := offlineTestRule(3).Rules[0]

		require.True(t, rule.Snapshot(nil, server, nil))
		require.Nil(t, server.RuntimeSnapshot().State)
	})

	t.Run("nil state with expired report fails", func(t *testing.T) {
		server := offlineTestServer(1, time.Now().Add(-4*time.Second))
		server.State = nil
		rule := offlineTestRule(3).Rules[0]

		require.False(t, rule.Snapshot(nil, server, nil))
		require.Nil(t, server.RuntimeSnapshot().State)
	})

	for _, duration := range []uint64{0, MaxAlertRuleDuration + 1} {
		t.Run("invalid duration", func(t *testing.T) {
			server := offlineTestServer(1, time.Now().Add(-10*time.Second))
			rule := offlineTestRule(duration).Rules[0]

			require.True(t, rule.Snapshot(nil, server, nil))
		})
	}
}

func TestAlertRuleOfflineCheckUsesLastSample(t *testing.T) {
	rule := offlineTestRule(10)

	duration, passed := rule.Check([][]bool{{false}})
	require.Equal(t, 10, duration)
	require.False(t, passed, "an already-expired offline sample must fail immediately")

	duration, passed = rule.Check([][]bool{{false}, {true}})
	require.Zero(t, duration)
	require.True(t, passed, "a fresh report must recover on the next check")
}

func TestAlertRuleOfflineCheckIgnoresMissingLastPoint(t *testing.T) {
	tests := []struct {
		name     string
		duration uint64
		points   [][]bool
	}{
		{name: "empty history", duration: 10},
		{name: "missing rule column", duration: 10, points: offlineTestSamples(10)},
		{name: "zero duration", duration: 0, points: [][]bool{{false}}},
		{name: "overflow duration", duration: MaxAlertRuleDuration + 1, points: [][]bool{{false}}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			duration, passed := offlineTestRule(test.duration).Check(test.points)
			require.Zero(t, duration)
			require.True(t, passed)
		})
	}
}

func TestAlertRuleOfflineMixedWaitsForGeneralWindow(t *testing.T) {
	rule := &AlertRule{Rules: []*Rule{
		{Type: "offline", Duration: 30, Cover: RuleCoverAll},
		{Type: "cpu", Duration: 10, Cover: RuleCoverAll},
	}}

	duration, passed := rule.Check(offlineTestRepeatedSamples(9, false, false))
	require.Equal(t, 30, duration)
	require.True(t, passed, "the ordinary rule window is not full yet")

	samples := offlineTestRepeatedSamples(10, false, false)
	duration, passed = rule.Check(samples)
	require.Equal(t, 30, duration)
	require.False(t, passed, "offline and general rules must both fail once the general window is full")
}

func TestAlertRuleOfflineRetentionWindow(t *testing.T) {
	tests := []struct {
		name string
		rule *AlertRule
		want int
	}{
		{name: "offline", rule: offlineTestRule(30), want: 1},
		{name: "zero duration", rule: offlineTestRule(0), want: 0},
		{name: "overflow duration", rule: offlineTestRule(MaxAlertRuleDuration + 1), want: 0},
		{name: "general unchanged", rule: &AlertRule{Rules: []*Rule{{Type: "cpu", Duration: 10}}}, want: 10},
		{
			name: "mixed takes general window",
			rule: &AlertRule{Rules: []*Rule{
				{Type: "offline", Duration: 30},
				{Type: "cpu", Duration: 10},
			}},
			want: 10,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, test.rule.RetentionWindow())
		})
	}
}
