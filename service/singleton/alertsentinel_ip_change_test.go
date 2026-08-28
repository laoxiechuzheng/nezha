package singleton

import (
	"testing"

	"github.com/nezhahq/nezha/model"
)

func TestIPChangeIncident(t *testing.T) {
	alert := &model.AlertRule{Rules: []*model.Rule{
		{Type: "ip_change", LastIPChange: map[uint64]model.IPChange{1: {Previous: "old", Current: "new"}}},
	}}

	if change, ok := ipChangeIncident(alert, []bool{false}, 1); !ok || change.Previous != "old" || change.Current != "new" {
		t.Fatalf("pure ip_change failure must be an incident: %+v ok=%v", change, ok)
	}
	if _, ok := ipChangeIncident(alert, []bool{true}, 1); ok {
		t.Fatal("passing sample must not be an incident")
	}
	if _, ok := ipChangeIncident(alert, []bool{false}, 2); ok {
		t.Fatal("no recorded change must not be an incident")
	}
	if _, ok := ipChangeIncident(alert, nil, 1); ok {
		t.Fatal("empty sample must not be an incident")
	}

	mixed := &model.AlertRule{Rules: []*model.Rule{{Type: "ip_change"}, {Type: "cpu", Duration: 10}}}
	if _, ok := ipChangeIncident(mixed, []bool{false, false}, 1); ok {
		t.Fatal("mixed failure must not use ip_change event semantics")
	}
}
