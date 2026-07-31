package singleton

import (
	"fmt"
	"testing"
	"time"

	"github.com/nezhahq/nezha/model"
	pb "github.com/nezhahq/nezha/proto"
	"github.com/stretchr/testify/require"
)

func TestClassifyServiceError(t *testing.T) {
	tests := []struct {
		name       string
		successful bool
		message    string
		want       uint8
	}{
		{name: "success", successful: true, message: "timeout", want: model.ServiceErrorNone},
		{name: "timeout", message: "i/o timeout", want: model.ServiceErrorTimeout},
		{name: "refused", message: "connect: connection refused", want: model.ServiceErrorRefused},
		{name: "dns", message: "lookup test: no such host", want: model.ServiceErrorDNS},
		{name: "unreachable", message: "network is unreachable", want: model.ServiceErrorUnreachable},
		{name: "invalid", message: "missing port in address", want: model.ServiceErrorInvalidTarget},
		{name: "other", message: "unexpected EOF", want: model.ServiceErrorOther},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, classifyServiceError(tt.successful, tt.message))
		})
	}
}

func TestRecentResultsByServerIsIncrementalAndBounded(t *testing.T) {
	ss := &ServiceSentinel{
		latestResults: make(map[uint64]map[uint64]model.ServiceLatestResult),
		recentResults: make(map[uint64]map[uint64][]model.ServiceLatestResult),
	}
	service := &model.Service{Common: model.Common{ID: 7}, Name: "tcp", Duration: 5}
	server := &model.Server{Common: model.Common{ID: 9}, Name: "node"}
	base := time.UnixMilli(1_700_000_000_000)
	for i := 0; i < 8200; i++ {
		ss.setLatestResult(service, server, &pb.TaskResult{Successful: i%2 == 0, Data: fmt.Sprintf("result-%d", i)}, base.Add(time.Duration(i)*time.Millisecond))
	}

	all := ss.RecentResultsByServer(server.ID, 0)
	require.Len(t, all, 8192)
	require.Equal(t, base.Add(8*time.Millisecond).UnixMilli(), all[0].Timestamp)
	since := base.Add(8197 * time.Millisecond).UnixMilli()
	incremental := ss.RecentResultsByServer(server.ID, since)
	require.Len(t, incremental, 2)
	require.Greater(t, incremental[0].Timestamp, since)
	require.Len(t, ss.LatestResultsByServer(server.ID), 1)
}

func TestRecentResultsByServerKeepsIndependentServiceWindows(t *testing.T) {
	ss := &ServiceSentinel{
		latestResults: make(map[uint64]map[uint64]model.ServiceLatestResult),
		recentResults: make(map[uint64]map[uint64][]model.ServiceLatestResult),
	}
	server := &model.Server{Common: model.Common{ID: 9}, Name: "node"}
	first := &model.Service{Common: model.Common{ID: 7}, Name: "tcp-a", Duration: 5}
	second := &model.Service{Common: model.Common{ID: 8}, Name: "tcp-b", Duration: 5}
	base := time.UnixMilli(1_700_000_000_000)
	for i := 0; i < 8200; i++ {
		at := base.Add(time.Duration(i) * time.Millisecond)
		ss.setLatestResult(first, server, &pb.TaskResult{Successful: true}, at)
		ss.setLatestResult(second, server, &pb.TaskResult{Successful: true}, at)
	}

	all := ss.RecentResultsByServer(server.ID, 0)
	require.Len(t, all, 8192*2)
	counts := map[uint64]int{}
	for _, item := range all {
		counts[item.ServiceID]++
	}
	require.Equal(t, 8192, counts[first.ID])
	require.Equal(t, 8192, counts[second.ID])
}
