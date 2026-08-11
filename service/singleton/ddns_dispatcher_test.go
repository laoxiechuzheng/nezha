package singleton

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/pkg/ddns"
)

func TestDDNSDispatcherRetriesFailedUpdateUntilSuccess(t *testing.T) {
	var attempts atomic.Int32
	succeeded := make(chan struct{})
	dispatcher := newDDNSDispatcher(1, func(int) time.Duration {
		return time.Millisecond
	}, func(context.Context, *ddns.Provider, string) error {
		if attempts.Add(1) == 1 {
			return errors.New("temporary provider failure")
		}
		close(succeeded)
		return nil
	})
	t.Cleanup(dispatcher.close)

	dispatcher.enqueue(ddnsDispatchTask{
		serverID:  7,
		profileID: 3,
		domain:    "node.example.com",
		provider:  &ddns.Provider{IPAddrs: &model.IP{IPv4Addr: "42.200.172.209"}},
	})

	select {
	case <-succeeded:
	case <-time.After(time.Second):
		t.Fatal("DDNS update was not retried after the temporary failure")
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("attempts = %d, want one failure followed by one success", got)
	}
}

func TestDDNSDispatcherSupersedesStaleAddressForSameDomain(t *testing.T) {
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	observed := make(chan string, 2)
	var calls atomic.Int32
	dispatcher := newDDNSDispatcher(1, func(int) time.Duration {
		return time.Millisecond
	}, func(_ context.Context, provider *ddns.Provider, _ string) error {
		observed <- provider.IPAddrs.IPv4Addr
		if calls.Add(1) == 1 {
			close(firstStarted)
			<-releaseFirst
		}
		return nil
	})
	t.Cleanup(dispatcher.close)

	dispatcher.enqueue(ddnsDispatchTask{
		serverID: 7, profileID: 3, domain: "node.example.com",
		provider: &ddns.Provider{IPAddrs: &model.IP{IPv4Addr: "192.0.2.10"}},
	})
	<-firstStarted
	dispatcher.enqueue(ddnsDispatchTask{
		serverID: 7, profileID: 3, domain: "node.example.com",
		provider: &ddns.Provider{IPAddrs: &model.IP{IPv4Addr: "192.0.2.20"}},
	})
	close(releaseFirst)

	var got []string
	for range 2 {
		select {
		case ip := <-observed:
			got = append(got, ip)
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for DDNS attempts; observed=%v", got)
		}
	}
	if got[0] != "192.0.2.10" || got[1] != "192.0.2.20" {
		t.Fatalf("observed addresses = %v, want old in-flight attempt followed by newest address", got)
	}
}

func TestDDNSDispatcherLimitsGlobalConcurrency(t *testing.T) {
	const limit = 2
	release := make(chan struct{})
	started := make(chan struct{}, 6)
	var active atomic.Int32
	var maximum atomic.Int32
	dispatcher := newDDNSDispatcher(limit, nil, func(_ context.Context, _ *ddns.Provider, _ string) error {
		current := active.Add(1)
		for {
			old := maximum.Load()
			if current <= old || maximum.CompareAndSwap(old, current) {
				break
			}
		}
		started <- struct{}{}
		<-release
		active.Add(-1)
		return nil
	})
	t.Cleanup(dispatcher.close)

	for i := range 6 {
		dispatcher.enqueue(ddnsDispatchTask{
			serverID: uint64(i + 1), profileID: uint64(i + 1), domain: "node.example.com",
			provider: &ddns.Provider{IPAddrs: &model.IP{IPv4Addr: "192.0.2.10"}},
		})
	}
	for range limit {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("workers did not start")
		}
	}
	if got := maximum.Load(); got != limit {
		t.Fatalf("maximum concurrency = %d, want %d", got, limit)
	}
	close(release)
}

func TestDDNSDispatcherCancelServerStopsRetries(t *testing.T) {
	firstAttempt := make(chan struct{})
	var attempts atomic.Int32
	dispatcher := newDDNSDispatcher(1, func(int) time.Duration {
		return 200 * time.Millisecond
	}, func(context.Context, *ddns.Provider, string) error {
		if attempts.Add(1) == 1 {
			close(firstAttempt)
		}
		return errors.New("temporary failure")
	})
	t.Cleanup(dispatcher.close)

	dispatcher.enqueue(ddnsDispatchTask{
		serverID: 7, profileID: 3, domain: "node.example.com",
		provider: &ddns.Provider{IPAddrs: &model.IP{IPv4Addr: "192.0.2.10"}},
	})
	<-firstAttempt
	dispatcher.cancelServer(7)
	time.Sleep(50 * time.Millisecond)
	if got := attempts.Load(); got != 1 {
		t.Fatalf("attempts after server cancellation = %d, want 1", got)
	}
}
