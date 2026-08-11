package singleton

import (
	"context"
	"fmt"
	"log"
	"math/rand/v2"
	"strings"
	"sync"
	"time"

	"github.com/nezhahq/nezha/pkg/ddns"
)

const (
	defaultDDNSConcurrency = 4
	ddnsAttemptTimeout     = 45 * time.Second
)

type ddnsDispatchTask struct {
	serverID   uint64
	profileID  uint64
	domain     string
	provider   *ddns.Provider
	dnsServers []string
}

type ddnsDispatchState struct {
	task     ddnsDispatchTask
	version  uint64
	wake     chan struct{}
	ctx      context.Context
	cancel   context.CancelFunc
	canceled bool
}

type ddnsDispatcher struct {
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex
	tasks      map[string]*ddnsDispatchState
	semaphore  chan struct{}
	retryDelay func(int) time.Duration
	execute    func(context.Context, *ddns.Provider, string) error
	wg         sync.WaitGroup
}

func newDDNSDispatcher(
	concurrency int,
	retryDelay func(int) time.Duration,
	execute func(context.Context, *ddns.Provider, string) error,
) *ddnsDispatcher {
	if concurrency < 1 {
		concurrency = 1
	}
	if retryDelay == nil {
		retryDelay = defaultDDNSRetryDelay
	}
	if execute == nil {
		execute = func(ctx context.Context, provider *ddns.Provider, domain string) error {
			return provider.UpdateDomain(ctx, domain)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &ddnsDispatcher{
		ctx:        ctx,
		cancel:     cancel,
		tasks:      make(map[string]*ddnsDispatchState),
		semaphore:  make(chan struct{}, concurrency),
		retryDelay: retryDelay,
		execute:    execute,
	}
}

func defaultDDNSRetryDelay(attempt int) time.Duration {
	delay := 2 * time.Second
	for range min(max(attempt-1, 0), 7) {
		delay *= 2
	}
	delay = min(delay, 5*time.Minute)
	jitter := time.Duration(rand.Int64N(max(int64(delay/5), 1)))
	return delay + jitter
}

func (d *ddnsDispatcher) enqueue(task ddnsDispatchTask) {
	keyDomain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(task.domain), "."))
	key := fmt.Sprintf("%d:%s", task.profileID, keyDomain)

	d.mu.Lock()
	if d.ctx.Err() != nil {
		d.mu.Unlock()
		return
	}
	if state, ok := d.tasks[key]; ok {
		state.task = task
		state.version++
		select {
		case state.wake <- struct{}{}:
		default:
		}
		d.mu.Unlock()
		return
	}

	stateContext, cancel := context.WithCancel(d.ctx)
	state := &ddnsDispatchState{
		task: task, version: 1, wake: make(chan struct{}, 1),
		ctx: stateContext, cancel: cancel,
	}
	d.tasks[key] = state
	d.wg.Add(1)
	d.mu.Unlock()

	go d.run(key, state)
}

func (d *ddnsDispatcher) run(key string, state *ddnsDispatchState) {
	defer d.wg.Done()
	attempt := 0
	for {
		d.mu.Lock()
		if state.canceled {
			d.mu.Unlock()
			return
		}
		task := state.task
		version := state.version
		d.mu.Unlock()

		select {
		case d.semaphore <- struct{}{}:
		case <-state.ctx.Done():
			return
		}
		attemptContext, cancel := context.WithTimeout(state.ctx, ddnsAttemptTimeout)
		attemptContext = context.WithValue(attemptContext, ddns.DNSServerKey{}, task.dnsServers)
		err := d.execute(attemptContext, task.provider, task.domain)
		cancel()
		<-d.semaphore

		d.mu.Lock()
		if state.canceled {
			d.mu.Unlock()
			return
		}
		current := state.version
		if err == nil && current == version {
			if d.tasks[key] == state {
				delete(d.tasks, key)
			}
			state.cancel()
			d.mu.Unlock()
			return
		}
		d.mu.Unlock()

		if current != version {
			attempt = 0
			continue
		}

		attempt++
		delay := d.retryDelay(attempt)
		log.Printf("NEZHA>> DDNS update queued for retry: server=%d profile=%d domain=%s attempt=%d delay=%s error=%v",
			task.serverID, task.profileID, task.domain, attempt, delay, err)
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-state.wake:
			stopAndDrainTimer(timer)
			attempt = 0
		case <-state.ctx.Done():
			stopAndDrainTimer(timer)
			return
		}
	}
}

func (d *ddnsDispatcher) cancelServer(serverID uint64) {
	d.cancelMatching(func(task ddnsDispatchTask) bool { return task.serverID == serverID })
}

func (d *ddnsDispatcher) cancelProfiles(profileIDs []uint64) {
	profileSet := make(map[uint64]struct{}, len(profileIDs))
	for _, id := range profileIDs {
		profileSet[id] = struct{}{}
	}
	d.cancelMatching(func(task ddnsDispatchTask) bool {
		_, ok := profileSet[task.profileID]
		return ok
	})
}

func (d *ddnsDispatcher) cancelMatching(matches func(ddnsDispatchTask) bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for key, state := range d.tasks {
		if !matches(state.task) {
			continue
		}
		state.canceled = true
		state.cancel()
		delete(d.tasks, key)
		select {
		case state.wake <- struct{}{}:
		default:
		}
	}
}

func stopAndDrainTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

func (d *ddnsDispatcher) close() {
	d.cancel()
	d.wg.Wait()
}
