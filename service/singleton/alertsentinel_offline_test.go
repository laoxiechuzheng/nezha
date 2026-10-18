package singleton

import (
	"bytes"
	"context"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/pkg/i18n"
	pb "github.com/nezhahq/nezha/proto"
)

type alertOfflineReportStream struct{}

func (alertOfflineReportStream) Send(*pb.Receipt) error       { return nil }
func (alertOfflineReportStream) Recv() (*pb.State, error)     { return nil, context.Canceled }
func (alertOfflineReportStream) SetHeader(metadata.MD) error  { return nil }
func (alertOfflineReportStream) SendHeader(metadata.MD) error { return nil }
func (alertOfflineReportStream) SetTrailer(metadata.MD)       {}
func (alertOfflineReportStream) Context() context.Context     { return context.Background() }
func (alertOfflineReportStream) SendMsg(any) error            { return nil }
func (alertOfflineReportStream) RecvMsg(any) error            { return nil }

type alertOfflineLogBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *alertOfflineLogBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(data)
}

func (b *alertOfflineLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

func waitForAlertOfflineNotification(t *testing.T, logs *alertOfflineLogBuffer, count int) {
	t.Helper()
	require.Eventually(t, func() bool {
		return strings.Count(logs.String(), "Sending notification to alert-offline-test failed") >= count
	}, time.Second, 10*time.Millisecond)

	// SendNotification holds listMu.RLock for its entire send loop. Once the
	// failure log is visible, taking the write lock waits for that goroutine to
	// finish before package globals are restored.
	NotificationShared.listMu.Lock()
	NotificationShared.listMu.Unlock()
}

func waitForAlertOfflineTriggerTasks(t *testing.T, stream *capturedTaskStream, ids ...uint64) {
	t.Helper()
	wanted := make(map[uint64]struct{}, len(ids))
	for _, id := range ids {
		wanted[id] = struct{}{}
	}
	deadline := time.After(time.Second)
	for len(wanted) > 0 {
		select {
		case task := <-stream.tasks:
			delete(wanted, task.Id)
		case <-deadline:
			t.Fatalf("timed out waiting for trigger tasks; remaining IDs: %v", wanted)
		}
	}
}

func TestCheckStatusForServerOfflineDurationTriggersAndRecovers(t *testing.T) {
	originalStore := alertsStore
	originalPrevState := alertsPrevState
	originalCycleStore := AlertsCycleTransferStatsStore
	originalCache := Cache
	originalLoc := Loc
	originalConf := Conf
	originalLocalizer := Localizer
	originalCron := CronShared
	originalNotification := NotificationShared
	originalServerShared := ServerShared
	originalLogWriter := log.Writer()

	alertsStore = map[uint64]map[uint64][][]bool{}
	alertsPrevState = map[uint64]map[uint64]uint8{}
	AlertsCycleTransferStatsStore = map[uint64]*model.CycleTransferStats{}
	Cache = cache.New(time.Minute, time.Minute)
	Loc = time.UTC
	Conf = &ConfigClass{Config: &model.Config{}}
	Localizer = i18n.NewLocalizer("en_US", "nezha", "translations", i18n.Translations)
	failCron := &model.Cron{
		Common:  model.Common{ID: 100, UserID: 1},
		Name:    "offline-fail-trigger",
		Command: "fail",
		Cover:   model.CronCoverAlertTrigger,
	}
	recoverCron := &model.Cron{
		Common:  model.Common{ID: 101, UserID: 1},
		Name:    "offline-recover-trigger",
		Command: "recover",
		Cover:   model.CronCoverAlertTrigger,
	}
	CronShared = &CronClass{class: class[uint64, *model.Cron]{list: map[uint64]*model.Cron{
		failCron.ID:    failCron,
		recoverCron.ID: recoverCron,
	}}}
	notification := &model.Notification{Common: model.Common{ID: 1}, Name: "alert-offline-test"}
	NotificationShared = &NotificationClass{
		class:         class[uint64, *model.Notification]{list: map[uint64]*model.Notification{notification.ID: notification}},
		groupToIDList: map[uint64]map[uint64]*model.Notification{0: {notification.ID: notification}},
		idToGroupList: map[uint64]map[uint64]struct{}{notification.ID: {0: {}}},
		groupList:     map[uint64]string{},
	}
	var logs alertOfflineLogBuffer
	log.SetOutput(&logs)

	t.Cleanup(func() {
		log.SetOutput(originalLogWriter)
		alertsStore = originalStore
		alertsPrevState = originalPrevState
		AlertsCycleTransferStatsStore = originalCycleStore
		Cache = originalCache
		Loc = originalLoc
		Conf = originalConf
		Localizer = originalLocalizer
		CronShared = originalCron
		NotificationShared = originalNotification
		ServerShared = originalServerShared
	})

	enabled := true
	alert := &model.AlertRule{
		Common:              model.Common{ID: 91},
		Enable:              &enabled,
		TriggerMode:         model.ModeOnetimeTrigger,
		Rules:               []*model.Rule{{Type: "offline", Duration: 3, Cover: model.RuleCoverAll}},
		FailTriggerTasks:    []uint64{failCron.ID},
		RecoverTriggerTasks: []uint64{recoverCron.ID},
	}
	alertsStore[alert.ID] = map[uint64][][]bool{}
	alertsPrevState[alert.ID] = map[uint64]uint8{}

	server := &model.Server{Common: model.Common{ID: 7, UserID: 1}, Name: "offline-server"}
	model.InitServer(server)
	taskStream := newCapturedTaskStream()
	server.SetTaskStream(taskStream)
	ServerShared = &ServerClass{
		class:    class[uint64, *model.Server]{list: map[uint64]*model.Server{server.ID: server}},
		uuidToID: map[string]uint64{},
	}
	lease := server.AttachStateStream(alertOfflineReportStream{})
	require.True(t, lease.UpdateState(&model.HostState{}, time.Now().Add(-4*time.Second)))

	checkStatusForServer(alert, server)
	require.Equal(t, uint8(_RuleCheckFail), alertsPrevState[alert.ID][server.ID])
	require.Len(t, alertsStore[alert.ID][server.ID], 1)
	waitForAlertOfflineNotification(t, &logs, 1)

	require.True(t, lease.UpdateState(&model.HostState{}, time.Now()))
	checkStatusForServer(alert, server)
	require.Equal(t, uint8(_RuleCheckPass), alertsPrevState[alert.ID][server.ID])
	require.Len(t, alertsStore[alert.ID][server.ID], 1)
	waitForAlertOfflineNotification(t, &logs, 2)
	waitForAlertOfflineTriggerTasks(t, taskStream, failCron.ID, recoverCron.ID)
}
