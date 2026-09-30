package singleton

import (
	"testing"
	"time"

	"github.com/nezhahq/nezha/model"
	pb "github.com/nezhahq/nezha/proto"
)

type serviceFailureIPTaskStream struct {
	pb.NezhaService_RequestTaskServer
	tasks chan *pb.Task
}

func (s *serviceFailureIPTaskStream) Send(task *pb.Task) error {
	s.tasks <- task
	return nil
}

func TestServiceSentinelFailureThresholdDNSChangeAndRecovery(t *testing.T) {
	tests := []struct {
		name     string
		taskType uint8
		oldError string
		newError string
	}{
		{name: "TCP", taskType: model.TaskTypeTCPPing, oldError: "dial tcp 192.0.2.10:443: i/o timeout", newError: "dial tcp 192.0.2.20:443: i/o timeout"},
		{name: "ICMP IPv4", taskType: model.TaskTypeICMPPing, oldError: "icmp ping target=192.0.2.10: packets recv 0", newError: "icmp ping target=192.0.2.20: packets recv 0"},
		{name: "ICMP IPv6", taskType: model.TaskTypeICMPPing, oldError: "icmp ping target=2001:db8::10: packets recv 0", newError: "icmp ping target=2001:db8::20: packets recv 0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stream := &serviceFailureIPTaskStream{tasks: make(chan *pb.Task, 16)}
			server := &model.Server{Common: model.Common{ID: 1, UserID: 200}, Name: "probe"}
			server.SetTaskStream(stream)
			ss := newServiceMonitorSecurityHarness(t, server)
			service := &model.Service{
				Common:              model.Common{ID: 10, UserID: 200},
				Name:                "DNS target",
				Type:                tt.taskType,
				Target:              "monitor.example",
				Duration:            7,
				FailureThreshold:    7,
				EnableTriggerTask:   true,
				FailTriggerTasks:    []uint64{77},
				RecoverTriggerTasks: []uint64{78},
			}
			addServiceMonitorSecurityService(t, ss, service)
			for _, id := range []uint64{77, 78} {
				CronShared.list[id] = &model.Cron{
					Common:  model.Common{ID: id, UserID: 200},
					Name:    "DDNS action",
					Command: "update-ddns",
					Cover:   model.CronCoverAlertTrigger,
				}
			}

			report := func(successful bool, data string) {
				r := serviceMonitorResult(1, 10, tt.taskType, successful)
				r.Data.Data = data
				ss.processReport(r, ServerShared)
			}
			expectTask := func(id uint64) {
				t.Helper()
				select {
				case task := <-stream.tasks:
					if task.GetId() != id || task.GetData() != "update-ddns" {
						t.Fatalf("triggered task = %+v, want DDNS task %d", task, id)
					}
				case <-time.After(time.Second):
					t.Fatalf("DDNS task %d was not triggered", id)
				}
			}
			expectNoTask := func() {
				t.Helper()
				select {
				case task := <-stream.tasks:
					t.Fatalf("unexpected DDNS task: %+v", task)
				case <-time.After(50 * time.Millisecond):
				}
			}

			for range 6 {
				report(false, tt.oldError)
			}
			expectNoTask()
			report(false, tt.oldError)
			expectTask(77)
			report(false, tt.oldError)
			expectNoTask()
			report(false, tt.newError)
			expectTask(77)
			report(false, tt.newError)
			expectNoTask()
			report(true, "")
			expectTask(78)
			report(true, "")
			expectNoTask()
			for range 6 {
				report(false, tt.newError)
			}
			expectNoTask()
			report(false, tt.newError)
			expectTask(77)
		})
	}
}
