package singleton

import (
	"sort"
	"strings"
	"time"

	"github.com/nezhahq/nezha/model"
	pb "github.com/nezhahq/nezha/proto"
)

func classifyServiceError(successful bool, message string) uint8 {
	if successful {
		return model.ServiceErrorNone
	}
	s := strings.ToLower(message)
	switch {
	case strings.Contains(s, "timeout"), strings.Contains(s, "deadline exceeded"):
		return model.ServiceErrorTimeout
	case strings.Contains(s, "refused"):
		return model.ServiceErrorRefused
	case strings.Contains(s, "no such host"), strings.Contains(s, "server misbehaving"), strings.Contains(s, "dns"):
		return model.ServiceErrorDNS
	case strings.Contains(s, "no route"), strings.Contains(s, "unreachable"), strings.Contains(s, "network is down"):
		return model.ServiceErrorUnreachable
	case strings.Contains(s, "missing port"), strings.Contains(s, "too many colons"), strings.Contains(s, "invalid"):
		return model.ServiceErrorInvalidTarget
	default:
		return model.ServiceErrorOther
	}
}

func ClassifyServiceError(successful bool, message string) uint8 {
	return classifyServiceError(successful, message)
}

func (ss *ServiceSentinel) setLatestResult(service *model.Service, server *model.Server, result *pb.TaskResult, at time.Time) {
	if service == nil || server == nil || result == nil {
		return
	}
	errorText := result.GetData()
	if len(errorText) > 512 {
		errorText = errorText[:512]
	}
	latest := model.ServiceLatestResult{
		ServiceID: service.ID, ServiceName: service.Name, ServerID: server.ID, ServerName: server.Name,
		Duration: service.Duration, Timestamp: at.UnixMilli(), Delay: float64(result.GetDelay()),
		Successful: result.GetSuccessful(), ErrorCode: classifyServiceError(result.GetSuccessful(), errorText), Error: errorText,
	}
	ss.latestResultLock.Lock()
	defer ss.latestResultLock.Unlock()
	if ss.latestResults[service.ID] == nil {
		ss.latestResults[service.ID] = make(map[uint64]model.ServiceLatestResult)
	}
	ss.latestResults[service.ID][server.ID] = latest
	const maxRecentResultsPerServer = 4096
	recent := append(ss.recentResults[server.ID], latest)
	if len(recent) > maxRecentResultsPerServer {
		recent = append([]model.ServiceLatestResult(nil), recent[len(recent)-maxRecentResultsPerServer:]...)
	}
	ss.recentResults[server.ID] = recent
}

func (ss *ServiceSentinel) RecentResultsByServer(serverID uint64, since int64) []model.ServiceLatestResult {
	ss.latestResultLock.RLock()
	defer ss.latestResultLock.RUnlock()
	recent := ss.recentResults[serverID]
	result := make([]model.ServiceLatestResult, 0, len(recent))
	for _, item := range recent {
		if item.Timestamp > since {
			result = append(result, item)
		}
	}
	return result
}

func (ss *ServiceSentinel) LatestResultsByServer(serverID uint64) []model.ServiceLatestResult {
	ss.latestResultLock.RLock()
	defer ss.latestResultLock.RUnlock()
	result := make([]model.ServiceLatestResult, 0)
	for _, perServer := range ss.latestResults {
		if latest, ok := perServer[serverID]; ok {
			result = append(result, latest)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].ServiceName != result[j].ServiceName {
			return result[i].ServiceName < result[j].ServiceName
		}
		return result[i].ServiceID < result[j].ServiceID
	})
	return result
}
