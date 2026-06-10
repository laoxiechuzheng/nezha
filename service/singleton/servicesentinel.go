package singleton

import (
	"cmp"
	"fmt"
	"iter"
	"log"
	"maps"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jinzhu/copier"
	"golang.org/x/exp/constraints"

	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/pkg/tsdb"
	"github.com/nezhahq/nezha/pkg/utils"
	pb "github.com/nezhahq/nezha/proto"
)

const (
	_CurrentStatusSize = 30 // 缁熻 15 鍒嗛挓鍐呯殑鏁版嵁涓哄綋鍓嶇姸鎬?
)

type serviceResponseItem struct {
	model.ServiceResponseItem

	service *model.Service
}

type ReportData struct {
	Data     *pb.TaskResult
	Reporter uint64
}

// _TodayStatsOfService 浠婃棩鐩戞帶璁板綍
type _TodayStatsOfService struct {
	Up    uint64  // 浠婃棩鍦ㄧ嚎璁℃暟
	Down  uint64  // 浠婃棩绂荤嚎璁℃暟
	Delay float64 // 浠婃棩骞冲潎寤惰繜
}

type serviceResponseData = _TodayStatsOfService

type serviceTaskStatus struct {
	lastStatus          uint8
	t                   time.Time
	result              []*pb.TaskResult
	consecutiveFailures int
	inFailureState      bool
	lastFailureIP       string
}

type pingStore struct {
	count        int
	ping         float64
	successCount int
}

/*
浣跨敤缂撳瓨 channel锛屽鐞嗕笂鎶ョ殑 Service 璇锋眰缁撴灉锛岀劧鍚庡垽鏂槸鍚﹂渶瑕佹姤璀?
闇€瑕佽褰曚笂涓€娆＄殑鐘舵€佷俊鎭?

鍔犻攣椤哄簭锛歴erviceResponseDataStoreLock > monthlyStatusLock > servicesLock
*/
type ServiceSentinel struct {
	// 鏈嶅姟鐩戞帶浠诲姟涓婃姤閫氶亾
	serviceReportChannel chan ReportData // 鏈嶅姟鐘舵€佹眹鎶ョ閬?
	// 鏈嶅姟鐩戞帶浠诲姟璋冨害閫氶亾
	dispatchBus chan<- *model.Service

	serviceResponseDataStoreLock sync.RWMutex
	serviceStatusToday           map[uint64]*_TodayStatsOfService // [service_id] -> _TodayStatsOfService
	serviceCurrentStatusData     map[uint64]*serviceTaskStatus    // 褰撳墠浠诲姟缁撴灉缂撳瓨
	serviceResponseDataStore     map[uint64]serviceResponseData   // 褰撳墠鏁版嵁

	serviceResponsePing map[uint64]map[uint64]*pingStore // [service_id] -> ClientID -> delay
	tlsCertCache        map[uint64]string

	servicesLock    sync.RWMutex
	serviceListLock sync.RWMutex
	services        map[uint64]*model.Service
	serviceList     []*model.Service

	// 30澶╂暟鎹紦瀛?
	monthlyStatusLock sync.Mutex
	monthlyStatus     map[uint64]*serviceResponseItem

	// closeOnce + workerWG together let Close() wait for the worker goroutine
	// to fully exit. Without this, a test that swaps ServiceSentinelShared back
	// to its original value in t.Cleanup races against the still-running
	// worker, which keeps reading globals like Conf/CronShared/NotificationShared.
	// Production never calls Close() 鈥?the process exits while the worker is
	// still running and that is fine 鈥?but tests must drain the worker before
	// restoring globals.
	closeOnce sync.Once
	workerWG  sync.WaitGroup
}

// NewServiceSentinel 鍒涘缓鏈嶅姟鐩戞帶鍣?
func NewServiceSentinel(serviceSentinelDispatchBus chan<- *model.Service) (*ServiceSentinel, error) {
	ss := &ServiceSentinel{
		serviceReportChannel:     make(chan ReportData, 200),
		serviceStatusToday:       make(map[uint64]*_TodayStatsOfService),
		serviceCurrentStatusData: make(map[uint64]*serviceTaskStatus),
		serviceResponseDataStore: make(map[uint64]serviceResponseData),
		serviceResponsePing:      make(map[uint64]map[uint64]*pingStore),
		services:                 make(map[uint64]*model.Service),
		tlsCertCache:             make(map[uint64]string),
		// 30澶╂暟鎹紦瀛?
		monthlyStatus: make(map[uint64]*serviceResponseItem),
		dispatchBus:   serviceSentinelDispatchBus,
	}

	// 鍔犺浇鍘嗗彶璁板綍
	err := ss.loadServiceHistory()
	if err != nil {
		return nil, err
	}

	year, month, day := time.Now().Date()
	today := time.Date(year, month, day, 0, 0, 0, 0, Loc)
	ss.loadTodayStats(today)

	// 鍚姩鏈嶅姟鐩戞帶鍣?
	ss.workerWG.Add(1)
	go func() {
		defer ss.workerWG.Done()
		ss.worker()
	}()

	// 姣忔棩灏嗘父鏍囧線鍚庢帹涓€澶?
	_, err = CronShared.AddFunc("0 0 0 * * *", ss.refreshMonthlyServiceStatus)
	if err != nil {
		return nil, err
	}

	// 姣忓懆鏃ュ噷鏅?4:00 鎵ц绯荤粺瀛樺偍缁存姢
	_, err = CronShared.AddFunc("0 0 4 * * 0", PerformMaintenance)
	if err != nil {
		log.Printf("NEZHA>> Warning: failed to schedule maintenance task: %v", err)
	}

	return ss, nil
}

func (ss *ServiceSentinel) refreshMonthlyServiceStatus() {
	// 鍒锋柊鏁版嵁闃叉鏃犱汉璁块棶
	ss.LoadStats()
	// 灏嗘暟鎹線鍓嶅埛涓€澶?
	ss.serviceResponseDataStoreLock.Lock()
	defer ss.serviceResponseDataStoreLock.Unlock()
	ss.monthlyStatusLock.Lock()
	defer ss.monthlyStatusLock.Unlock()
	for k, v := range ss.monthlyStatus {
		for i := range len(v.Up) - 1 {
			if i == 0 {
				// 30 澶╁湪绾跨巼锛屽噺鍘诲凡缁忓嚭30澶╀箣澶栫殑鏁版嵁
				v.TotalDown -= v.Down[i]
				v.TotalUp -= v.Up[i]
			}
			v.Up[i], v.Down[i], v.Delay[i] = v.Up[i+1], v.Down[i+1], v.Delay[i+1]
		}
		v.Up[29] = 0
		v.Down[29] = 0
		v.Delay[29] = 0
		// 娓呯悊鍓嶄竴澶╂暟鎹?
		ss.serviceResponseDataStore[k] = serviceResponseData{}
		ss.serviceStatusToday[k].Delay = 0
		ss.serviceStatusToday[k].Up = 0
		ss.serviceStatusToday[k].Down = 0
	}
}

// Dispatch 灏嗕紶鍏ョ殑 ReportData 浼犵粰 鏈嶅姟鐘舵€佹眹鎶ョ閬?
func (ss *ServiceSentinel) Dispatch(r ReportData) {
	ss.serviceReportChannel <- r
}

// sortServices 鎸?DisplayIndex 闄嶅簭銆両D 鍗囧簭鎺掑垪鏈嶅姟鍒楄〃
func sortServices(services []*model.Service) {
	slices.SortFunc(services, func(a, b *model.Service) int {
		if a.DisplayIndex != b.DisplayIndex {
			return cmp.Compare(b.DisplayIndex, a.DisplayIndex)
		}
		return cmp.Compare(a.ID, b.ID)
	})
}

func (ss *ServiceSentinel) UpdateServiceList() {
	ss.servicesLock.RLock()
	defer ss.servicesLock.RUnlock()

	ss.serviceListLock.Lock()
	defer ss.serviceListLock.Unlock()

	ss.serviceList = utils.MapValuesToSlice(ss.services)
	sortServices(ss.serviceList)
}

// loadServiceHistory 鍔犺浇鏈嶅姟鐩戞帶鍣ㄧ殑鍘嗗彶鐘舵€佷俊鎭?
func (ss *ServiceSentinel) loadServiceHistory() error {
	var services []*model.Service
	err := DB.Find(&services).Error
	if err != nil {
		return err
	}

	for _, service := range services {
		task := service
		// 閫氳繃cron瀹氭椂灏嗘湇鍔＄洃鎺т换鍔′紶閫掔粰浠诲姟璋冨害绠￠亾
		service.CronJobID, err = CronShared.AddFunc(task.CronSpec(), func() {
			ss.dispatchBus <- task
		})
		if err != nil {
			return err
		}
		ss.services[service.ID] = service
		ss.serviceCurrentStatusData[service.ID] = new(serviceTaskStatus)
		ss.serviceCurrentStatusData[service.ID].result = make([]*pb.TaskResult, 0, _CurrentStatusSize)
		ss.serviceStatusToday[service.ID] = &_TodayStatsOfService{}
	}
	ss.serviceList = services
	sortServices(ss.serviceList)

	year, month, day := time.Now().Date()
	today := time.Date(year, month, day, 0, 0, 0, 0, Loc)

	for _, service := range services {
		ss.monthlyStatus[service.ID] = &serviceResponseItem{
			service: service,
			ServiceResponseItem: model.ServiceResponseItem{
				Delay: &[30]float64{},
				Up:    &[30]uint64{},
				Down:  &[30]uint64{},
			},
		}
	}

	if TSDBEnabled() {
		ss.loadMonthlyStatusFromTSDB(services, today)
	} else {
		ss.loadMonthlyStatusFromDB(today)
	}

	return nil
}

func (ss *ServiceSentinel) loadMonthlyStatusFromTSDB(services []*model.Service, today time.Time) {
	for _, service := range services {
		dailyStats, err := TSDBShared.QueryServiceDailyStats(service.ID, today, 30)
		if err != nil {
			log.Printf("NEZHA>> Failed to load TSDB history for service %d: %v", service.ID, err)
			continue
		}
		ms := ss.monthlyStatus[service.ID]
		for i := 0; i < 29; i++ {
			ms.Up[i] = dailyStats[i].Up
			ms.TotalUp += dailyStats[i].Up
			ms.Down[i] = dailyStats[i].Down
			ms.TotalDown += dailyStats[i].Down
			ms.Delay[i] = dailyStats[i].Delay
		}
	}
}

func (ss *ServiceSentinel) loadMonthlyStatusFromDB(today time.Time) {
	var mhs []model.ServiceHistory
	DB.Where("created_at > ? AND created_at < ? AND server_id = 0", today.AddDate(0, 0, -29), today).Find(&mhs)
	delayCount := make(map[uint64]map[int]int)
	for _, mh := range mhs {
		dayIndex := 28 - int(today.Sub(mh.CreatedAt).Hours())/24
		if dayIndex < 0 {
			continue
		}
		ms := ss.monthlyStatus[mh.ServiceID]
		if ms == nil {
			continue
		}
		if delayCount[mh.ServiceID] == nil {
			delayCount[mh.ServiceID] = make(map[int]int)
		}
		ms.Delay[dayIndex] = (ms.Delay[dayIndex]*float64(delayCount[mh.ServiceID][dayIndex]) + mh.AvgDelay) / float64(delayCount[mh.ServiceID][dayIndex]+1)
		delayCount[mh.ServiceID][dayIndex]++
		ms.Up[dayIndex] += mh.Up
		ms.TotalUp += mh.Up
		ms.Down[dayIndex] += mh.Down
		ms.TotalDown += mh.Down
	}
}

func (ss *ServiceSentinel) loadTodayStats(today time.Time) {
	if TSDBEnabled() {
		for serviceID, ms := range ss.monthlyStatus {
			result, err := TSDBShared.QueryServiceHistory(serviceID, tsdb.Period1Day)
			if err != nil {
				log.Printf("NEZHA>> Failed to load TSDB today stats for service %d: %v", serviceID, err)
				continue
			}
			var totalUp, totalDown uint64
			var totalDelay float64
			var delayCount int
			for _, serverStats := range result.Servers {
				totalUp += serverStats.Stats.TotalUp
				totalDown += serverStats.Stats.TotalDown
				if serverStats.Stats.AvgDelay > 0 {
					totalDelay += serverStats.Stats.AvgDelay
					delayCount++
				}
			}
			ss.serviceStatusToday[serviceID].Up = totalUp
			ss.serviceStatusToday[serviceID].Down = totalDown
			if delayCount > 0 {
				ss.serviceStatusToday[serviceID].Delay = totalDelay / float64(delayCount)
			}
			ms.TotalUp += totalUp
			ms.TotalDown += totalDown
		}
	} else {
		var mhs []model.ServiceHistory
		DB.Where("created_at >= ? AND server_id = 0", today).Find(&mhs)
		totalDelay := make(map[uint64]float64)
		totalDelayCount := make(map[uint64]int)
		for _, mh := range mhs {
			ss.serviceStatusToday[mh.ServiceID].Up += mh.Up
			ss.monthlyStatus[mh.ServiceID].TotalUp += mh.Up
			ss.serviceStatusToday[mh.ServiceID].Down += mh.Down
			ss.monthlyStatus[mh.ServiceID].TotalDown += mh.Down
			totalDelay[mh.ServiceID] += mh.AvgDelay
			totalDelayCount[mh.ServiceID]++
		}
		for id, delay := range totalDelay {
			ss.serviceStatusToday[id].Delay = delay / float64(totalDelayCount[id])
		}
	}
}

func (ss *ServiceSentinel) Update(m *model.Service) error {
	ss.serviceResponseDataStoreLock.Lock()
	defer ss.serviceResponseDataStoreLock.Unlock()
	ss.monthlyStatusLock.Lock()
	defer ss.monthlyStatusLock.Unlock()
	ss.servicesLock.Lock()
	defer ss.servicesLock.Unlock()

	var err error
	// 鍐欏叆鏂颁换鍔?
	m.CronJobID, err = CronShared.AddFunc(m.CronSpec(), func() {
		ss.dispatchBus <- m
	})
	if err != nil {
		return err
	}
	if ss.services[m.ID] != nil {
		// 鍋滄帀鏃т换鍔?
		CronShared.Remove(ss.services[m.ID].CronJobID)
	} else {
		// 鏂颁换鍔″垵濮嬪寲鏁版嵁
		ss.monthlyStatus[m.ID] = &serviceResponseItem{
			service: m,
			ServiceResponseItem: model.ServiceResponseItem{
				Delay: &[30]float64{},
				Up:    &[30]uint64{},
				Down:  &[30]uint64{},
			},
		}
		if ss.serviceCurrentStatusData[m.ID] == nil {
			ss.serviceCurrentStatusData[m.ID] = new(serviceTaskStatus)
		}
		ss.serviceCurrentStatusData[m.ID].result = make([]*pb.TaskResult, 0, _CurrentStatusSize)
		ss.serviceStatusToday[m.ID] = &_TodayStatsOfService{}
	}
	// 鏇存柊杩欎釜浠诲姟
	ss.services[m.ID] = m
	return nil
}

func (ss *ServiceSentinel) Delete(ids []uint64) {
	ss.serviceResponseDataStoreLock.Lock()
	defer ss.serviceResponseDataStoreLock.Unlock()
	ss.monthlyStatusLock.Lock()
	defer ss.monthlyStatusLock.Unlock()
	ss.servicesLock.Lock()
	defer ss.servicesLock.Unlock()

	for _, id := range ids {
		delete(ss.serviceCurrentStatusData, id)
		delete(ss.serviceResponseDataStore, id)
		delete(ss.tlsCertCache, id)
		delete(ss.serviceStatusToday, id)

		// 鍋滄帀瀹氭椂浠诲姟
		CronShared.Remove(ss.services[id].CronJobID)
		delete(ss.services, id)

		delete(ss.monthlyStatus, id)
	}
}

func (ss *ServiceSentinel) LoadStats() map[uint64]*serviceResponseItem {
	ss.servicesLock.RLock()
	defer ss.servicesLock.RUnlock()
	ss.serviceResponseDataStoreLock.RLock()
	defer ss.serviceResponseDataStoreLock.RUnlock()
	ss.monthlyStatusLock.Lock()
	defer ss.monthlyStatusLock.Unlock()

	// 鍒锋柊鏈€鏂颁竴澶╃殑鏁版嵁
	for k := range ss.services {
		ss.monthlyStatus[k].service = ss.services[k]
		v := ss.serviceStatusToday[k]

		// 30 澶╁湪绾跨巼锛?
		//   |- 鍑忓幓涓婃鍔犵殑鏃у綋澶╂暟鎹紝闃叉鍑虹幇閲嶅璁℃暟
		ss.monthlyStatus[k].TotalUp -= ss.monthlyStatus[k].Up[29]
		ss.monthlyStatus[k].TotalDown -= ss.monthlyStatus[k].Down[29]
		//   |- 鍔犱笂褰撴棩鏁版嵁
		ss.monthlyStatus[k].TotalUp += v.Up
		ss.monthlyStatus[k].TotalDown += v.Down

		ss.monthlyStatus[k].Up[29] = v.Up
		ss.monthlyStatus[k].Down[29] = v.Down
		ss.monthlyStatus[k].Delay[29] = v.Delay
	}

	// 鏈€鍚?5 鍒嗛挓鐨勭姸鎬?涓?service 瀵硅薄濉厖
	for k, v := range ss.serviceResponseDataStore {
		ss.monthlyStatus[k].CurrentDown = v.Down
		ss.monthlyStatus[k].CurrentUp = v.Up
	}

	return ss.monthlyStatus
}

func (ss *ServiceSentinel) CopyStats() map[uint64]model.ServiceResponseItem {
	var stats map[uint64]*serviceResponseItem
	copier.Copy(&stats, ss.LoadStats())

	sri := make(map[uint64]model.ServiceResponseItem)
	for k, service := range stats {
		if service.service.HideForGuest {
			delete(stats, k)
			continue
		}

		service.ServiceName = service.service.Name
		sri[k] = service.ServiceResponseItem
	}

	return sri
}

func (ss *ServiceSentinel) Get(id uint64) (s *model.Service, ok bool) {
	ss.servicesLock.RLock()
	defer ss.servicesLock.RUnlock()

	s, ok = ss.services[id]
	return
}

func (ss *ServiceSentinel) GetList() map[uint64]*model.Service {
	ss.servicesLock.RLock()
	defer ss.servicesLock.RUnlock()

	return maps.Clone(ss.services)
}

func (ss *ServiceSentinel) GetSortedList() []*model.Service {
	ss.serviceListLock.RLock()
	defer ss.serviceListLock.RUnlock()

	return slices.Clone(ss.serviceList)
}

func (ss *ServiceSentinel) CheckPermission(c *gin.Context, idList iter.Seq[uint64]) bool {
	ss.servicesLock.RLock()
	defer ss.servicesLock.RUnlock()

	for id := range idList {
		if s, ok := ss.services[id]; ok {
			if !s.HasPermission(c) {
				return false
			}
		}
	}
	return true
}

func canReportServiceResult(service *model.Service, reporter *model.Server, taskType uint64) bool {
	if service == nil || reporter == nil || uint64(service.Type) != taskType {
		return false
	}
	switch service.Cover {
	case model.ServiceCoverAll:
		if service.SkipServers[reporter.ID] {
			return false
		}
	case model.ServiceCoverIgnoreAll:
		if !service.SkipServers[reporter.ID] {
			return false
		}
	default:
		return false
	}

	return service.UserID == reporter.GetUserID() || userIsAdmin(service.UserID)
}

// Close shuts down the ServiceSentinel worker goroutine and waits for it to
// exit. It is idempotent and safe to call more than once.
//
// Why this exists: the worker reads multiple package-level globals during
// each report (Conf, CronShared via notifyCheck, NotificationShared via
// UnMuteNotification, ServerShared, TSDBShared). A test fixture that swaps
// those globals out in t.Cleanup MUST first call Close() 鈥?otherwise the
// cleanup write races the still-running worker's read and `go test -race`
// fires (see security_regression_test.go newServiceMonitorSecurityHarness).
// Production never calls Close because the process exits with the worker
// still running, which is fine.
func (ss *ServiceSentinel) Close() {
	ss.closeOnce.Do(func() {
		close(ss.serviceReportChannel)
		ss.workerWG.Wait()
	})
}

// worker 鏈嶅姟鐩戞帶鐨勫疄闄呭伐浣滄祦绋?
//
// IMPORTANT: this loop reads several package-level globals (Conf, CronShared,
// NotificationShared, ServerShared, TSDBShared). Any test that replaces those
// globals via t.Cleanup must first call ServiceSentinel.Close() so the worker
// drains and exits before the swap, otherwise the race detector trips. See
// the Close() comment above for the full rationale.
func (ss *ServiceSentinel) worker() {
	// 浠庢湇鍔＄姸鎬佹眹鎶ョ閬撹幏鍙栨眹鎶ョ殑鏈嶅姟鏁版嵁
	for r := range ss.serviceReportChannel {
		cs, _ := ss.Get(r.Data.GetId())
		reporter, _ := ServerShared.Get(r.Reporter)
		// 鍏ョ珯缁撴灉蹇呴』鍖归厤鍑虹珯浠诲姟娲惧彂杈圭晫锛岄伩鍏?agent 浼€犲叾浠栨湇鍔?ID 鍐欏叆鐩戞帶鐘舵€併€?
		if !canReportServiceResult(cs, reporter, r.Data.GetType()) {
			log.Printf("NEZHA>> Incorrect service monitor report %+v", r)
			continue
		}

		mh := r.Data
		if mh.Type == model.TaskTypeTCPPing || mh.Type == model.TaskTypeICMPPing {
			// TCP/ICMP Ping 浣跨敤骞冲潎鍊艰绠楀悗鍐嶅啓鍏?
			serviceTcpMap, ok := ss.serviceResponsePing[mh.GetId()]
			if !ok {
				serviceTcpMap = make(map[uint64]*pingStore)
				ss.serviceResponsePing[mh.GetId()] = serviceTcpMap
			}
			ts, ok := serviceTcpMap[r.Reporter]
			if !ok {
				ts = &pingStore{}
			}
			ts.count++
			ts.ping = (ts.ping*float64(ts.count-1) + float64(mh.Delay)) / float64(ts.count)
			if mh.Successful {
				ts.successCount++
			}
			if ts.count == Conf.AvgPingCount {
				if TSDBEnabled() {
					if err := TSDBShared.WriteServiceMetrics(&tsdb.ServiceMetrics{
						ServiceID:  mh.GetId(),
						ServerID:   r.Reporter,
						Timestamp:  time.Now(),
						Delay:      ts.ping,
						Successful: ts.successCount*2 >= ts.count,
					}); err != nil {
						log.Printf("NEZHA>> Failed to save service monitor metrics to TSDB: %v", err)
					}
				} else {
					if err := DB.Create(&model.ServiceHistory{
						ServiceID: mh.GetId(),
						AvgDelay:  ts.ping,
						Data:      mh.Data,
						ServerID:  r.Reporter,
					}).Error; err != nil {
						log.Printf("NEZHA>> Failed to save service monitor metrics: %v", err)
					}
				}
				ts.count = 0
				ts.ping = 0
				ts.successCount = 0
			}
			serviceTcpMap[r.Reporter] = ts
		} else {
			if TSDBEnabled() {
				if err := TSDBShared.WriteServiceMetrics(&tsdb.ServiceMetrics{
					ServiceID:  mh.GetId(),
					ServerID:   r.Reporter,
					Timestamp:  time.Now(),
					Delay:      float64(mh.Delay),
					Successful: mh.Successful,
				}); err != nil {
					log.Printf("NEZHA>> Failed to save service monitor metrics to TSDB: %v", err)
				}
			}
		}

		ss.serviceResponseDataStoreLock.Lock()
		// 鍐欏叆褰撳ぉ鐘舵€?
		if mh.Successful {
			ss.serviceStatusToday[mh.GetId()].Delay = (ss.serviceStatusToday[mh.
				GetId()].Delay*float64(ss.serviceStatusToday[mh.GetId()].Up) +
				float64(mh.Delay)) / float64(ss.serviceStatusToday[mh.GetId()].Up+1)
			ss.serviceStatusToday[mh.GetId()].Up++
		} else {
			ss.serviceStatusToday[mh.GetId()].Down++
		}

		currentTime := time.Now()
		if ss.serviceCurrentStatusData[mh.GetId()].t.IsZero() {
			ss.serviceCurrentStatusData[mh.GetId()].t = currentTime
		}

		// Record current status data.
		if ss.serviceCurrentStatusData[mh.GetId()].t.Before(currentTime) {
			sampleInterval := time.Duration(cs.Duration) * time.Second
			if sampleInterval <= 0 {
				sampleInterval = 30 * time.Second
			}
			ss.serviceCurrentStatusData[mh.GetId()].t = currentTime.Add(sampleInterval)
			ss.serviceCurrentStatusData[mh.GetId()].result = append(ss.serviceCurrentStatusData[mh.GetId()].result, mh)
		}

		// 鏇存柊褰撳墠鐘舵€?
		ss.serviceResponseDataStore[mh.GetId()] = serviceResponseData{}

		// 姘歌繙鏄渶鏂扮殑 30 涓暟鎹殑鐘舵€?[01:00, 02:00, 03:00] -> [04:00, 02:00, 03: 00]
		for _, cs := range ss.serviceCurrentStatusData[mh.GetId()].result {
			if cs.GetId() > 0 {
				rd := ss.serviceResponseDataStore[mh.GetId()]
				if cs.Successful {
					rd.Up++
					rd.Delay = (rd.Delay*float64(rd.Up-1) + float64(cs.Delay)) / float64(rd.Up)
				} else {
					rd.Down++
				}
				ss.serviceResponseDataStore[mh.GetId()] = rd
			}
		}

		status := ss.serviceCurrentStatusData[mh.GetId()]
		if status.lastStatus == 0 {
			status.lastStatus = StatusGood
		}

		stateCode := status.lastStatus
		triggerFailureForChangedIP := false

		if mh.Successful {
			status.consecutiveFailures = 0
			status.lastFailureIP = ""

			if status.inFailureState {
				status.inFailureState = false
				stateCode = StatusGood
			}
		} else {
			status.consecutiveFailures++

			currentFailureIP := extractTCPFailureIP(mh.Data)
			if !status.inFailureState && status.consecutiveFailures >= 3 {
				status.inFailureState = true
				status.lastFailureIP = currentFailureIP
				stateCode = StatusDown
			} else if status.inFailureState {
				if currentFailureIP != "" && status.lastFailureIP != "" && currentFailureIP != status.lastFailureIP {
					status.lastFailureIP = currentFailureIP
					triggerFailureForChangedIP = true
				} else if status.lastFailureIP == "" && currentFailureIP != "" {
					status.lastFailureIP = currentFailureIP
				}
			}
		}

		if len(ss.serviceCurrentStatusData[mh.GetId()].result) == _CurrentStatusSize {
			ss.serviceCurrentStatusData[mh.GetId()].t = currentTime
			if !TSDBEnabled() {
				rd := ss.serviceResponseDataStore[mh.GetId()]
				if err := DB.Create(&model.ServiceHistory{
					ServiceID: mh.GetId(),
					AvgDelay:  rd.Delay,
					Data:      mh.Data,
					Up:        rd.Up,
					Down:      rd.Down,
				}).Error; err != nil {
					log.Printf("NEZHA>> Failed to save service monitor metrics: %v", err)
				}
			}
			ss.serviceCurrentStatusData[mh.GetId()].result = ss.serviceCurrentStatusData[mh.GetId()].result[:0]
		}

		cs, _ = ss.Get(mh.GetId())
		m := ServerShared.GetList()
		// 寤惰繜鎶ヨ
		if mh.Delay > 0 {
			delayCheck(&r, m, cs, mh)
		}

		// State changes:
		// - 3 consecutive failures enter Down once.
		// - During failure, a changed resolved IP triggers one extra failure task.
		// - 1 successful check recovers to Good once.
		if stateCode != status.lastStatus {
			lastStatus := status.lastStatus
			status.lastStatus = stateCode

			notifyCheck(&r, m, cs, mh, lastStatus, stateCode)
		} else if triggerFailureForChangedIP {
			notifyCheck(&r, m, cs, mh, StatusGood, StatusDown)
		}
		ss.serviceResponseDataStoreLock.Unlock()

		// TLS 璇佷功鎶ヨ
		var errMsg string
		if strings.HasPrefix(mh.Data, "SSL\u8bc1\u4e66\u9519\u8bef\uff1a") {
			// i/o timeout銆乧onnection timeout銆丒OF 閿欒
			if !strings.HasSuffix(mh.Data, "timeout") &&
				!strings.HasSuffix(mh.Data, "EOF") &&
				!strings.HasSuffix(mh.Data, "timed out") {
				errMsg = mh.Data
				if cs.Notify {
					muteLabel := NotificationMuteLabel.ServiceTLS(mh.GetId(), "network")
					go NotificationShared.SendNotification(cs.NotificationGroupID, Localizer.Tf("[TLS] Fetch cert info failed, Reporter: %s, Error: %s", cs.Name, errMsg), muteLabel)
				}
			}
		} else {
			// 娓呴櫎缃戠粶閿欒闈欓煶缂撳瓨
			NotificationShared.UnMuteNotification(cs.NotificationGroupID, NotificationMuteLabel.ServiceTLS(mh.GetId(), "network"))

			var newCert = strings.Split(mh.Data, "|")
			if len(newCert) > 1 {
				enableNotify := cs.Notify

				// 棣栨鑾峰彇璇佷功淇℃伅鏃讹紝缂撳瓨璇佷功淇℃伅
				if ss.tlsCertCache[mh.GetId()] == "" {
					ss.tlsCertCache[mh.GetId()] = mh.Data
				}

				oldCert := strings.Split(ss.tlsCertCache[mh.GetId()], "|")
				isCertChanged := false
				expiresOld, _ := time.Parse("2006-01-02 15:04:05 -0700 MST", oldCert[1])
				expiresNew, _ := time.Parse("2006-01-02 15:04:05 -0700 MST", newCert[1])

				// 璇佷功鍙樻洿鏃讹紝鏇存柊缂撳瓨
				if oldCert[0] != newCert[0] && !expiresNew.Equal(expiresOld) {
					isCertChanged = true
					ss.tlsCertCache[mh.GetId()] = mh.Data
				}

				notificationGroupID := cs.NotificationGroupID
				serviceName := cs.Name

				// 闇€瑕佸彂閫佹彁閱?
				if enableNotify {
					// 璇佷功杩囨湡鎻愰啋
					if expiresNew.Before(time.Now().AddDate(0, 0, 7)) {
						expiresTimeStr := expiresNew.Format("2006-01-02 15:04:05")
						errMsg = Localizer.Tf(
							"The TLS certificate will expire within seven days. Expiration time: %s",
							expiresTimeStr,
						)

						// 闈欓煶瑙勫垯锛?鏈嶅姟id+璇佷功杩囨湡鏃堕棿
						// 鐢ㄤ簬閬垮厤澶氫釜鐩戞祴鐐瑰鐩稿悓璇佷功鍚屾椂鎶ヨ
						muteLabel := NotificationMuteLabel.ServiceTLS(mh.GetId(), fmt.Sprintf("expire_%s", expiresTimeStr))
						go NotificationShared.SendNotification(notificationGroupID, fmt.Sprintf("[TLS] %s %s", serviceName, errMsg), muteLabel)
					}

					// 璇佷功鍙樻洿鎻愰啋
					if isCertChanged {
						errMsg = Localizer.Tf(
							"TLS certificate changed, old: issuer %s, expires at %s; new: issuer %s, expires at %s",
							oldCert[0], expiresOld.Format("2006-01-02 15:04:05"), newCert[0], expiresNew.Format("2006-01-02 15:04:05"))

						// 璇佷功鍙樻洿鍚庝細鑷姩鏇存柊缂撳瓨锛屾墍浠ヤ笉闇€瑕侀潤闊?
						go NotificationShared.SendNotification(notificationGroupID, fmt.Sprintf("[TLS] %s %s", serviceName, errMsg), "")
					}
				}
			}
		}
	}
}

func delayCheck(r *ReportData, m map[uint64]*model.Server, ss *model.Service, mh *pb.TaskResult) {
	if !ss.LatencyNotify {
		return
	}

	notificationGroupID := ss.NotificationGroupID
	minMuteLabel := NotificationMuteLabel.ServiceLatencyMin(mh.GetId())
	maxMuteLabel := NotificationMuteLabel.ServiceLatencyMax(mh.GetId())
	if mh.Delay > ss.MaxLatency {
		// 寤惰繜瓒呰繃鏈€澶у€?
		reporterServer := m[r.Reporter]
		msg := Localizer.Tf("[Latency] %s %2f > %2f, Reporter: %s", ss.Name, mh.Delay, ss.MaxLatency, reporterServer.Name)
		go NotificationShared.SendNotification(notificationGroupID, msg, minMuteLabel)
	} else if mh.Delay < ss.MinLatency {
		// 寤惰繜浣庝簬鏈€灏忓€?
		reporterServer := m[r.Reporter]
		msg := Localizer.Tf("[Latency] %s %2f < %2f, Reporter: %s", ss.Name, mh.Delay, ss.MinLatency, reporterServer.Name)
		go NotificationShared.SendNotification(notificationGroupID, msg, maxMuteLabel)
	} else {
		// 姝ｅ父寤惰繜锛?娓呴櫎闈欓煶缂撳瓨
		NotificationShared.UnMuteNotification(notificationGroupID, minMuteLabel)
		NotificationShared.UnMuteNotification(notificationGroupID, maxMuteLabel)
	}
}

func extractTCPFailureIP(data string) string {
	const prefix = "dial tcp "
	idx := strings.Index(data, prefix)
	if idx < 0 {
		return ""
	}

	rest := data[idx+len(prefix):]
	end := strings.Index(rest, ": ")
	if end < 0 {
		return ""
	}

	addr := rest[:end]
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}

	return ip.String()
}

func notifyCheck(r *ReportData, m map[uint64]*model.Server,
	ss *model.Service, mh *pb.TaskResult, lastStatus, stateCode uint8) {
	// 鍒ゆ柇鏄惁闇€瑕佸彂閫侀€氱煡
	isNeedSendNotification := ss.Notify && (lastStatus != 0 || stateCode == StatusDown)
	if isNeedSendNotification {
		reporterServer := m[r.Reporter]
		notificationGroupID := ss.NotificationGroupID
		notificationMsg := Localizer.Tf("[%s] %s Reporter: %s, Error: %s", StatusCodeToString(stateCode), ss.Name, reporterServer.Name, mh.Data)
		muteLabel := NotificationMuteLabel.ServiceStateChanged(mh.GetId())

		// 鐘舵€佸彉鏇存椂锛屾竻闄ら潤闊崇紦瀛?
		if stateCode != lastStatus {
			NotificationShared.UnMuteNotification(notificationGroupID, muteLabel)
		}

		go NotificationShared.SendNotification(notificationGroupID, notificationMsg, muteLabel)
	}

	// 鍒ゆ柇鏄惁闇€瑕佽Е鍙戜换鍔?
	isNeedTriggerTask := ss.EnableTriggerTask && lastStatus != 0
	if isNeedTriggerTask {
		reporterServer := m[r.Reporter]
		if stateCode == StatusGood && lastStatus != stateCode {
			// 褰撳墠鐘舵€佹甯?鍓嶅簭鐘舵€侀潪姝ｅ父鏃?瑙﹀彂鎭㈠浠诲姟
			go CronShared.SendTriggerTasks(ss.RecoverTriggerTasks, reporterServer.ID, ss.UserID)
		} else if lastStatus == StatusGood && lastStatus != stateCode {
			// 鍓嶅簭鐘舵€佹甯?褰撳墠鐘舵€侀潪姝ｅ父鏃?瑙﹀彂澶辫触浠诲姟
			go CronShared.SendTriggerTasks(ss.FailTriggerTasks, reporterServer.ID, ss.UserID)
		}
	}
}

const (
	_ = iota
	StatusNoData
	StatusGood
	StatusLowAvailability
	StatusDown
)

func GetStatusCode[T constraints.Float | constraints.Integer](percent T) uint8 {
	if percent == 0 {
		return StatusNoData
	}
	if percent > 95 {
		return StatusGood
	}
	if percent > 80 {
		return StatusLowAvailability
	}
	return StatusDown
}

func StatusCodeToString(statusCode uint8) string {
	switch statusCode {
	case StatusNoData:
		return Localizer.T("No Data")
	case StatusGood:
		return Localizer.T("Good")
	case StatusLowAvailability:
		return Localizer.T("Low Availability")
	case StatusDown:
		return Localizer.T("Down")
	default:
		return ""
	}
}
