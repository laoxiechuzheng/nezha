package tsdb

import (
	"fmt"
	"log"
	"sort"
	"strconv"
	"time"

	"github.com/VictoriaMetrics/VictoriaMetrics/lib/storage"

	"github.com/nezhahq/nezha/model"
)

// QueryPeriod 查询时间段
type QueryPeriod string

const (
	Period1Day   QueryPeriod = "1d"
	Period6Hours QueryPeriod = "6h"
	Period7Days  QueryPeriod = "7d"
	Period30Days QueryPeriod = "30d"
)

// ParseQueryPeriod 解析查询时间段
func ParseQueryPeriod(s string) (QueryPeriod, error) {
	switch s {
	case "1d", "":
		return Period1Day, nil
	case "6h":
		return Period6Hours, nil
	case "7d":
		return Period7Days, nil
	case "30d":
		return Period30Days, nil
	default:
		return "", fmt.Errorf("invalid period: %s, expected 6h, 1d, 7d, or 30d", s)
	}
}

// Duration 返回时间段的时长
func (p QueryPeriod) Duration() time.Duration {
	switch p {
	case Period6Hours:
		return 6 * time.Hour
	case Period7Days:
		return 7 * 24 * time.Hour
	case Period30Days:
		return 30 * 24 * time.Hour
	default:
		return 24 * time.Hour
	}
}

// DownsampleInterval 返回降采样间隔
// 1d: 30秒一个点 (2880个点)
// 7d: 30分钟一个点 (336个点)
// 30d: 2小时一个点 (360个点)
func (p QueryPeriod) DownsampleInterval() time.Duration {
	switch p {
	case Period6Hours:
		return time.Millisecond
	case Period7Days:
		return 30 * time.Minute
	case Period30Days:
		return 2 * time.Hour
	default:
		return 30 * time.Second
	}
}

// Type aliases for model types used in tsdb package
type (
	DataPoint             = model.DataPoint
	ServiceHistorySummary = model.ServiceHistorySummary
	ServerServiceStats    = model.ServerServiceStats
	ServiceHistoryResult  = model.ServiceHistoryResponse
	MetricDataPoint       = model.ServerMetricsDataPoint
)

type rawDataPoint struct {
	timestamp     int64
	value         float64
	status        float64
	hasDelay      bool
	hasStatus     bool
	packetLoss    float64
	hasPacketLoss bool
	errorCode     uint8
	hasErrorCode  bool
}

const maxServiceChartPoints = 720

func (p rawDataPoint) hasReachableDelay() bool {
	if !p.hasDelay {
		return false
	}
	if p.hasPacketLoss {
		return p.packetLoss < 100 || p.value > 0
	}
	return true
}

func (db *TSDB) QueryServiceHistory(serviceID uint64, period QueryPeriod) (*ServiceHistoryResult, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	if db.closed {
		return nil, fmt.Errorf("TSDB is closed")
	}

	now := time.Now()
	tr := storage.TimeRange{
		MinTimestamp: now.Add(-period.Duration()).UnixMilli(),
		MaxTimestamp: now.UnixMilli(),
	}

	serviceIDStr := strconv.FormatUint(serviceID, 10)

	delayData, err := db.queryMetricByServiceID(MetricServiceDelay, serviceIDStr, tr)
	if err != nil {
		return nil, fmt.Errorf("failed to query delay data: %w", err)
	}

	statusData, err := db.queryMetricByServiceID(MetricServiceStatus, serviceIDStr, tr)
	if err != nil {
		return nil, fmt.Errorf("failed to query status data: %w", err)
	}
	packetLossData, err := db.queryMetricByServiceID(MetricServicePacketLoss, serviceIDStr, tr)
	if err != nil {
		return nil, fmt.Errorf("failed to query packet loss data: %w", err)
	}
	errorCodeData, err := db.queryMetricByServiceID(MetricServiceErrorCode, serviceIDStr, tr)
	if err != nil {
		return nil, fmt.Errorf("failed to query error code data: %w", err)
	}

	result := &ServiceHistoryResult{
		ServiceID: serviceID,
		Servers:   make([]ServerServiceStats, 0),
	}

	serverDataMap := make(map[uint64]map[int64]*rawDataPoint)

	for serverID, points := range delayData {
		if serverDataMap[serverID] == nil {
			serverDataMap[serverID] = make(map[int64]*rawDataPoint)
		}
		for _, p := range points {
			serverDataMap[serverID][p.timestamp] = &rawDataPoint{
				timestamp: p.timestamp,
				value:     p.value,
				hasDelay:  true,
			}
		}
	}

	for serverID, points := range statusData {
		if serverDataMap[serverID] == nil {
			serverDataMap[serverID] = make(map[int64]*rawDataPoint)
		}
		for _, p := range points {
			if existing, ok := serverDataMap[serverID][p.timestamp]; ok {
				existing.status = p.value
				existing.hasStatus = true
			} else {
				serverDataMap[serverID][p.timestamp] = &rawDataPoint{
					timestamp: p.timestamp,
					status:    p.value,
					hasStatus: true,
				}
			}
		}
	}
	mergePacketLossData(serverDataMap, packetLossData)
	mergeErrorCodeData(serverDataMap, errorCodeData)

	for serverID, pointsMap := range serverDataMap {
		points := make([]rawDataPoint, 0, len(pointsMap))
		for _, p := range pointsMap {
			points = append(points, *p)
		}
		stats := calculateStats(points, period.DownsampleInterval())
		result.Servers = append(result.Servers, ServerServiceStats{
			ServerID: serverID,
			Stats:    stats,
		})
	}

	sort.Slice(result.Servers, func(i, j int) bool {
		return result.Servers[i].ServerID < result.Servers[j].ServerID
	})

	return result, nil
}

type DailyServiceStats struct {
	Up    uint64
	Down  uint64
	Delay float64
}

func (db *TSDB) QueryServiceDailyStats(serviceID uint64, today time.Time, days int) ([]DailyServiceStats, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	if db.closed {
		return nil, fmt.Errorf("TSDB is closed")
	}

	stats := make([]DailyServiceStats, days)
	serviceIDStr := strconv.FormatUint(serviceID, 10)

	start := today.AddDate(0, 0, -(days - 1))
	tr := storage.TimeRange{
		MinTimestamp: start.UnixMilli(),
		MaxTimestamp: today.UnixMilli(),
	}

	statusData, err := db.queryMetricByServiceID(MetricServiceStatus, serviceIDStr, tr)
	if err != nil {
		return nil, err
	}
	delayData, err := db.queryMetricByServiceID(MetricServiceDelay, serviceIDStr, tr)
	if err != nil {
		return nil, err
	}

	for _, points := range statusData {
		for _, p := range points {
			ts := time.UnixMilli(p.timestamp)
			dayIndex := (days - 1) - int(today.Sub(ts).Hours())/24
			if dayIndex < 0 || dayIndex >= days {
				continue
			}
			if p.value >= 0.5 {
				stats[dayIndex].Up++
			} else {
				stats[dayIndex].Down++
			}
		}
	}

	delayCount := make([]int, days)
	for _, points := range delayData {
		for _, p := range points {
			ts := time.UnixMilli(p.timestamp)
			dayIndex := (days - 1) - int(today.Sub(ts).Hours())/24
			if dayIndex < 0 || dayIndex >= days {
				continue
			}
			stats[dayIndex].Delay = (stats[dayIndex].Delay*float64(delayCount[dayIndex]) + p.value) / float64(delayCount[dayIndex]+1)
			delayCount[dayIndex]++
		}
	}

	return stats, nil
}

type metricPoint struct {
	timestamp int64
	value     float64
}

func (db *TSDB) queryMetricByServiceID(metric MetricType, serviceID string, tr storage.TimeRange) (map[uint64][]metricPoint, error) {
	tfs := storage.NewTagFilters()
	if err := tfs.Add(nil, []byte(metric), false, false); err != nil {
		return nil, err
	}
	if err := tfs.Add([]byte("service_id"), []byte(serviceID), false, false); err != nil {
		return nil, err
	}

	deadline := uint64(time.Now().Add(30 * time.Second).Unix())

	var search storage.Search
	search.Init(nil, db.storage, []*storage.TagFilters{tfs}, tr, 100000, deadline)
	defer search.MustClose()

	result := make(map[uint64][]metricPoint)
	var timestamps []int64
	var values []float64

	for search.NextMetricBlock() {
		mbr := search.MetricBlockRef
		var block storage.Block
		mbr.BlockRef.MustReadBlock(&block)

		mn := storage.GetMetricName()
		if err := mn.Unmarshal(mbr.MetricName); err != nil {
			log.Printf("NEZHA>> TSDB: failed to unmarshal metric name: %v", err)
			storage.PutMetricName(mn)
			continue
		}

		serverIDBytes := mn.GetTagValue("server_id")
		if len(serverIDBytes) == 0 {
			storage.PutMetricName(mn)
			continue
		}

		serverID, err := strconv.ParseUint(string(serverIDBytes), 10, 64)
		if err != nil {
			log.Printf("NEZHA>> TSDB: failed to parse server_id %q: %v", string(serverIDBytes), err)
			storage.PutMetricName(mn)
			continue
		}
		storage.PutMetricName(mn)

		if err := block.UnmarshalData(); err != nil {
			log.Printf("NEZHA>> TSDB: failed to unmarshal block data: %v", err)
			continue
		}

		timestamps = timestamps[:0]
		values = values[:0]
		timestamps, values = block.AppendRowsWithTimeRangeFilter(timestamps, values, tr)

		for i := range timestamps {
			result[serverID] = append(result[serverID], metricPoint{
				timestamp: timestamps[i],
				value:     values[i],
			})
		}
	}

	if err := search.Error(); err != nil {
		return nil, err
	}

	return result, nil
}

func calculateStats(points []rawDataPoint, downsampleInterval time.Duration) ServiceHistorySummary {
	if len(points) == 0 {
		return ServiceHistorySummary{}
	}

	sort.Slice(points, func(i, j int) bool {
		return points[i].timestamp < points[j].timestamp
	})

	var totalDelay float64
	var delayCount int
	var totalUp, totalDown uint64

	for _, p := range points {
		if p.hasReachableDelay() {
			totalDelay += p.value
			delayCount++
		}
		if p.hasStatus {
			if p.status >= 0.5 {
				totalUp++
			} else {
				totalDown++
			}
		}
	}

	summary := ServiceHistorySummary{
		TotalUp:   totalUp,
		TotalDown: totalDown,
	}

	if delayCount > 0 {
		summary.AvgDelay = totalDelay / float64(delayCount)
	}

	if totalUp+totalDown > 0 {
		summary.UpPercent = float32(totalUp) / float32(totalUp+totalDown) * 100
	}

	summary.DataPoints = downsample(points, downsampleInterval)
	if downsampleInterval <= time.Millisecond {
		summary.DataPoints = compactServiceChartPoints(summary.DataPoints, maxServiceChartPoints)
	}

	return summary
}

// compactServiceChartPoints selects real probe samples for the browser chart.
// It never averages or invents latency values and always keeps outage/recovery
// transitions, so the full-resolution TSDB data remains untouched while 6h
// responses stay small enough to render promptly on phones.
func compactServiceChartPoints(points []DataPoint, maxPoints int) []DataPoint {
	if maxPoints < 2 || len(points) <= maxPoints {
		return points
	}

	mandatory := map[int]struct{}{0: {}, len(points) - 1: {}}
	for i := 1; i < len(points); i++ {
		if points[i].Status != points[i-1].Status {
			mandatory[i-1] = struct{}{}
			mandatory[i] = struct{}{}
		}
	}

	remaining := maxPoints - len(mandatory)
	if remaining > 0 {
		bucketSize := float64(len(points)) / float64(remaining)
		for bucket := 0; bucket < remaining; bucket++ {
			from := int(float64(bucket) * bucketSize)
			to := int(float64(bucket+1) * bucketSize)
			if to <= from {
				to = from + 1
			}
			if to > len(points) {
				to = len(points)
			}
			representative := from
			for i := from + 1; i < to; i++ {
				if points[i].Delay > points[representative].Delay {
					representative = i
				}
			}
			mandatory[representative] = struct{}{}
		}
	}

	indices := make([]int, 0, len(mandatory))
	for index := range mandatory {
		indices = append(indices, index)
	}
	sort.Ints(indices)

	result := make([]DataPoint, 0, len(indices))
	for _, index := range indices {
		result = append(result, points[index])
	}
	return result
}

func downsample(points []rawDataPoint, interval time.Duration) []DataPoint {
	if len(points) == 0 {
		return nil
	}

	intervalMs := interval.Milliseconds()
	result := make([]DataPoint, 0)

	// points 已排序，线性扫描分桶
	bucketStart := (points[0].timestamp / intervalMs) * intervalMs
	var totalDelay, totalPacketLoss float64
	var delayCount, upCount, statusCount, packetLossCount int
	var errorCode uint8

	flushBucket := func() {
		var avgDelay float64
		if delayCount > 0 {
			avgDelay = totalDelay / float64(delayCount)
		}
		var status uint8
		// A bucket is healthy only when every probe succeeded. This preserves
		// short outages in downsampled 1d/7d/30d views instead of hiding them
		// behind a majority of successful probes.
		if statusCount > 0 && upCount == statusCount {
			status = 1
		}
		var packetLoss float64
		if packetLossCount > 0 {
			packetLoss = totalPacketLoss / float64(packetLossCount)
		} else if statusCount > 0 {
			packetLoss = float64(statusCount-upCount) / float64(statusCount) * 100
		}
		result = append(result, DataPoint{
			Timestamp:  bucketStart,
			Delay:      avgDelay,
			Status:     status,
			PacketLoss: packetLoss,
			ErrorCode:  errorCode,
		})
	}

	for _, p := range points {
		key := (p.timestamp / intervalMs) * intervalMs
		if key != bucketStart {
			flushBucket()
			bucketStart = key
			totalDelay = 0
			delayCount = 0
			upCount = 0
			statusCount = 0
			totalPacketLoss = 0
			packetLossCount = 0
			errorCode = 0
		}
		if p.hasReachableDelay() {
			totalDelay += p.value
			delayCount++
		}
		if p.hasStatus {
			statusCount++
			if p.status >= 0.5 {
				upCount++
			}
		}
		if p.hasPacketLoss {
			totalPacketLoss += p.packetLoss
			packetLossCount++
		}
		if p.hasErrorCode && p.errorCode != model.ServiceErrorNone {
			errorCode = p.errorCode
		}
	}
	flushBucket()

	return result
}

func downsampleMetrics(points []rawDataPoint, interval time.Duration, useLastValue bool) []MetricDataPoint {
	if len(points) == 0 {
		return nil
	}

	sort.Slice(points, func(i, j int) bool {
		return points[i].timestamp < points[j].timestamp
	})

	intervalMs := interval.Milliseconds()
	result := make([]MetricDataPoint, 0)

	bucketStart := (points[0].timestamp / intervalMs) * intervalMs
	var total float64
	var count int
	var last rawDataPoint

	flushBucket := func() {
		var value float64
		if useLastValue {
			value = last.value
		} else if count > 0 {
			value = total / float64(count)
		}
		result = append(result, MetricDataPoint{
			Timestamp: bucketStart,
			Value:     value,
		})
	}

	for _, p := range points {
		key := (p.timestamp / intervalMs) * intervalMs
		if key != bucketStart {
			flushBucket()
			bucketStart = key
			total = 0
			count = 0
		}
		total += p.value
		count++
		last = p
	}
	flushBucket()

	return result
}

// isCumulativeMetric 判断指标是否为累积型（单调递增）
func isCumulativeMetric(metric MetricType) bool {
	switch metric {
	case MetricServerNetInTransfer, MetricServerNetOutTransfer, MetricServerUptime:
		return true
	default:
		return false
	}
}

func (db *TSDB) QueryServerMetrics(serverID uint64, metric MetricType, period QueryPeriod) ([]MetricDataPoint, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	if db.closed {
		return nil, fmt.Errorf("TSDB is closed")
	}

	now := time.Now()
	tr := storage.TimeRange{
		MinTimestamp: now.Add(-period.Duration()).UnixMilli(),
		MaxTimestamp: now.UnixMilli(),
	}

	serverIDStr := strconv.FormatUint(serverID, 10)

	tfs := storage.NewTagFilters()
	if err := tfs.Add(nil, []byte(metric), false, false); err != nil {
		return nil, err
	}
	if err := tfs.Add([]byte("server_id"), []byte(serverIDStr), false, false); err != nil {
		return nil, err
	}

	deadline := uint64(time.Now().Add(30 * time.Second).Unix())

	var search storage.Search
	search.Init(nil, db.storage, []*storage.TagFilters{tfs}, tr, 100000, deadline)
	defer search.MustClose()

	var points []rawDataPoint
	var timestamps []int64
	var values []float64

	for search.NextMetricBlock() {
		mbr := search.MetricBlockRef
		var block storage.Block
		mbr.BlockRef.MustReadBlock(&block)

		if err := block.UnmarshalData(); err != nil {
			log.Printf("NEZHA>> TSDB: failed to unmarshal block data: %v", err)
			continue
		}

		timestamps = timestamps[:0]
		values = values[:0]
		timestamps, values = block.AppendRowsWithTimeRangeFilter(timestamps, values, tr)

		for i := range timestamps {
			points = append(points, rawDataPoint{
				timestamp: timestamps[i],
				value:     values[i],
			})
		}
	}

	if err := search.Error(); err != nil {
		return nil, err
	}

	return downsampleMetrics(points, period.DownsampleInterval(), isCumulativeMetric(metric)), nil
}

func (db *TSDB) QueryServiceHistoryByServerID(serverID uint64, period QueryPeriod) (map[uint64]*ServiceHistoryResult, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	if db.closed {
		return nil, fmt.Errorf("TSDB is closed")
	}

	now := time.Now()
	tr := storage.TimeRange{
		MinTimestamp: now.Add(-period.Duration()).UnixMilli(),
		MaxTimestamp: now.UnixMilli(),
	}

	serverIDStr := strconv.FormatUint(serverID, 10)

	delayData, err := db.queryMetricByServerID(MetricServiceDelay, serverIDStr, tr)
	if err != nil {
		return nil, fmt.Errorf("failed to query delay data: %w", err)
	}

	statusData, err := db.queryMetricByServerID(MetricServiceStatus, serverIDStr, tr)
	if err != nil {
		return nil, fmt.Errorf("failed to query status data: %w", err)
	}
	packetLossData, err := db.queryMetricByServerID(MetricServicePacketLoss, serverIDStr, tr)
	if err != nil {
		return nil, fmt.Errorf("failed to query packet loss data: %w", err)
	}
	errorCodeData, err := db.queryMetricByServerID(MetricServiceErrorCode, serverIDStr, tr)
	if err != nil {
		return nil, fmt.Errorf("failed to query error code data: %w", err)
	}

	serviceDataMap := make(map[uint64]map[int64]*rawDataPoint)

	for serviceID, points := range delayData {
		if serviceDataMap[serviceID] == nil {
			serviceDataMap[serviceID] = make(map[int64]*rawDataPoint)
		}
		for _, p := range points {
			serviceDataMap[serviceID][p.timestamp] = &rawDataPoint{
				timestamp: p.timestamp,
				value:     p.value,
				hasDelay:  true,
			}
		}
	}

	for serviceID, points := range statusData {
		if serviceDataMap[serviceID] == nil {
			serviceDataMap[serviceID] = make(map[int64]*rawDataPoint)
		}
		for _, p := range points {
			if existing, ok := serviceDataMap[serviceID][p.timestamp]; ok {
				existing.status = p.value
				existing.hasStatus = true
			} else {
				serviceDataMap[serviceID][p.timestamp] = &rawDataPoint{
					timestamp: p.timestamp,
					status:    p.value,
					hasStatus: true,
				}
			}
		}
	}
	mergePacketLossData(serviceDataMap, packetLossData)
	mergeErrorCodeData(serviceDataMap, errorCodeData)

	results := make(map[uint64]*ServiceHistoryResult)

	for serviceID, pointsMap := range serviceDataMap {
		points := make([]rawDataPoint, 0, len(pointsMap))
		for _, p := range pointsMap {
			points = append(points, *p)
		}
		stats := calculateStats(points, period.DownsampleInterval())
		results[serviceID] = &ServiceHistoryResult{
			ServiceID: serviceID,
			Servers: []ServerServiceStats{{
				ServerID: serverID,
				Stats:    stats,
			}},
		}
	}

	return results, nil
}

func (db *TSDB) queryMetricByServerID(metric MetricType, serverID string, tr storage.TimeRange) (map[uint64][]metricPoint, error) {
	tfs := storage.NewTagFilters()
	if err := tfs.Add(nil, []byte(metric), false, false); err != nil {
		return nil, err
	}
	if err := tfs.Add([]byte("server_id"), []byte(serverID), false, false); err != nil {
		return nil, err
	}

	deadline := uint64(time.Now().Add(30 * time.Second).Unix())

	var search storage.Search
	search.Init(nil, db.storage, []*storage.TagFilters{tfs}, tr, 100000, deadline)
	defer search.MustClose()

	result := make(map[uint64][]metricPoint)
	var timestamps []int64
	var values []float64

	for search.NextMetricBlock() {
		mbr := search.MetricBlockRef
		var block storage.Block
		mbr.BlockRef.MustReadBlock(&block)

		mn := storage.GetMetricName()
		if err := mn.Unmarshal(mbr.MetricName); err != nil {
			log.Printf("NEZHA>> TSDB: failed to unmarshal metric name: %v", err)
			storage.PutMetricName(mn)
			continue
		}

		serviceIDBytes := mn.GetTagValue("service_id")
		if len(serviceIDBytes) == 0 {
			storage.PutMetricName(mn)
			continue
		}

		serviceID, err := strconv.ParseUint(string(serviceIDBytes), 10, 64)
		if err != nil {
			log.Printf("NEZHA>> TSDB: failed to parse service_id %q: %v", string(serviceIDBytes), err)
			storage.PutMetricName(mn)
			continue
		}
		storage.PutMetricName(mn)

		if err := block.UnmarshalData(); err != nil {
			log.Printf("NEZHA>> TSDB: failed to unmarshal block data: %v", err)
			continue
		}

		timestamps = timestamps[:0]
		values = values[:0]
		timestamps, values = block.AppendRowsWithTimeRangeFilter(timestamps, values, tr)

		for i := range timestamps {
			result[serviceID] = append(result[serviceID], metricPoint{
				timestamp: timestamps[i],
				value:     values[i],
			})
		}
	}

	if err := search.Error(); err != nil {
		return nil, err
	}

	return result, nil
}

func mergePacketLossData(target map[uint64]map[int64]*rawDataPoint, source map[uint64][]metricPoint) {
	for id, points := range source {
		if target[id] == nil {
			target[id] = make(map[int64]*rawDataPoint)
		}
		for _, p := range points {
			if existing, ok := target[id][p.timestamp]; ok {
				existing.packetLoss = p.value
				existing.hasPacketLoss = true
			} else {
				target[id][p.timestamp] = &rawDataPoint{
					timestamp:     p.timestamp,
					packetLoss:    p.value,
					hasPacketLoss: true,
				}
			}
		}
	}
}

func mergeErrorCodeData(target map[uint64]map[int64]*rawDataPoint, source map[uint64][]metricPoint) {
	for id, points := range source {
		if target[id] == nil {
			target[id] = make(map[int64]*rawDataPoint)
		}
		for _, p := range points {
			errorCode := uint8(p.value)
			if existing, ok := target[id][p.timestamp]; ok {
				existing.errorCode = errorCode
				existing.hasErrorCode = true
			} else {
				target[id][p.timestamp] = &rawDataPoint{
					timestamp: p.timestamp, errorCode: errorCode, hasErrorCode: true,
				}
			}
		}
	}
}
