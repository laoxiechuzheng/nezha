package tsdb

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_Defaults(t *testing.T) {
	config := DefaultConfig()

	assert.Equal(t, "", config.DataPath) // 默认为空，不启用 TSDB
	assert.Equal(t, uint16(30), config.RetentionDays)
	assert.Equal(t, float64(1), config.MinFreeDiskSpaceGB)
	assert.Equal(t, time.Millisecond, config.DedupInterval)
	assert.False(t, config.Enabled())
}

func TestConfig_Enabled(t *testing.T) {
	config := &Config{DataPath: ""}
	assert.False(t, config.Enabled())

	config.DataPath = "data/tsdb"
	assert.True(t, config.Enabled())
}

func TestConfig_MinFreeDiskSpaceBytes(t *testing.T) {
	config := &Config{MinFreeDiskSpaceGB: 5}
	expected := int64(5 * 1024 * 1024 * 1024)
	assert.Equal(t, expected, config.MinFreeDiskSpaceBytes())
}

func TestTSDB_OpenClose(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "tsdb_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	config := &Config{
		DataPath:           filepath.Join(tempDir, "tsdb"),
		RetentionDays:      1,
		MinFreeDiskSpaceGB: 1,
		DedupInterval:      time.Second,
	}

	db, err := Open(config)
	require.NoError(t, err)
	require.NotNil(t, db)

	assert.False(t, db.IsClosed())
	assert.NotNil(t, db.Storage())
	assert.Equal(t, config, db.Config())

	err = db.Close()
	require.NoError(t, err)
	assert.True(t, db.IsClosed())

	// 重复关闭应该安全
	err = db.Close()
	require.NoError(t, err)
}

func TestTSDB_WriteServerMetrics(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "tsdb_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	config := &Config{
		DataPath:           filepath.Join(tempDir, "tsdb"),
		RetentionDays:      1,
		MinFreeDiskSpaceGB: 1,
		DedupInterval:      time.Second,
	}

	db, err := Open(config)
	require.NoError(t, err)
	defer db.Close()

	metrics := &ServerMetrics{
		ServerID:       1,
		Timestamp:      time.Now(),
		CPU:            50.5,
		MemUsed:        1024 * 1024 * 1024,
		SwapUsed:       512 * 1024 * 1024,
		DiskUsed:       10 * 1024 * 1024 * 1024,
		NetInSpeed:     1000000,
		NetOutSpeed:    500000,
		NetInTransfer:  1000000000,
		NetOutTransfer: 500000000,
		Load1:          1.5,
		Load5:          1.2,
		Load15:         1.0,
		TCPConnCount:   100,
		UDPConnCount:   50,
		ProcessCount:   200,
		Temperature:    65.5,
		Uptime:         86400,
		GPU:            30.0,
	}

	err = db.WriteServerMetrics(metrics)
	require.NoError(t, err)

	// 强制刷盘
	db.Flush()
}

func TestTSDB_WriteServiceMetrics(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "tsdb_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	config := &Config{
		DataPath:           filepath.Join(tempDir, "tsdb"),
		RetentionDays:      1,
		MinFreeDiskSpaceGB: 1,
		DedupInterval:      time.Second,
	}

	db, err := Open(config)
	require.NoError(t, err)
	defer db.Close()

	metrics := &ServiceMetrics{
		ServiceID:  1,
		ServerID:   1,
		Timestamp:  time.Now(),
		Delay:      45.5,
		Successful: true,
	}

	err = db.WriteServiceMetrics(metrics)
	require.NoError(t, err)

	// 测试失败状态
	metrics2 := &ServiceMetrics{
		ServiceID:  1,
		ServerID:   2,
		Timestamp:  time.Now(),
		Delay:      0,
		Successful: false,
	}

	err = db.WriteServiceMetrics(metrics2)
	require.NoError(t, err)

	// 强制刷盘
	db.Flush()
}

func TestTSDB_WriteBatchMetrics(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "tsdb_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	config := &Config{
		DataPath:           filepath.Join(tempDir, "tsdb"),
		RetentionDays:      1,
		MinFreeDiskSpaceGB: 1,
		DedupInterval:      time.Second,
	}

	db, err := Open(config)
	require.NoError(t, err)
	defer db.Close()

	// 批量写入服务器指标
	serverMetrics := []*ServerMetrics{
		{ServerID: 1, Timestamp: time.Now(), CPU: 10.0},
		{ServerID: 2, Timestamp: time.Now(), CPU: 20.0},
		{ServerID: 3, Timestamp: time.Now(), CPU: 30.0},
	}

	err = db.WriteBatchServerMetrics(serverMetrics)
	require.NoError(t, err)

	// 批量写入服务指标
	serviceMetrics := []*ServiceMetrics{
		{ServiceID: 1, ServerID: 1, Timestamp: time.Now(), Delay: 10.0, Successful: true},
		{ServiceID: 1, ServerID: 2, Timestamp: time.Now(), Delay: 20.0, Successful: true},
		{ServiceID: 2, ServerID: 1, Timestamp: time.Now(), Delay: 15.0, Successful: false},
	}

	err = db.WriteBatchServiceMetrics(serviceMetrics)
	require.NoError(t, err)

	db.Flush()
}

func TestTSDB_WriteToClosedDB(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "tsdb_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	config := &Config{
		DataPath:           filepath.Join(tempDir, "tsdb"),
		RetentionDays:      1,
		MinFreeDiskSpaceGB: 1,
		DedupInterval:      time.Second,
	}

	db, err := Open(config)
	require.NoError(t, err)

	db.Close()

	// 写入已关闭的数据库应该返回错误
	err = db.WriteServerMetrics(&ServerMetrics{ServerID: 1, Timestamp: time.Now()})
	assert.Error(t, err)

	err = db.WriteServiceMetrics(&ServiceMetrics{ServiceID: 1, ServerID: 1, Timestamp: time.Now()})
	assert.Error(t, err)
}

func TestQueryPeriod_Parse(t *testing.T) {
	tests := []struct {
		input    string
		expected QueryPeriod
		hasError bool
	}{
		{"1d", Period1Day, false},
		{"7d", Period7Days, false},
		{"30d", Period30Days, false},
		{"", Period1Day, false},
		{"invalid", "", true},
		{"1w", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			period, err := ParseQueryPeriod(tt.input)
			if tt.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, period)
			}
		})
	}
}

func TestQueryPeriod_Duration(t *testing.T) {
	assert.Equal(t, 6*time.Hour, Period6Hours.Duration())
	assert.Equal(t, 24*time.Hour, Period1Day.Duration())
	assert.Equal(t, 7*24*time.Hour, Period7Days.Duration())
	assert.Equal(t, 30*24*time.Hour, Period30Days.Duration())
}

func TestQueryPeriod_DownsampleInterval(t *testing.T) {
	assert.Equal(t, time.Millisecond, Period6Hours.DownsampleInterval())
	assert.Equal(t, 30*time.Second, Period1Day.DownsampleInterval())
	assert.Equal(t, 30*time.Minute, Period7Days.DownsampleInterval())
	assert.Equal(t, 2*time.Hour, Period30Days.DownsampleInterval())
}

func TestTSDB_QueryServiceHistory6HoursPreservesEveryProbe(t *testing.T) {
	tempDir := t.TempDir()
	db, err := Open(&Config{
		DataPath: filepath.Join(tempDir, "tsdb"), RetentionDays: 1,
		MinFreeDiskSpaceGB: 1, DedupInterval: time.Millisecond,
	})
	require.NoError(t, err)
	defer db.Close()

	now := time.Now().Truncate(time.Millisecond)
	probes := []*ServiceMetrics{
		{ServiceID: 10, ServerID: 20, Timestamp: now.Add(-10 * time.Second), Delay: 21, Successful: true},
		{ServiceID: 10, ServerID: 20, Timestamp: now.Add(-5 * time.Second), Successful: false, PacketLoss: 100, ErrorCode: 1},
		{ServiceID: 10, ServerID: 20, Timestamp: now, Delay: 23, Successful: true},
	}
	for _, probe := range probes {
		require.NoError(t, db.WriteServiceMetrics(probe))
	}
	db.Flush()

	result, err := db.QueryServiceHistory(10, Period6Hours)
	require.NoError(t, err)
	require.Len(t, result.Servers, 1)
	points := result.Servers[0].Stats.DataPoints
	require.Len(t, points, 3)
	assert.Equal(t, []int64{probes[0].Timestamp.UnixMilli(), probes[1].Timestamp.UnixMilli(), probes[2].Timestamp.UnixMilli()},
		[]int64{points[0].Timestamp, points[1].Timestamp, points[2].Timestamp})
	assert.Equal(t, []uint8{1, 0, 1}, []uint8{points[0].Status, points[1].Status, points[2].Status})
	assert.Equal(t, 100.0, points[1].PacketLoss)
	assert.Equal(t, uint8(1), points[1].ErrorCode)
}

func TestCompactServiceChartPointsPreservesRealOutageTransitions(t *testing.T) {
	points := make([]DataPoint, 5000)
	for i := range points {
		status := uint8(1)
		if i >= 2000 && i < 2100 {
			status = 0
		}
		points[i] = DataPoint{
			Timestamp: int64(i * 5000),
			Delay:     float64(i % 100),
			Status:    status,
		}
	}

	compacted := compactServiceChartPoints(points, 720)
	assert.LessOrEqual(t, len(compacted), 720)
	assert.Equal(t, points[0], compacted[0])
	assert.Equal(t, points[len(points)-1], compacted[len(compacted)-1])

	byTimestamp := make(map[int64]DataPoint, len(compacted))
	for _, point := range compacted {
		byTimestamp[point.Timestamp] = point
	}
	for _, index := range []int{1999, 2000, 2099, 2100} {
		actual, ok := byTimestamp[points[index].Timestamp]
		require.True(t, ok, "transition point %d must be preserved", index)
		assert.Equal(t, points[index], actual)
	}
}

func TestServiceChartDownsamplingUsesRealSamples(t *testing.T) {
	healthy := []rawDataPoint{
		{timestamp: 1000, value: 10, status: 1, hasDelay: true, hasStatus: true},
		{timestamp: 5000, value: 40, status: 1, hasDelay: true, hasStatus: true},
		{timestamp: 9000, value: 20, status: 1, hasDelay: true, hasStatus: true},
	}
	healthyPoints := downsample(healthy, 30*time.Second)
	require.Len(t, healthyPoints, 1)
	assert.Equal(t, int64(5000), healthyPoints[0].Timestamp)
	assert.Equal(t, 40.0, healthyPoints[0].Delay)
	assert.NotEqual(t, (10.0+40.0+20.0)/3.0, healthyPoints[0].Delay)

	withOutage := []rawDataPoint{
		{timestamp: 1000, value: 10, status: 1, hasDelay: true, hasStatus: true},
		{timestamp: 5000, value: 12, status: 1, hasDelay: true, hasStatus: true},
		{timestamp: 10000, status: 0, hasStatus: true, errorCode: 1, hasErrorCode: true},
		{timestamp: 15000, status: 0, hasStatus: true, errorCode: 1, hasErrorCode: true},
		{timestamp: 20000, value: 11, status: 1, hasDelay: true, hasStatus: true},
	}
	sampled := downsample(withOutage, 30*time.Second)
	merged := mergeServiceTransitions(sampled, withOutage)
	byTimestamp := make(map[int64]DataPoint, len(merged))
	for _, point := range merged {
		byTimestamp[point.Timestamp] = point
	}
	for _, timestamp := range []int64{5000, 10000, 15000, 20000} {
		_, ok := byTimestamp[timestamp]
		require.True(t, ok, "real transition sample %d must be preserved", timestamp)
	}
	assert.Equal(t, uint8(0), byTimestamp[10000].Status)
	assert.Equal(t, uint8(1), byTimestamp[20000].Status)
}

func TestTSDB_QueryServiceHistory(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "tsdb_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	config := &Config{
		DataPath:           filepath.Join(tempDir, "tsdb"),
		RetentionDays:      1,
		MinFreeDiskSpaceGB: 1,
		DedupInterval:      time.Second,
	}

	db, err := Open(config)
	require.NoError(t, err)
	defer db.Close()

	// 写入测试数据
	now := time.Now()
	serviceID := uint64(100)
	serverID1 := uint64(1)
	serverID2 := uint64(2)

	// 写入多条服务监控数据
	for i := 0; i < 10; i++ {
		ts := now.Add(-time.Duration(i) * time.Minute)

		// 服务器1的数据：成功
		err := db.WriteServiceMetrics(&ServiceMetrics{
			ServiceID:  serviceID,
			ServerID:   serverID1,
			Timestamp:  ts,
			Delay:      float64(10 + i),
			Successful: true,
		})
		require.NoError(t, err)

		// 服务器2的数据：部分失败
		err = db.WriteServiceMetrics(&ServiceMetrics{
			ServiceID:  serviceID,
			ServerID:   serverID2,
			Timestamp:  ts,
			Delay:      float64(20 + i),
			Successful: i%2 == 0, // 偶数成功，奇数失败
		})
		require.NoError(t, err)
	}

	// 强制刷盘确保数据可见
	db.Flush()

	// 查询服务历史
	result, err := db.QueryServiceHistory(serviceID, Period1Day)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, serviceID, result.ServiceID)
	require.Len(t, result.Servers, 2, "expected 2 servers")

	// 验证服务器统计
	for _, server := range result.Servers {
		if server.ServerID == serverID1 {
			// 服务器1全部成功
			assert.Equal(t, uint64(10), server.Stats.TotalUp)
			assert.Equal(t, uint64(0), server.Stats.TotalDown)
			assert.Equal(t, float32(100), server.Stats.UpPercent)
		} else if server.ServerID == serverID2 {
			// 服务器2一半成功
			assert.Equal(t, uint64(5), server.Stats.TotalUp)
			assert.Equal(t, uint64(5), server.Stats.TotalDown)
			assert.Equal(t, float32(50), server.Stats.UpPercent)
		}
	}
}

func TestTSDB_QueryServerMetrics(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "tsdb_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	config := &Config{
		DataPath:           filepath.Join(tempDir, "tsdb"),
		RetentionDays:      1,
		MinFreeDiskSpaceGB: 1,
		DedupInterval:      time.Second,
	}

	db, err := Open(config)
	require.NoError(t, err)
	defer db.Close()

	// 写入测试数据
	now := time.Now()
	serverID := uint64(1)

	for i := 0; i < 10; i++ {
		ts := now.Add(-time.Duration(i) * time.Minute)
		err := db.WriteServerMetrics(&ServerMetrics{
			ServerID:  serverID,
			Timestamp: ts,
			CPU:       float64(10 + i*5),
		})
		require.NoError(t, err)
	}

	// 强制刷盘确保数据可见
	db.Flush()

	// 查询服务器指标
	result, err := db.QueryServerMetrics(serverID, MetricServerCPU, Period1Day)
	require.NoError(t, err)
	require.NotEmpty(t, result, "expected data points")
}

func TestTSDB_QueryEmptyResult(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "tsdb_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	config := &Config{
		DataPath:           filepath.Join(tempDir, "tsdb"),
		RetentionDays:      1,
		MinFreeDiskSpaceGB: 1,
		DedupInterval:      time.Second,
	}

	db, err := Open(config)
	require.NoError(t, err)
	defer db.Close()

	// 查询不存在的服务历史
	result, err := db.QueryServiceHistory(9999, Period1Day)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Empty(t, result.Servers)

	// 查询不存在的服务器指标
	serverResult, err := db.QueryServerMetrics(9999, MetricServerCPU, Period1Day)
	require.NoError(t, err)
	assert.Empty(t, serverResult)
}

func TestTSDB_QueryClosedDB(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "tsdb_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	config := &Config{
		DataPath:           filepath.Join(tempDir, "tsdb"),
		RetentionDays:      1,
		MinFreeDiskSpaceGB: 1,
		DedupInterval:      time.Second,
	}

	db, err := Open(config)
	require.NoError(t, err)
	db.Close()

	// 查询已关闭的数据库应该返回错误
	_, err = db.QueryServiceHistory(1, Period1Day)
	assert.Error(t, err)

	_, err = db.QueryServerMetrics(1, MetricServerCPU, Period1Day)
	assert.Error(t, err)
}

func TestDownsample(t *testing.T) {
	points := []rawDataPoint{
		{timestamp: 0, value: 10, status: 1, hasDelay: true, hasStatus: true},
		{timestamp: 1000, value: 20, status: 1, hasDelay: true, hasStatus: true},
		{timestamp: 2000, value: 30, status: 0, hasDelay: true, hasStatus: true},
		{timestamp: 3000, value: 40, status: 1, hasDelay: true, hasStatus: true},
		{timestamp: 4000, value: 50, status: 1, hasDelay: true, hasStatus: true},
	}

	result := downsample(points, 2*time.Second)

	assert.Len(t, result, 3)

	for i := 1; i < len(result); i++ {
		assert.Greater(t, result[i].Timestamp, result[i-1].Timestamp)
	}
}

func TestCalculateStats(t *testing.T) {
	points := []rawDataPoint{
		{timestamp: 1000, value: 10, status: 1, hasDelay: true, hasStatus: true},
		{timestamp: 2000, value: 20, status: 1, hasDelay: true, hasStatus: true},
		{timestamp: 3000, value: 30, status: 0, hasDelay: true, hasStatus: true},
		{timestamp: 4000, value: 40, status: 1, hasDelay: true, hasStatus: true},
	}

	stats := calculateStats(points, 5*time.Minute)

	assert.Equal(t, uint64(3), stats.TotalUp)
	assert.Equal(t, uint64(1), stats.TotalDown)
	assert.Equal(t, float32(75), stats.UpPercent)
	assert.Equal(t, float64(25), stats.AvgDelay)
}

func TestCalculateStats_ZeroDelay(t *testing.T) {
	points := []rawDataPoint{
		{timestamp: 1000, value: 0, status: 1, hasDelay: true, hasStatus: true},
		{timestamp: 2000, value: 10, status: 1, hasDelay: true, hasStatus: true},
	}

	stats := calculateStats(points, 5*time.Minute)

	assert.Equal(t, float64(5), stats.AvgDelay)
	assert.Equal(t, uint64(2), stats.TotalUp)
}

func TestDownsampleReportsActualPacketLoss(t *testing.T) {
	points := []rawDataPoint{
		{timestamp: 1000, value: 10, status: 1, hasDelay: true, hasStatus: true, packetLoss: 0, hasPacketLoss: true},
		{timestamp: 2000, value: 20, status: 1, hasDelay: true, hasStatus: true, packetLoss: 0, hasPacketLoss: true},
		{timestamp: 3000, value: 30, status: 1, hasDelay: true, hasStatus: true, packetLoss: 0, hasPacketLoss: true},
		{timestamp: 4000, value: 0, status: 0, hasDelay: true, hasStatus: true, packetLoss: 100, hasPacketLoss: true},
	}

	result := downsample(points, time.Minute)
	require.Len(t, result, 1)
	assert.InDelta(t, 25.0, result[0].PacketLoss, 0.001)
	assert.InDelta(t, 20.0, result[0].Delay, 0.001)
	assert.Equal(t, uint8(0), result[0].Status, "one failed probe must keep the outage visible")
}

func TestCalculateStatsEmpty(t *testing.T) {
	points := []rawDataPoint{}
	stats := calculateStats(points, 5*time.Minute)

	assert.Equal(t, uint64(0), stats.TotalUp)
	assert.Equal(t, uint64(0), stats.TotalDown)
	assert.Equal(t, float32(0), stats.UpPercent)
	assert.Equal(t, float64(0), stats.AvgDelay)
	assert.Nil(t, stats.DataPoints)
}

func TestTSDB_QueryServerMetrics_Float64Precision(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "tsdb_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	config := &Config{
		DataPath:           filepath.Join(tempDir, "tsdb"),
		RetentionDays:      1,
		MinFreeDiskSpaceGB: 1,
		DedupInterval:      time.Second,
	}

	db, err := Open(config)
	require.NoError(t, err)
	defer db.Close()

	now := time.Now()
	serverID := uint64(1)
	largeMemValue := uint64(17_179_869_184) // 16GB

	err = db.WriteServerMetrics(&ServerMetrics{
		ServerID:  serverID,
		Timestamp: now,
		MemUsed:   largeMemValue,
	})
	require.NoError(t, err)

	db.Flush()

	result, err := db.QueryServerMetrics(serverID, MetricServerMemory, Period1Day)
	require.NoError(t, err)
	require.NotEmpty(t, result)

	// float64 可以精确表示该值，float32 会丢失精度
	assert.Equal(t, float64(largeMemValue), result[0].Value)
}

func TestTSDB_QueryServiceHistoryByServerID(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "tsdb_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	config := &Config{
		DataPath:           filepath.Join(tempDir, "tsdb"),
		RetentionDays:      1,
		MinFreeDiskSpaceGB: 1,
		DedupInterval:      time.Second,
	}

	db, err := Open(config)
	require.NoError(t, err)
	defer db.Close()

	now := time.Now()
	serverID := uint64(1)
	serviceID1 := uint64(100)
	serviceID2 := uint64(200)

	// 写入两个服务在同一服务器上的数据
	for i := 0; i < 5; i++ {
		ts := now.Add(-time.Duration(i) * time.Minute)

		err := db.WriteServiceMetrics(&ServiceMetrics{
			ServiceID:  serviceID1,
			ServerID:   serverID,
			Timestamp:  ts,
			Delay:      float64(10 + i),
			Successful: true,
		})
		require.NoError(t, err)

		err = db.WriteServiceMetrics(&ServiceMetrics{
			ServiceID:  serviceID2,
			ServerID:   serverID,
			Timestamp:  ts,
			Delay:      float64(20 + i),
			Successful: i%2 == 0,
		})
		require.NoError(t, err)
	}

	db.Flush()

	results, err := db.QueryServiceHistoryByServerID(serverID, Period1Day)
	require.NoError(t, err)
	require.Len(t, results, 2, "expected 2 services")

	// 验证 service1：全部成功
	s1, ok := results[serviceID1]
	require.True(t, ok)
	assert.Equal(t, serviceID1, s1.ServiceID)
	require.Len(t, s1.Servers, 1)
	assert.Equal(t, serverID, s1.Servers[0].ServerID)
	assert.Equal(t, uint64(5), s1.Servers[0].Stats.TotalUp)
	assert.Equal(t, uint64(0), s1.Servers[0].Stats.TotalDown)

	// 验证 service2：部分成功
	s2, ok := results[serviceID2]
	require.True(t, ok)
	assert.Equal(t, serviceID2, s2.ServiceID)
	assert.Equal(t, uint64(3), s2.Servers[0].Stats.TotalUp)
	assert.Equal(t, uint64(2), s2.Servers[0].Stats.TotalDown)
}

func TestTSDB_QueryServiceHistoryByServerID_Empty(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "tsdb_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	config := &Config{
		DataPath:           filepath.Join(tempDir, "tsdb"),
		RetentionDays:      1,
		MinFreeDiskSpaceGB: 1,
		DedupInterval:      time.Second,
	}

	db, err := Open(config)
	require.NoError(t, err)
	defer db.Close()

	results, err := db.QueryServiceHistoryByServerID(9999, Period1Day)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestTSDB_QueryServiceHistoryByServerID_ClosedDB(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "tsdb_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	config := &Config{
		DataPath:           filepath.Join(tempDir, "tsdb"),
		RetentionDays:      1,
		MinFreeDiskSpaceGB: 1,
		DedupInterval:      time.Second,
	}

	db, err := Open(config)
	require.NoError(t, err)
	db.Close()

	_, err = db.QueryServiceHistoryByServerID(1, Period1Day)
	assert.Error(t, err)
}
