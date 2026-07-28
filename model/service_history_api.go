package model

// ServiceInfos 服务监控信息（兼容旧API）
type ServiceInfos struct {
	ServiceID    uint64    `json:"monitor_id"`
	ServerID     uint64    `json:"server_id"`
	ServiceName  string    `json:"monitor_name"`
	ServerName   string    `json:"server_name"`
	DisplayIndex int       `json:"display_index"` // 展示排序，越大越靠前
	Duration     uint64    `json:"duration"`
	CreatedAt    []int64   `json:"created_at"`
	AvgDelay     []float64 `json:"avg_delay"`
	PacketLoss   []float64 `json:"packet_loss,omitempty"`
	Status       []uint8   `json:"status,omitempty"`
	ErrorCode    []uint8   `json:"error_code,omitempty"`
}

// DataPoint 数据点
type DataPoint struct {
	Timestamp  int64   `json:"ts"`
	Delay      float64 `json:"delay"`
	Status     uint8   `json:"status"`      // 1=成功, 0=失败
	PacketLoss float64 `json:"packet_loss"` // 当前时间桶的真实失败比例（0-100）
	ErrorCode  uint8   `json:"error_code,omitempty"`
}

const (
	ServiceErrorNone uint8 = iota
	ServiceErrorTimeout
	ServiceErrorRefused
	ServiceErrorDNS
	ServiceErrorUnreachable
	ServiceErrorInvalidTarget
	ServiceErrorOther
)

type ServiceLatestResult struct {
	ServiceID   uint64  `json:"monitor_id"`
	ServiceName string  `json:"monitor_name"`
	ServerID    uint64  `json:"server_id"`
	ServerName  string  `json:"server_name"`
	Duration    uint64  `json:"duration"`
	Timestamp   int64   `json:"created_at"`
	Delay       float64 `json:"delay"`
	Successful  bool    `json:"successful"`
	ErrorCode   uint8   `json:"error_code"`
	Error       string  `json:"error,omitempty"`
}

type ServiceLiveResponse struct {
	ServerID      uint64                `json:"server_id"`
	ServerName    string                `json:"server_name"`
	MinDurationMs int64                 `json:"min_duration_ms"`
	Results       []ServiceLatestResult `json:"results"`
}

// ServiceHistorySummary 服务历史统计摘要
type ServiceHistorySummary struct {
	AvgDelay   float64     `json:"avg_delay"`
	UpPercent  float32     `json:"up_percent"`
	TotalUp    uint64      `json:"total_up"`
	TotalDown  uint64      `json:"total_down"`
	DataPoints []DataPoint `json:"data_points,omitempty"`
}

// ServerServiceStats 某服务器对某服务的统计
type ServerServiceStats struct {
	ServerID   uint64                `json:"server_id"`
	ServerName string                `json:"server_name,omitempty"`
	Stats      ServiceHistorySummary `json:"stats"`
}

// ServiceHistoryResponse 服务历史查询响应
type ServiceHistoryResponse struct {
	ServiceID   uint64               `json:"service_id"`
	ServiceName string               `json:"service_name,omitempty"`
	Servers     []ServerServiceStats `json:"servers"`
}

// ServerMetricsDataPoint 服务器指标数据点
type ServerMetricsDataPoint struct {
	Timestamp int64   `json:"ts"`
	Value     float64 `json:"value"`
}

// ServerMetricsResponse 服务器指标历史查询响应
type ServerMetricsResponse struct {
	ServerID   uint64                   `json:"server_id"`
	ServerName string                   `json:"server_name,omitempty"`
	Metric     string                   `json:"metric"`
	DataPoints []ServerMetricsDataPoint `json:"data_points"`
}
