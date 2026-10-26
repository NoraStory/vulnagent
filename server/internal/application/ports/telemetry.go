package ports

import "context"

// HostMetrics 一次性能采样
type HostMetrics struct {
	CPUPercent   float64 `json:"cpuPercent"`
	Load1        float64 `json:"load1"`
	Load5        float64 `json:"load5"`
	Load15       float64 `json:"load15"`
	MemUsed      uint64  `json:"memUsed"`
	MemTotal     uint64  `json:"memTotal"`
	SwapUsed     uint64  `json:"swapUsed"`
	SwapTotal    uint64  `json:"swapTotal"`
	DiskReadBps  float64 `json:"diskReadBps"`
	DiskWriteBps float64 `json:"diskWriteBps"`
	NetRxBps     float64 `json:"netRxBps"`
	NetTxBps     float64 `json:"netTxBps"`
	UptimeSec    int64   `json:"uptimeSec"`
	ProcessCount int     `json:"processCount"`
}

// DiskInfo 物理磁盘信息
type DiskInfo struct {
	Device    string `json:"device"`
	Model     string `json:"model"`
	Serial    string `json:"serial"`
	SizeBytes uint64 `json:"sizeBytes"`
}

// NICInfo 物理网卡信息
type NICInfo struct {
	Name      string `json:"name"`
	MAC       string `json:"mac"`
	SpeedMbps int64  `json:"speedMbps"`
}

// HostHardware 设备详情
type HostHardware struct {
	CPUModel       string     `json:"cpuModel"`
	CPUCores       int        `json:"cpuCores"`
	CPUThreads     int        `json:"cpuThreads"`
	MemTotal       uint64     `json:"memTotal"`
	Kernel         string     `json:"kernel"`
	Virtualization string     `json:"virtualization"`
	Serial         string     `json:"serial"`
	Disks          []DiskInfo `json:"disks"`
	NICs           []NICInfo  `json:"nics"`
}

// HostService 系统服务状态
type HostService struct {
	Name    string `json:"name"`
	State   string `json:"state"`
	Enabled bool   `json:"enabled"`
	Detail  string `json:"detail"`
}

// HostPort 监听端口
type HostPort struct {
	Proto   string `json:"proto"`
	Addr    string `json:"addr"`
	Port    int    `json:"port"`
	Process string `json:"process"`
	PID     int    `json:"pid"`
}

// HostTelemetry 一次完整遥测快照
type HostTelemetry struct {
	CollectedAt string        `json:"collectedAt"`
	Metrics     HostMetrics   `json:"metrics"`
	Hardware    HostHardware  `json:"hardware"`
	Services    []HostService `json:"services"`
	Ports       []HostPort    `json:"ports"`
}

// MetricPoint 性能时序点
type MetricPoint struct {
	TS           string  `json:"ts"`
	CPUPercent   float64 `json:"cpuPercent"`
	Load1        float64 `json:"load1"`
	MemUsed      uint64  `json:"memUsed"`
	MemTotal     uint64  `json:"memTotal"`
	NetRxBps     float64 `json:"netRxBps"`
	NetTxBps     float64 `json:"netTxBps"`
	DiskReadBps  float64 `json:"diskReadBps"`
	DiskWriteBps float64 `json:"diskWriteBps"`
}

// TelemetryRepository 主机遥测持久化端口
type TelemetryRepository interface {
	// Save 写入一次采样并整体替换硬件/服务/端口快照
	Save(ctx context.Context, assetID int64, t HostTelemetry) error
	// Latest 读取最新快照，不存在时 found=false
	Latest(ctx context.Context, assetID int64) (HostTelemetry, bool, error)
	// Series 返回最近 limit 个采样点，按时间升序
	Series(ctx context.Context, assetID int64, limit int) ([]MetricPoint, error)
}
