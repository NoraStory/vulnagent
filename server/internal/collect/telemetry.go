package collect

import (
	"runtime"
	"strings"
	"time"
)

// Metrics 一次主机性能采样
type Metrics struct {
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

// DiskInfo 物理磁盘
type DiskInfo struct {
	Device    string `json:"device"`
	Model     string `json:"model"`
	Serial    string `json:"serial"`
	SizeBytes uint64 `json:"sizeBytes"`
}

// NICInfo 物理网卡
type NICInfo struct {
	Name      string `json:"name"`
	MAC       string `json:"mac"`
	SpeedMbps int64  `json:"speedMbps"`
}

// Hardware 设备详情
type Hardware struct {
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

// Service 系统服务
type Service struct {
	Name    string `json:"name"`
	State   string `json:"state"`
	Enabled bool   `json:"enabled"`
	Detail  string `json:"detail"`
}

// Port 监听端口
type Port struct {
	Proto   string `json:"proto"`
	Addr    string `json:"addr"`
	Port    int    `json:"port"`
	Process string `json:"process"`
	PID     int    `json:"pid"`
}

// Process 进程资源占用（按内存排序的 Top N）
type Process struct {
	Name     string `json:"name"`
	PID      int    `json:"pid"`
	MemBytes uint64 `json:"memBytes"`
}

// Telemetry 一次完整遥测
type Telemetry struct {
	CollectedAt string    `json:"collectedAt"`
	Metrics     Metrics   `json:"metrics"`
	Hardware    Hardware  `json:"hardware"`
	Services    []Service `json:"services"`
	Ports       []Port    `json:"ports"`
	Processes   []Process `json:"processes"`
}

func collectTelemetry() (Telemetry, []string) {
	t := Telemetry{
		CollectedAt: time.Now().Format(time.RFC3339),
		Services:    []Service{},
		Ports:       []Port{},
		Processes:   []Process{},
		Hardware: Hardware{
			Disks: []DiskInfo{},
			NICs:  []NICInfo{},
		},
	}
	switch runtime.GOOS {
	case "linux":
		return collectLinuxTelemetry(t)
	case "windows":
		return collectWindowsTelemetry(t)
	default:
		return t, []string{"当前平台暂不支持主机遥测：" + runtime.GOOS}
	}
}

// sortedStrings 轻量去重排序辅助，供各平台复用
func sortedStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, item := range in {
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// round2 保留两位小数并裁掉负数，避免展示异常值。
func round2(v float64) float64 {
	if v < 0 {
		return 0
	}
	return float64(int64(v*100+0.5)) / 100
}

// subFloor 计算差值，b 大于 a 时返回 0。
func subFloor(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return 0
}

// isVirtualVendor 按厂商/型号关键字判断是否虚拟化环境。
func isVirtualVendor(text string) bool {
	lower := strings.ToLower(text)
	for _, keyword := range []string{"vmware", "virtualbox", "kvm", "qemu", "xen",
		"hyper-v", "microsoft corporation", "bochs", "parallels", "openstack"} {
		if strings.Contains(lower, keyword) {
			return true
		}
	}
	return false
}

// firstNonEmpty 返回第一个非空字符串。
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
