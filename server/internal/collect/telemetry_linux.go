//go:build linux

package collect

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// collectLinuxTelemetry 通过 /proc、/sys 与只读系统命令采集性能、硬件、服务与端口。
func collectLinuxTelemetry(t Telemetry) (Telemetry, []string) {
	var warnings []string

	// 两次采样计算 CPU / 磁盘 / 网络速率
	cpuTotal1, cpuIdle1 := readCPUTimes()
	diskRead1, diskWrite1 := readDiskBytes()
	netRx1, netTx1 := readNetBytes()
	time.Sleep(300 * time.Millisecond)
	cpuTotal2, cpuIdle2 := readCPUTimes()
	diskRead2, diskWrite2 := readDiskBytes()
	netRx2, netTx2 := readNetBytes()

	const window = 0.3
	if cpuTotal2 > cpuTotal1 {
		total := float64(cpuTotal2 - cpuTotal1)
		idle := float64(cpuIdle2 - cpuIdle1)
		t.Metrics.CPUPercent = round2((total - idle) / total * 100)
	}
	t.Metrics.DiskReadBps = round2(float64(diskRead2-diskRead1) / window)
	t.Metrics.DiskWriteBps = round2(float64(diskWrite2-diskWrite1) / window)
	t.Metrics.NetRxBps = round2(float64(netRx2-netRx1) / window)
	t.Metrics.NetTxBps = round2(float64(netTx2-netTx1) / window)

	load1, load5, load15, ok := readLoadAvg()
	if ok {
		t.Metrics.Load1, t.Metrics.Load5, t.Metrics.Load15 = load1, load5, load15
	}
	mem := readMemInfo()
	t.Metrics.MemTotal = mem["MemTotal"]
	t.Metrics.MemUsed = subFloor(mem["MemTotal"], mem["MemAvailable"])
	t.Metrics.SwapTotal = mem["SwapTotal"]
	t.Metrics.SwapUsed = subFloor(mem["SwapTotal"], mem["SwapFree"])
	t.Metrics.ProcessCount = countProcesses()
	t.Metrics.UptimeSec = readUptime()

	t.Hardware = readLinuxHardware(mem["MemTotal"])

	services, warn := readLinuxServices()
	if warn != "" {
		warnings = append(warnings, warn)
	}
	t.Services = services

	ports, warn := readLinuxPorts()
	if warn != "" {
		warnings = append(warnings, warn)
	}
	t.Ports = ports
	return t, warnings
}

func readCPUTimes() (total, idle uint64) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)[1:]
		for i, raw := range fields {
			if i >= 8 {
				break
			}
			value, _ := strconv.ParseUint(raw, 10, 64)
			total += value
			if i == 3 || i == 4 { // idle + iowait
				idle += value
			}
		}
		break
	}
	return total, idle
}

func readDiskBytes() (read, write uint64) {
	data, err := os.ReadFile("/proc/diskstats")
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		name := fields[2]
		if _, err := os.Stat(filepath.Join("/sys/block", name)); err != nil {
			continue // 分区或虚拟设备
		}
		sectorsRead, _ := strconv.ParseUint(fields[5], 10, 64)
		sectorsWrite, _ := strconv.ParseUint(fields[9], 10, 64)
		read += sectorsRead * 512
		write += sectorsWrite * 512
	}
	return read, write
}

func readNetBytes() (rx, tx uint64) {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		name := strings.TrimSpace(line[:idx])
		if name == "lo" || name == "" {
			continue
		}
		fields := strings.Fields(line[idx+1:])
		if len(fields) < 9 {
			continue
		}
		rxBytes, _ := strconv.ParseUint(fields[0], 10, 64)
		txBytes, _ := strconv.ParseUint(fields[8], 10, 64)
		rx += rxBytes
		tx += txBytes
	}
	return rx, tx
}

func readLoadAvg() (float64, float64, float64, bool) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0, false
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return 0, 0, 0, false
	}
	l1, _ := strconv.ParseFloat(fields[0], 64)
	l5, _ := strconv.ParseFloat(fields[1], 64)
	l15, _ := strconv.ParseFloat(fields[2], 64)
	return l1, l5, l15, true
}

func readMemInfo() map[string]uint64 {
	out := map[string]uint64{}
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.TrimSuffix(fields[0], ":")
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		out[key] = value * 1024
	}
	return out
}

func readUptime() int64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	seconds, _ := strconv.ParseFloat(fields[0], 64)
	return int64(seconds)
}

func countProcesses() int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(entry.Name()); err == nil {
			count++
		}
	}
	return count
}

func readLinuxHardware(memTotal uint64) Hardware {
	hw := Hardware{MemTotal: memTotal, Disks: []DiskInfo{}, NICs: []NICInfo{}}
	hw.Kernel = strings.TrimSpace(readFile("/proc/sys/kernel/osrelease"))
	hw.Serial = firstNonEmpty(readFile("/sys/class/dmi/id/product_serial"), readFile("/sys/class/dmi/id/board_serial"))
	vendor := readFile("/sys/class/dmi/id/sys_vendor")
	model := readFile("/sys/class/dmi/id/product_name")
	if isVirtualVendor(vendor + " " + model) {
		hw.Virtualization = "virtual"
	} else if hw.Kernel != "" {
		hw.Virtualization = "physical"
	}
	parseCPUInfo(&hw)
	hw.Disks = readLinuxDisks()
	hw.NICs = readLinuxNICs()
	return hw
}

func parseCPUInfo(hw *Hardware) {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return
	}
	threads := 0
	cores := make(map[string]bool)
	var physicalID, coreID string
	flush := func() {
		if physicalID != "" || coreID != "" {
			cores[physicalID+"/"+coreID] = true
		}
		physicalID, coreID = "", ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch key {
		case "processor":
			threads++
		case "model name":
			if hw.CPUModel == "" {
				hw.CPUModel = value
			}
		case "physical id":
			physicalID = value
		case "core id":
			coreID = value
		}
	}
	flush()
	hw.CPUThreads = threads
	hw.CPUCores = len(cores)
	if hw.CPUCores == 0 {
		hw.CPUCores = threads
	}
}

func readLinuxDisks() []DiskInfo {
	entries, err := os.ReadDir("/sys/block")
	if err != nil {
		return []DiskInfo{}
	}
	out := make([]DiskInfo, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if hasAnyPrefix(name, "loop", "ram", "dm-", "sr", "fd", "zram", "md") {
			continue
		}
		base := filepath.Join("/sys/block", name)
		sectors, err := strconv.ParseUint(strings.TrimSpace(readFile(filepath.Join(base, "size"))), 10, 64)
		if err != nil {
			continue
		}
		out = append(out, DiskInfo{
			Device:    name,
			Model:     strings.TrimSpace(readFile(filepath.Join(base, "device/model"))),
			Serial:    strings.TrimSpace(readFile(filepath.Join(base, "device/serial"))),
			SizeBytes: sectors * 512,
		})
	}
	return out
}

func readLinuxNICs() []NICInfo {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return []NICInfo{}
	}
	out := make([]NICInfo, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if name == "lo" {
			continue
		}
		mac := strings.TrimSpace(readFile(filepath.Join("/sys/class/net", name, "address")))
		if mac == "" {
			continue
		}
		speed, _ := strconv.ParseInt(strings.TrimSpace(readFile(filepath.Join("/sys/class/net", name, "speed"))), 10, 64)
		if speed < 0 {
			speed = 0
		}
		out = append(out, NICInfo{Name: name, MAC: mac, SpeedMbps: speed})
	}
	return out
}

func readLinuxServices() ([]Service, string) {
	if _, err := exec.LookPath("systemctl"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		unitsOut, err := exec.CommandContext(ctx, "systemctl", "list-units", "--type=service", "--all",
			"--no-legend", "--plain", "--no-pager").Output()
		if err == nil {
			enabled := map[string]bool{}
			if filesOut, ferr := exec.CommandContext(ctx, "systemctl", "list-unit-files", "--type=service",
				"--no-legend", "--no-pager").Output(); ferr == nil {
				for _, line := range strings.Split(string(filesOut), "\n") {
					fields := strings.Fields(line)
					if len(fields) >= 2 {
						enabled[strings.TrimSuffix(fields[0], ".service")] = strings.HasPrefix(fields[1], "enabled")
					}
				}
			}
			out := make([]Service, 0, 64)
			for _, line := range strings.Split(string(unitsOut), "\n") {
				fields := strings.Fields(line)
				if len(fields) < 4 || strings.HasPrefix(fields[0], "●") {
					continue
				}
				name := strings.TrimSuffix(fields[0], ".service")
				if name == "" {
					continue
				}
				out = append(out, Service{
					Name:    name,
					State:   fields[2],
					Enabled: enabled[name],
					Detail:  strings.Join(fields[4:], " "),
				})
				if len(out) >= 200 {
					break
				}
			}
			return out, ""
		}
	}
	if _, err := exec.LookPath("rc-service"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		outBytes, err := exec.CommandContext(ctx, "rc-service", "--list").Output()
		if err == nil {
			out := make([]Service, 0, 64)
			for _, name := range strings.Fields(string(outBytes)) {
				out = append(out, Service{Name: name, State: "unknown"})
				if len(out) >= 200 {
					break
				}
			}
			return out, ""
		}
	}
	return []Service{}, "未找到 systemctl/rc-service，服务状态未采集"
}

func readLinuxPorts() ([]Port, string) {
	if _, err := exec.LookPath("ss"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		outBytes, err := exec.CommandContext(ctx, "ss", "-lntupH").Output()
		if err == nil {
			out := make([]Port, 0, 64)
			for _, line := range strings.Split(string(outBytes), "\n") {
				fields := strings.Fields(line)
				if len(fields) < 5 {
					continue
				}
				addr, port := splitAddrPort(fields[4])
				if port == 0 {
					continue
				}
				item := Port{Proto: fields[0], Addr: addr, Port: port}
				if len(fields) >= 6 {
					item.Process, item.PID = parseSSProcess(fields[5])
				}
				out = append(out, item)
				if len(out) >= 300 {
					break
				}
			}
			return out, ""
		}
	}
	return readLinuxProcPorts()
}

func readLinuxProcPorts() ([]Port, string) {
	out := make([]Port, 0, 64)
	for _, item := range []struct{ file, proto string }{{"/proc/net/tcp", "tcp"}, {"/proc/net/tcp6", "tcp6"}} {
		data, err := os.ReadFile(item.file)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) < 4 || fields[3] != "0A" {
				continue
			}
			parts := strings.Split(fields[1], ":")
			if len(parts) != 2 {
				continue
			}
			port64, err := strconv.ParseInt(parts[1], 16, 32)
			if err != nil || port64 <= 0 {
				continue
			}
			addr := decodeProcIPv4(parts[0])
			out = append(out, Port{Proto: item.proto, Addr: addr, Port: int(port64)})
			if len(out) >= 300 {
				return out, ""
			}
		}
	}
	if len(out) == 0 {
		return out, "未采集到监听端口（ss 与 /proc/net/tcp 均不可用）"
	}
	return out, ""
}

func splitAddrPort(raw string) (string, int) {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "[") {
		idx := strings.LastIndex(raw, "]:")
		if idx < 0 {
			return raw, 0
		}
		port, _ := strconv.Atoi(raw[idx+2:])
		return raw[1:idx], port
	}
	if strings.HasPrefix(raw, "0x") { // 兼容部分 ss 版本的十六进制展示
		parts := strings.Split(raw, ":")
		if len(parts) != 2 {
			return raw, 0
		}
		port64, _ := strconv.ParseInt(parts[1], 16, 32)
		return parts[0], int(port64)
	}
	idx := strings.LastIndex(raw, ":")
	if idx < 0 {
		return raw, 0
	}
	port, _ := strconv.Atoi(raw[idx+1:])
	addr := raw[:idx]
	if addr == "*" {
		addr = "0.0.0.0"
	}
	return addr, port
}

func decodeProcIPv4(hex string) string {
	if len(hex) != 8 {
		return hex
	}
	b := make([]byte, 4)
	for i := 0; i < 4; i++ {
		value, err := strconv.ParseUint(hex[i*2:i*2+2], 16, 8)
		if err != nil {
			return hex
		}
		b[3-i] = byte(value)
	}
	return net.IP(b).String()
}

func parseSSProcess(raw string) (string, int) {
	start := strings.Index(raw, "(\"")
	if start < 0 {
		return "", 0
	}
	rest := raw[start+2:]
	end := strings.Index(rest, "\"")
	if end < 0 {
		return "", 0
	}
	name := rest[:end]
	pid := 0
	if idx := strings.Index(rest, "pid="); idx >= 0 {
		value := rest[idx+4:]
		if comma := strings.IndexAny(value, ",)"); comma >= 0 {
			value = value[:comma]
		}
		pid, _ = strconv.Atoi(value)
	}
	return name, pid
}

func readFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func hasAnyPrefix(name string, prefixes ...string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// collectWindowsTelemetry 在 Linux 构建中不参与运行，仅保证调度函数可编译。
func collectWindowsTelemetry(t Telemetry) (Telemetry, []string) {
	return t, []string{"当前平台不支持 Windows 遥测"}
}
