package main

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// sshMetricSampleSeconds 两次采样的间隔，用于把网络计数器换算为速率
const sshMetricSampleSeconds = 0.6

// sshHostMetrics 一次主机性能采样结果
type sshHostMetrics struct {
	HostID         int64             `json:"hostId"`
	HostName       string            `json:"hostName"`
	HostAddr       string            `json:"hostAddr"`
	SampledAt      string            `json:"sampledAt"`
	ElapsedMs      int64             `json:"elapsedMs"`
	CPUPercent     float64           `json:"cpuPercent"`
	CPUCores       int               `json:"cpuCores"`
	MemTotalKB     int64             `json:"memTotalKb"`
	MemUsedKB      int64             `json:"memUsedKb"`
	MemAvailableKB int64             `json:"memAvailableKb"`
	MemPercent     float64           `json:"memPercent"`
	SwapTotalKB    int64             `json:"swapTotalKb"`
	SwapUsedKB     int64             `json:"swapUsedKb"`
	SwapPercent    float64           `json:"swapPercent"`
	Load1          float64           `json:"load1"`
	Load5          float64           `json:"load5"`
	Load15         float64           `json:"load15"`
	UptimeSeconds  int64             `json:"uptimeSeconds"`
	Processes      int               `json:"processes"`
	NetRxBps       float64           `json:"netRxBps"`
	NetTxBps       float64           `json:"netTxBps"`
	Disks          []sshDiskUsage    `json:"disks"`
	Top            []sshProcessUsage `json:"top"`
}

// sshDiskUsage 单个挂载点的磁盘占用
type sshDiskUsage struct {
	Mount   string  `json:"mount"`
	TotalKB int64   `json:"totalKb"`
	UsedKB  int64   `json:"usedKb"`
	AvailKB int64   `json:"availKb"`
	Percent float64 `json:"percent"`
}

// sshProcessUsage CPU 占用最高的进程
type sshProcessUsage struct {
	PID        int     `json:"pid"`
	Command    string  `json:"command"`
	CPUPercent float64 `json:"cpuPercent"`
	MemPercent float64 `json:"memPercent"`
}

// sshMetricScript 只读采集脚本：两次快照换算 CPU 与网卡速率，其余直接读取 /proc
const sshMetricScript = `export LC_ALL=C
cpu_snap() { awk '/^cpu /{printf "%.0f %.0f", $2+$3+$4+$7+$8+$9, $5+$6}' /proc/stat; }
net_snap() { awk -F'[: ]+' '/^ *(eth|ens|enp|eno|wlan|bond|br-|docker|veth)/ {rx+=$3; tx+=$11} END {printf "%.0f %.0f", rx+0, tx+0}' /proc/net/dev; }
set -- $(cpu_snap); cb1=$1; ci1=$2
set -- $(net_snap); nr1=$1; nt1=$2
sleep 0.6
set -- $(cpu_snap); cb2=$1; ci2=$2
set -- $(net_snap); nr2=$1; nt2=$2
echo "CPU|$cb1|$ci1|$cb2|$ci2"
echo "NET|$nr1|$nt1|$nr2|$nt2"
awk -F':' '/^(MemTotal|MemAvailable|MemFree|Buffers|Cached|SwapTotal|SwapFree):/ {gsub(/^ +| +$/,"",$2); split($2,a," "); printf "MEM|%s|%s\n",$1,a[1]}' /proc/meminfo
awk '{printf "LOAD|%s|%s|%s\n",$1,$2,$3}' /proc/loadavg
awk '{printf "UPTIME|%.0f\n",$1}' /proc/uptime
echo "CPUS|$(nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo)"
echo "PROCS|$(ps -e --no-headers 2>/dev/null | wc -l | tr -d ' ')"
df -P -k 2>/dev/null | awk 'NR>1 && $1 !~ /^(tmpfs|devtmpfs|shm|squashfs)$/ {printf "DISK|%s|%.0f|%.0f|%.0f|%s\n",$6,$2,$3,$4,$5}'
ps -eo pid=,comm=,%cpu=,%mem= --sort=-%cpu 2>/dev/null | head -5 | awk '{printf "TOP|%s|%s|%s|%s\n",$1,$3,$4,$2}'
`

// handleSSHHostMetrics 通过只读 SSH 命令采样主机性能（viewer+）
func (a *App) handleSSHHostMetrics(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "viewer"); !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "主机 ID 无效")
		return
	}
	host, err := a.getSSHHost(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "主机不存在")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	started := time.Now()
	client, _, err := a.dialSSHHost(ctx, host)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "ssh_failed", err.Error())
		return
	}
	defer client.Close()

	output, _, runErr := runSSHCommand(ctx, client, sshMetricScript, 10*time.Second)
	metrics, parseErr := parseSSHHostMetrics(output)
	if parseErr != nil {
		message := "读取主机性能失败"
		if runErr != nil {
			message = runErr.Error()
		}
		writeErr(w, http.StatusBadGateway, "metrics_failed", message)
		return
	}
	metrics.HostID = host.ID
	metrics.HostName = host.Name
	metrics.HostAddr = host.addr()
	metrics.SampledAt = fmtT(nowT())
	metrics.ElapsedMs = time.Since(started).Milliseconds()
	writeJSON(w, http.StatusOK, metrics)
}

// parseSSHHostMetrics 解析采集脚本输出的 KEY|value 行
func parseSSHHostMetrics(output string) (sshHostMetrics, error) {
	metrics := sshHostMetrics{Disks: []sshDiskUsage{}, Top: []sshProcessUsage{}}
	mem := make(map[string]float64)
	var cpu [4]float64
	var net [4]float64
	hasCPU := false

	for _, rawLine := range strings.Split(output, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "|")
		switch parts[0] {
		case "CPU":
			if len(parts) == 5 {
				for i := 0; i < 4; i++ {
					cpu[i], _ = strconv.ParseFloat(parts[i+1], 64)
				}
				hasCPU = true
			}
		case "NET":
			if len(parts) == 5 {
				for i := 0; i < 4; i++ {
					net[i], _ = strconv.ParseFloat(parts[i+1], 64)
				}
			}
		case "MEM":
			if len(parts) == 3 {
				if value, err := strconv.ParseFloat(parts[2], 64); err == nil {
					mem[parts[1]] = value
				}
			}
		case "LOAD":
			if len(parts) == 4 {
				metrics.Load1, _ = strconv.ParseFloat(parts[1], 64)
				metrics.Load5, _ = strconv.ParseFloat(parts[2], 64)
				metrics.Load15, _ = strconv.ParseFloat(parts[3], 64)
			}
		case "UPTIME":
			if len(parts) == 2 {
				value, _ := strconv.ParseFloat(parts[1], 64)
				metrics.UptimeSeconds = int64(value)
			}
		case "CPUS":
			if len(parts) == 2 {
				metrics.CPUCores, _ = strconv.Atoi(parts[1])
			}
		case "PROCS":
			if len(parts) == 2 {
				metrics.Processes, _ = strconv.Atoi(parts[1])
			}
		case "DISK":
			if len(parts) == 6 {
				total, _ := strconv.ParseFloat(parts[2], 64)
				used, _ := strconv.ParseFloat(parts[3], 64)
				avail, _ := strconv.ParseFloat(parts[4], 64)
				percent, _ := strconv.ParseFloat(strings.TrimSuffix(parts[5], "%"), 64)
				metrics.Disks = append(metrics.Disks, sshDiskUsage{
					Mount: parts[1], TotalKB: int64(total), UsedKB: int64(used),
					AvailKB: int64(avail), Percent: round1(percent),
				})
			}
		case "TOP":
			if len(parts) == 5 {
				pid, _ := strconv.Atoi(parts[1])
				cpuPercent, _ := strconv.ParseFloat(parts[2], 64)
				memPercent, _ := strconv.ParseFloat(parts[3], 64)
				metrics.Top = append(metrics.Top, sshProcessUsage{
					PID: pid, Command: parts[4], CPUPercent: round1(cpuPercent), MemPercent: round1(memPercent),
				})
			}
		}
	}

	if !hasCPU || len(mem) == 0 {
		return metrics, fmt.Errorf("无法解析主机性能数据")
	}

	busyDelta := cpu[2] - cpu[0]
	idleDelta := cpu[3] - cpu[1]
	if total := busyDelta + idleDelta; total > 0 {
		metrics.CPUPercent = round1(busyDelta / total * 100)
	}
	if metrics.CPUPercent < 0 {
		metrics.CPUPercent = 0
	}
	if metrics.CPUPercent > 100 {
		metrics.CPUPercent = 100
	}

	rxDelta := net[2] - net[0]
	txDelta := net[3] - net[1]
	if rxDelta > 0 {
		metrics.NetRxBps = round1(rxDelta / sshMetricSampleSeconds)
	}
	if txDelta > 0 {
		metrics.NetTxBps = round1(txDelta / sshMetricSampleSeconds)
	}

	metrics.MemTotalKB = int64(mem["MemTotal"])
	metrics.MemAvailableKB = int64(mem["MemAvailable"])
	if metrics.MemAvailableKB == 0 {
		metrics.MemAvailableKB = int64(mem["MemFree"] + mem["Buffers"] + mem["Cached"])
	}
	if metrics.MemTotalKB > 0 {
		metrics.MemUsedKB = metrics.MemTotalKB - metrics.MemAvailableKB
		if metrics.MemUsedKB < 0 {
			metrics.MemUsedKB = 0
		}
		metrics.MemPercent = round1(float64(metrics.MemUsedKB) / float64(metrics.MemTotalKB) * 100)
	}
	metrics.SwapTotalKB = int64(mem["SwapTotal"])
	if metrics.SwapTotalKB > 0 {
		metrics.SwapUsedKB = metrics.SwapTotalKB - int64(mem["SwapFree"])
		if metrics.SwapUsedKB < 0 {
			metrics.SwapUsedKB = 0
		}
		metrics.SwapPercent = round1(float64(metrics.SwapUsedKB) / float64(metrics.SwapTotalKB) * 100)
	}
	return metrics, nil
}
