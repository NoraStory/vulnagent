package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"vulnagent/server/internal/platform/clock"
)

// sshAccelScript 只读采集加速能力：NVIDIA GPU、CUDA、持久化模式、功耗/频率、CPU 调频策略
const sshAccelScript = `export LC_ALL=C
if command -v nvidia-smi >/dev/null 2>&1; then
  echo "NVSMI|1"
  nvidia-smi --query-gpu=name,memory.total,memory.used,driver_version,utilization.gpu,persistence_mode,power.limit,power.default_limit,clocks.current.graphics,clocks.max.graphics --format=csv,noheader,nounits 2>/dev/null | head -8 | awk '{print "GPU|" $0}'
  nvidia-smi 2>/dev/null | awk -F'CUDA Version: ' 'NR<8 && NF>1 {split($2,a," "); print "CUDA|" a[1]; exit}'
  nvidia-smi --query-gpu=clocks_throttle_reasons.active --format=csv,noheader 2>/dev/null | head -8 | awk '{print "THROTTLE|" $0}'
else
  echo "NVSMI|0"
fi
echo "CPU|$(awk -F: '/model name/{gsub(/^ +/,"",$2); print $2; exit}' /proc/cpuinfo)"
echo "GOV|$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo unknown)"
echo "CORES|$(nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo)"
echo "MEM|$(awk '/MemTotal/{print $2}' /proc/meminfo)"
echo "SWAP|$(awk '/SwapTotal/{print $2}' /proc/meminfo)"
if command -v hashcat >/dev/null 2>&1; then
  echo "HASHCAT|$(hashcat --version 2>/dev/null | head -1)"
else
  echo "HASHCAT|"
fi
`

// accelProfileTTL 加速能力探测缓存时长，避免连续打开页面重复建立 SSH 会话
const accelProfileTTL = 60 * time.Second

// accelGPU 单块 GPU 的加速相关状态
type accelGPU struct {
	Name          string  `json:"name"`
	MemoryMB      int     `json:"memoryMb"`
	MemoryUsedMB  int     `json:"memoryUsedMb"`
	Driver        string  `json:"driver"`
	Utilization   float64 `json:"utilization"`
	Persistence   string  `json:"persistenceMode"`
	PowerLimitW   float64 `json:"powerLimitW"`
	PowerDefaultW float64 `json:"powerDefaultW"`
	ClockMHz      float64 `json:"clockMhz"`
	MaxClockMHz   float64 `json:"maxClockMhz"`
	Throttle      string  `json:"throttle"`
}

// accelSuggestion 只读检测得出的优化建议，不自动修改主机
type accelSuggestion struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Detail  string `json:"detail"`
	Command string `json:"command"`
	Impact  string `json:"impact"`
	Risk    string `json:"risk"`
}

// sshHostAccelProfile 主机服务加速能力与系统状态
type sshHostAccelProfile struct {
	HostID           int64             `json:"hostId"`
	HostName         string            `json:"hostName"`
	HostAddr         string            `json:"hostAddr"`
	SampledAt        string            `json:"sampledAt"`
	ElapsedMs        int64             `json:"elapsedMs"`
	Available        bool              `json:"available"`
	NvidiaSMI        bool              `json:"nvidiaSmi"`
	GPUs             []accelGPU        `json:"gpus"`
	CUDA             string            `json:"cuda"`
	CPUModel         string            `json:"cpuModel"`
	CPUCores         int               `json:"cpuCores"`
	Governor         string            `json:"cpuGovernor"`
	MemTotalKB       int64             `json:"memTotalKb"`
	SwapTotalKB      int64             `json:"swapTotalKb"`
	EndpointReady    bool              `json:"endpointReady"`
	AccelEnabled     bool              `json:"accelEnabled"`
	BaselineAt       string            `json:"baselineAt,omitempty"`
	HashcatAvailable bool              `json:"hashcatAvailable"`
	HashcatVersion   string            `json:"hashcatVersion"`
	Suggestions      []accelSuggestion `json:"suggestions"`
}

// parseSSHAccelProfile 解析采集脚本的 KEY|value 行
func parseSSHAccelProfile(output string) (sshHostAccelProfile, error) {
	profile := sshHostAccelProfile{GPUs: []accelGPU{}, Suggestions: []accelSuggestion{}}
	seen := false
	throttles := make([]string, 0, 4)
	for _, rawLine := range strings.Split(output, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 2)
		if len(parts) < 2 {
			continue
		}
		switch parts[0] {
		case "NVSMI":
			seen = true
			profile.NvidiaSMI = strings.TrimSpace(parts[1]) == "1"
		case "GPU":
			fields := strings.Split(parts[1], ",")
			if len(fields) < 10 {
				continue
			}
			gpu := accelGPU{
				Name:          strings.TrimSpace(fields[0]),
				Driver:        strings.TrimSpace(fields[3]),
				Utilization:   parseFloatTrim(fields[4]),
				Persistence:   strings.TrimSpace(fields[5]),
				PowerLimitW:   parseFloatTrim(fields[6]),
				PowerDefaultW: parseFloatTrim(fields[7]),
				ClockMHz:      parseFloatTrim(fields[8]),
				MaxClockMHz:   parseFloatTrim(fields[9]),
			}
			gpu.MemoryMB, _ = strconv.Atoi(strings.TrimSpace(fields[1]))
			gpu.MemoryUsedMB, _ = strconv.Atoi(strings.TrimSpace(fields[2]))
			profile.GPUs = append(profile.GPUs, gpu)
		case "CUDA":
			profile.CUDA = strings.TrimSpace(parts[1])
		case "THROTTLE":
			throttles = append(throttles, strings.TrimSpace(parts[1]))
		case "CPU":
			profile.CPUModel = strings.TrimSpace(parts[1])
		case "GOV":
			profile.Governor = strings.TrimSpace(parts[1])
		case "CORES":
			profile.CPUCores, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
		case "MEM":
			profile.MemTotalKB, _ = strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
		case "SWAP":
			profile.SwapTotalKB, _ = strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
		case "HASHCAT":
			profile.HashcatVersion = strings.TrimSpace(parts[1])
			profile.HashcatAvailable = profile.HashcatVersion != ""
		}
	}
	if !seen {
		return profile, errors.New("无法解析主机加速信息")
	}
	for index := range profile.GPUs {
		if index < len(throttles) {
			profile.GPUs[index].Throttle = throttles[index]
		}
	}
	profile.Available = profile.NvidiaSMI && len(profile.GPUs) > 0
	return profile, nil
}

// buildAccelSuggestions 基于探测结果给出只读优化建议
func buildAccelSuggestions(profile *sshHostAccelProfile) []accelSuggestion {
	suggestions := make([]accelSuggestion, 0, 4)
	if !profile.NvidiaSMI {
		return append(suggestions, accelSuggestion{
			ID:      "install-driver",
			Title:   "未检测到 NVIDIA 驱动",
			Detail:  "主机未安装 nvidia-smi，无法使用 GPU 服务加速。安装官方驱动后重新检测。",
			Command: "nvidia-smi",
			Impact:  "启用 GPU 加速能力",
			Risk:    "low",
		})
	}
	if len(profile.GPUs) == 0 {
		return append(suggestions, accelSuggestion{
			ID:     "no-device",
			Title:  "驱动正常但无可用 GPU",
			Detail: "nvidia-smi 可执行但未返回设备，可能是显卡未挂载或被容器隔离。",
			Risk:   "low",
		})
	}
	for index, gpu := range profile.GPUs {
		if !strings.EqualFold(gpu.Persistence, "Enabled") {
			suggestions = append(suggestions, accelSuggestion{
				ID:      fmt.Sprintf("persistence-%d", index),
				Title:   fmt.Sprintf("GPU %d 未开启持久化模式", index),
				Detail:  "频繁创建短任务时，持久化模式可减少驱动初始化与显存回收延迟。",
				Command: fmt.Sprintf("sudo nvidia-smi -i %d -pm 1", index),
				Impact:  "降低短任务启动抖动",
				Risk:    "low",
			})
		}
		if gpu.PowerDefaultW > 0 && gpu.PowerLimitW > 0 && gpu.PowerLimitW < gpu.PowerDefaultW-1 {
			suggestions = append(suggestions, accelSuggestion{
				ID:      fmt.Sprintf("power-%d", index),
				Title:   fmt.Sprintf("GPU %d 功耗上限低于出厂值", index),
				Detail:  fmt.Sprintf("当前 %.0fW，出厂上限 %.0fW；受限功耗会直接压缩算力。", gpu.PowerLimitW, gpu.PowerDefaultW),
				Command: fmt.Sprintf("sudo nvidia-smi -i %d -pl %.0f", index, gpu.PowerDefaultW),
				Impact:  "恢复出厂算力上限",
				Risk:    "medium",
			})
		}
		if strings.Contains(strings.ToLower(gpu.Throttle), "power cap") {
			suggestions = append(suggestions, accelSuggestion{
				ID:     fmt.Sprintf("thermal-%d", index),
				Title:  fmt.Sprintf("GPU %d 触发功耗/温度降频", index),
				Detail: "运行中检测到功耗或温度限制，持续负载下算力会下降，建议检查供电与散热。",
				Impact: "避免长任务中途降频",
				Risk:   "low",
			})
		}
	}
	if profile.Governor != "" && profile.Governor != "unknown" && profile.Governor != "performance" {
		suggestions = append(suggestions, accelSuggestion{
			ID:      "cpu-governor",
			Title:   "CPU 调频策略不是 performance",
			Detail:  fmt.Sprintf("当前策略为 %s，加速任务对 CPU 侧调度与数据搬运较敏感。", profile.Governor),
			Command: "echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor",
			Impact:  "降低调度抖动，提升数据准备速度",
			Risk:    "medium",
		})
	}
	if profile.SwapTotalKB > 0 {
		suggestions = append(suggestions, accelSuggestion{
			ID:     "swap-enabled",
			Title:  "主机启用了 Swap",
			Detail: "加速任务占用大量内存时可能换页到磁盘，导致耗时波动；建议评估关闭或降低 swappiness。",
			Risk:   "low",
		})
	}
	return suggestions
}

// ---------- 基线 ----------

type accelBaselineRecord struct {
	Profile   sshHostAccelProfile
	Metrics   sshHostMetrics
	CreatedBy string
	CreatedAt string
}

func (a *App) saveAccelBaseline(ctx context.Context, hostID int64, profile sshHostAccelProfile, metrics sshHostMetrics, actor, at string) error {
	profileJSON, err := json.Marshal(profile)
	if err != nil {
		return err
	}
	metricsJSON, err := json.Marshal(metrics)
	if err != nil {
		return err
	}
	_, err = a.db.ExecContext(ctx, `INSERT INTO ssh_accel_baselines(host_id, profile, metrics, created_by, created_at)
		VALUES(?,?,?,?,?)
		ON CONFLICT(host_id) DO UPDATE SET
			profile=excluded.profile, metrics=excluded.metrics,
			created_by=excluded.created_by, created_at=excluded.created_at`,
		hostID, string(profileJSON), string(metricsJSON), actor, at)
	return err
}

func (a *App) loadAccelBaseline(ctx context.Context, hostID int64) (accelBaselineRecord, error) {
	var (
		record                   accelBaselineRecord
		profileJSON, metricsJSON string
	)
	err := a.db.QueryRowContext(ctx, `SELECT profile, metrics, created_by, created_at
		FROM ssh_accel_baselines WHERE host_id = ?`, hostID).
		Scan(&profileJSON, &metricsJSON, &record.CreatedBy, &record.CreatedAt)
	if err != nil {
		return record, err
	}
	if err := json.Unmarshal([]byte(profileJSON), &record.Profile); err != nil {
		return record, err
	}
	if err := json.Unmarshal([]byte(metricsJSON), &record.Metrics); err != nil {
		return record, err
	}
	return record, nil
}

// accelBaselineAt 返回最近一次基线时间，无记录时返回空串
func (a *App) accelBaselineAt(ctx context.Context, hostID int64) string {
	var createdAt string
	err := a.db.QueryRowContext(ctx, `SELECT created_at FROM ssh_accel_baselines WHERE host_id = ?`, hostID).Scan(&createdAt)
	if err != nil {
		return ""
	}
	return createdAt
}

// ---------- 采集 ----------

// sampleHostAccel 在同一 SSH 连接内采集加速能力与性能指标
func (a *App) sampleHostAccel(ctx context.Context, host sshHost) (sshHostAccelProfile, sshHostMetrics, error) {
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	started := time.Now()
	client, _, release, err := a.acquireSSHHost(ctx, host)
	if err != nil {
		return sshHostAccelProfile{}, sshHostMetrics{}, err
	}
	defer release()

	profileOutput, _, runErr := runSSHCommand(ctx, client, sshAccelScript, 15*time.Second)
	profile, parseErr := parseSSHAccelProfile(profileOutput)
	if parseErr != nil {
		if runErr != nil {
			return profile, sshHostMetrics{}, runErr
		}
		return profile, sshHostMetrics{}, parseErr
	}
	metricsOutput, _, _ := runSSHCommand(ctx, client, sshMetricScript, 12*time.Second)
	metrics, metricsErr := parseSSHHostMetrics(metricsOutput)
	if metricsErr == nil {
		metrics.HostID = host.ID
		metrics.HostName = host.Name
		metrics.HostAddr = host.addr()
		metrics.SampledAt = fmtT(nowT())
	}

	profile.Available = profile.NvidiaSMI && len(profile.GPUs) > 0
	profile.EndpointReady = a.gpuLLM != nil
	profile.AccelEnabled = host.GPUAccel
	profile.HostID = host.ID
	profile.HostName = host.Name
	profile.HostAddr = host.addr()
	profile.SampledAt = fmtT(nowT())
	profile.ElapsedMs = time.Since(started).Milliseconds()
	profile.Suggestions = buildAccelSuggestions(&profile)
	a.rememberAccelProfile(profile)
	return profile, metrics, nil
}

func (a *App) rememberAccelProfile(profile sshHostAccelProfile) {
	a.accelMu.Lock()
	defer a.accelMu.Unlock()
	if a.accelProfiles == nil {
		a.accelProfiles = make(map[int64]sshHostAccelProfile)
	}
	a.accelProfiles[profile.HostID] = profile
}

func (a *App) cachedAccelProfile(hostID int64) (sshHostAccelProfile, bool) {
	a.accelMu.Lock()
	defer a.accelMu.Unlock()
	profile, ok := a.accelProfiles[hostID]
	return profile, ok
}

// ---------- 对比 ----------

type accelMetricDelta struct {
	Key      string  `json:"key"`
	Label    string  `json:"label"`
	Before   float64 `json:"before"`
	After    float64 `json:"after"`
	Delta    float64 `json:"delta"`
	Unit     string  `json:"unit"`
	Better   string  `json:"better"`
	Improved bool    `json:"improved"`
}

type sshAccelComparison struct {
	HostID      int64               `json:"hostId"`
	HostName    string              `json:"hostName"`
	BaselineAt  string              `json:"baselineAt"`
	BaselineBy  string              `json:"baselineBy"`
	CurrentAt   string              `json:"currentAt"`
	ElapsedMs   int64               `json:"elapsedMs"`
	Metrics     []accelMetricDelta  `json:"metrics"`
	Changes     []string            `json:"changes"`
	Before      sshHostAccelProfile `json:"before"`
	After       sshHostAccelProfile `json:"after"`
	Suggestions []accelSuggestion   `json:"suggestions"`
}

func accelDelta(key, label string, before, after float64, unit, better string) accelMetricDelta {
	delta := after - before
	improved := false
	switch better {
	case "lower":
		improved = delta < 0
	case "higher":
		improved = delta > 0
	}
	return accelMetricDelta{
		Key: key, Label: label, Before: round1(before), After: round1(after),
		Delta: round1(delta), Unit: unit, Better: better, Improved: improved,
	}
}

// buildAccelComparison 对比基线与此前状态，给出指标变化与配置变更
func buildAccelComparison(before sshHostAccelProfile, beforeMetrics sshHostMetrics, after sshHostAccelProfile, afterMetrics sshHostMetrics) sshAccelComparison {
	comparison := sshAccelComparison{
		HostID: after.HostID, HostName: after.HostName,
		CurrentAt: after.SampledAt, ElapsedMs: after.ElapsedMs,
		Before: before, After: after, Changes: []string{},
		Metrics:     []accelMetricDelta{},
		Suggestions: after.Suggestions,
	}
	if beforeMetrics.HostID != 0 {
		comparison.Metrics = append(comparison.Metrics,
			accelDelta("cpu", "CPU 使用率", beforeMetrics.CPUPercent, afterMetrics.CPUPercent, "%", "lower"),
			accelDelta("mem", "内存使用率", beforeMetrics.MemPercent, afterMetrics.MemPercent, "%", "lower"),
			accelDelta("load1", "系统负载 1m", beforeMetrics.Load1, afterMetrics.Load1, "", "lower"),
		)
	}
	if len(before.GPUs) > 0 && len(after.GPUs) > 0 {
		comparison.Metrics = append(comparison.Metrics,
			accelDelta("gpu-util", "GPU 利用率", before.GPUs[0].Utilization, after.GPUs[0].Utilization, "%", "none"),
			accelDelta("gpu-clock", "GPU 当前频率", before.GPUs[0].ClockMHz, after.GPUs[0].ClockMHz, "MHz", "higher"),
		)
		if before.GPUs[0].PowerLimitW > 0 && after.GPUs[0].PowerLimitW > 0 &&
			before.GPUs[0].PowerLimitW != after.GPUs[0].PowerLimitW {
			comparison.Changes = append(comparison.Changes,
				fmt.Sprintf("GPU 功耗上限：%.0fW → %.0fW", before.GPUs[0].PowerLimitW, after.GPUs[0].PowerLimitW))
		}
		for index := 0; index < len(before.GPUs) && index < len(after.GPUs); index++ {
			if before.GPUs[index].Persistence != after.GPUs[index].Persistence {
				comparison.Changes = append(comparison.Changes,
					fmt.Sprintf("GPU %d 持久化模式：%s → %s", index, before.GPUs[index].Persistence, after.GPUs[index].Persistence))
			}
		}
	}
	if before.Governor != "" && after.Governor != "" && before.Governor != after.Governor {
		comparison.Changes = append(comparison.Changes,
			fmt.Sprintf("CPU 调频策略：%s → %s", before.Governor, after.Governor))
	}
	return comparison
}

// ---------- HTTP ----------

func (a *App) handleSSHHostAccel(w http.ResponseWriter, r *http.Request) {
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
	if r.URL.Query().Get("refresh") != "1" {
		if cached, ok := a.cachedAccelProfile(host.ID); ok {
			if sampled, parseErr := clock.Parse(cached.SampledAt); parseErr == nil && time.Since(sampled) < accelProfileTTL {
				cached.BaselineAt = a.accelBaselineAt(r.Context(), host.ID)
				writeJSON(w, http.StatusOK, cached)
				return
			}
		}
	}
	profile, _, err := a.sampleHostAccel(r.Context(), host)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "accel_failed", err.Error())
		return
	}
	profile.BaselineAt = a.accelBaselineAt(r.Context(), host.ID)
	writeJSON(w, http.StatusOK, profile)
}

func (a *App) handleSSHHostAccelBaseline(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "operator")
	if !ok {
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
	profile, metrics, err := a.sampleHostAccel(r.Context(), host)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "accel_failed", err.Error())
		return
	}
	createdAt := fmtT(nowT())
	if err := a.saveAccelBaseline(r.Context(), host.ID, profile, metrics, u.Username, createdAt); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "保存加速基线失败")
		return
	}
	profile.BaselineAt = createdAt
	a.audit(r, "ssh.accel.baseline", host.Name, "记录服务加速基线")
	writeJSON(w, http.StatusOK, map[string]any{
		"profile": profile, "metrics": metrics, "createdAt": createdAt,
	})
}

func (a *App) handleSSHHostAccelCompare(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
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
	baseline, err := a.loadAccelBaseline(r.Context(), host.ID)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "no_baseline", "尚未记录加速基线，请先记录基线再对比")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取加速基线失败")
		return
	}
	profile, metrics, err := a.sampleHostAccel(r.Context(), host)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "accel_failed", err.Error())
		return
	}
	profile.BaselineAt = baseline.CreatedAt
	comparison := buildAccelComparison(baseline.Profile, baseline.Metrics, profile, metrics)
	comparison.BaselineAt = baseline.CreatedAt
	comparison.BaselineBy = baseline.CreatedBy
	a.audit(r, "ssh.accel.compare", host.Name, "对比服务加速基线")
	writeJSON(w, http.StatusOK, comparison)
}

// handleAccelHosts 列出已启用服务加速的主机，作为服务端计算任务调度的候选节点
func (a *App) handleAccelHosts(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "viewer"); !ok {
		return
	}
	hosts, err := a.listSSHHosts(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取加速节点失败")
		return
	}
	items := make([]map[string]any, 0, len(hosts))
	for _, host := range hosts {
		if !host.GPUAccel {
			continue
		}
		item := map[string]any{
			"hostId": host.ID, "hostName": host.Name, "hostAddr": host.addr(),
			"accelEnabled": true, "endpointReady": a.gpuLLM != nil,
			"available": false, "cuda": "", "gpuName": "", "lastProfiledAt": "",
		}
		if profile, ok := a.cachedAccelProfile(host.ID); ok {
			item["available"] = profile.Available
			item["cuda"] = profile.CUDA
			item["lastProfiledAt"] = profile.SampledAt
			if len(profile.GPUs) > 0 {
				item["gpuName"] = profile.GPUs[0].Name
			}
		}
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
