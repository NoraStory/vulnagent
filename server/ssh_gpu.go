package main

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"vulnagent/server/internal/application/ports"
)

// sshGPUScript 只读探测远端 NVIDIA GPU；打印 NOGPU 表示未安装驱动或非 NVIDIA 主机
const sshGPUScript = `export LC_ALL=C
if ! command -v nvidia-smi >/dev/null 2>&1; then
  echo "NOGPU|未检测到 nvidia-smi"
  exit 0
fi
nvidia-smi --query-gpu=name,memory.total,driver_version,utilization.gpu --format=csv,noheader,nounits 2>/dev/null | head -8
`

// sshGPUDevice 单块 GPU 的基础信息
type sshGPUDevice struct {
	Name        string  `json:"name"`
	MemoryMB    int     `json:"memoryMb"`
	Driver      string  `json:"driver"`
	Utilization float64 `json:"utilization"`
}

// sshGPUInfo 主机 GPU 探测结果
type sshGPUInfo struct {
	HostID        int64          `json:"hostId"`
	HostName      string         `json:"hostName"`
	Available     bool           `json:"available"`
	Name          string         `json:"name"`
	MemoryMB      int            `json:"memoryMb"`
	Driver        string         `json:"driver"`
	Utilization   float64        `json:"utilization"`
	Devices       []sshGPUDevice `json:"devices"`
	EndpointReady bool           `json:"endpointReady"`
	AccelEnabled  bool           `json:"accelEnabled"`
	Error         string         `json:"error,omitempty"`
	SampledAt     string         `json:"sampledAt"`
}

// parseSSHGPUInfo 解析 nvidia-smi 的 CSV 输出
func parseSSHGPUInfo(output string) sshGPUInfo {
	info := sshGPUInfo{Devices: []sshGPUDevice{}}
	for _, rawLine := range strings.Split(output, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "NOGPU|") {
			info.Error = strings.TrimPrefix(line, "NOGPU|")
			continue
		}
		fields := strings.SplitN(line, ",", 4)
		if len(fields) < 4 {
			continue
		}
		device := sshGPUDevice{
			Name:        strings.TrimSpace(fields[0]),
			Driver:      strings.TrimSpace(fields[2]),
			Utilization: parseFloatTrim(fields[3]),
		}
		device.MemoryMB, _ = strconv.Atoi(strings.TrimSpace(fields[1]))
		info.Devices = append(info.Devices, device)
	}
	if len(info.Devices) == 0 {
		if info.Error == "" {
			info.Error = "未检测到可用的 NVIDIA GPU"
		}
		return info
	}
	info.Available = true
	info.Name = info.Devices[0].Name
	info.MemoryMB = info.Devices[0].MemoryMB
	info.Driver = info.Devices[0].Driver
	info.Utilization = info.Devices[0].Utilization
	return info
}

func parseFloatTrim(raw string) float64 {
	value, _ := strconv.ParseFloat(strings.TrimSpace(strings.TrimSuffix(raw, "%")), 64)
	return round1(value)
}

// handleSSHHostGPU 探测主机 GPU（viewer+）
func (a *App) handleSSHHostGPU(w http.ResponseWriter, r *http.Request) {
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
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	client, _, err := a.dialSSHHost(ctx, host)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "ssh_failed", err.Error())
		return
	}
	defer client.Close()

	output, _, runErr := runSSHCommand(ctx, client, sshGPUScript, 12*time.Second)
	info := parseSSHGPUInfo(output)
	if runErr != nil && !info.Available {
		info.Error = runErr.Error()
	}
	info.HostID = host.ID
	info.HostName = host.Name
	info.EndpointReady = a.gpuLLM != nil
	info.AccelEnabled = host.GPUAccel
	info.SampledAt = fmtT(nowT())
	writeJSON(w, http.StatusOK, info)
}

// llmBenchResult 一组模型调用的耗时统计
type llmBenchResult struct {
	Model   string `json:"model"`
	AvgMs   int64  `json:"avgMs"`
	MinMs   int64  `json:"minMs"`
	MaxMs   int64  `json:"maxMs"`
	Samples int    `json:"samples"`
	Failed  int    `json:"failed"`
	Error   string `json:"error,omitempty"`
}

// sshGPUBenchmark 加速前后对比结果
type sshGPUBenchmark struct {
	HostID         int64          `json:"hostId"`
	HostName       string         `json:"hostName"`
	Detected       sshGPUInfo     `json:"detected"`
	Default        llmBenchResult `json:"default"`
	GPU            llmBenchResult `json:"gpu"`
	SpeedupPercent float64        `json:"speedupPercent"`
	Rounds         int            `json:"rounds"`
	SampledAt      string         `json:"sampledAt"`
}

const sshGPUBenchmarkPrompt = "用一句话说明 SSH 最小权限原则，控制在 30 字以内。"

// benchmarkLLM 预热一次后连续调用，统计成功调用的平均耗时
func benchmarkLLM(ctx context.Context, llm ports.LLM, prompt string, rounds int) llmBenchResult {
	result := llmBenchResult{Model: llm.Model(), MinMs: -1}
	warmCtx, cancelWarm := context.WithTimeout(ctx, 60*time.Second)
	_, _ = llm.Chat(warmCtx, ports.LLMRequest{Messages: []ports.LLMMessage{{Role: "user", Content: prompt}}})
	cancelWarm()

	var total time.Duration
	for index := 0; index < rounds; index++ {
		if ctx.Err() != nil {
			result.Error = ctx.Err().Error()
			break
		}
		callCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		started := time.Now()
		resp, err := llm.Chat(callCtx, ports.LLMRequest{Messages: []ports.LLMMessage{{Role: "user", Content: prompt}}})
		elapsed := time.Since(started)
		cancel()
		if err != nil {
			result.Failed++
			result.Error = truncateRunes(err.Error(), 200)
			continue
		}
		if strings.TrimSpace(resp.Content) == "" {
			result.Failed++
			result.Error = "模型返回空内容"
			continue
		}
		ms := elapsed.Milliseconds()
		if ms <= 0 {
			ms = 1
		}
		result.Samples++
		total += elapsed
		if result.MinMs < 0 || ms < result.MinMs {
			result.MinMs = ms
		}
		if ms > result.MaxMs {
			result.MaxMs = ms
		}
	}
	if result.Samples == 0 {
		result.MinMs, result.MaxMs = 0, 0
		return result
	}
	result.AvgMs = total.Milliseconds() / int64(result.Samples)
	if result.AvgMs <= 0 {
		result.AvgMs = 1
	}
	return result
}

// handleSSHHostGPUBenchmark 对比默认端点与 GPU 端点的推理耗时（operator+）
func (a *App) handleSSHHostGPUBenchmark(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
		return
	}
	if a.gpuLLM == nil {
		writeErr(w, http.StatusServiceUnavailable, "gpu_not_configured",
			"未配置 GPU 推理端点，请设置 VA_GPU_LLM_BASE_URL / VA_GPU_LLM_MODEL 后重启服务")
		return
	}
	if a.harness == nil || a.harness.LLM == nil {
		writeErr(w, http.StatusServiceUnavailable, "llm_unavailable", "未配置默认模型端点，无法对比加速前后效果")
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

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	client, _, err := a.dialSSHHost(ctx, host)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "ssh_failed", err.Error())
		return
	}
	output, _, _ := runSSHCommand(ctx, client, sshGPUScript, 12*time.Second)
	client.Close()
	info := parseSSHGPUInfo(output)
	info.HostID = host.ID
	info.HostName = host.Name
	info.EndpointReady = true
	info.AccelEnabled = host.GPUAccel
	info.SampledAt = fmtT(nowT())
	if !info.Available {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":    map[string]string{"code": "gpu_unavailable", "message": "该主机未检测到可用的 NVIDIA GPU"},
			"detected": info,
		})
		return
	}

	rounds := clampInt(queryInt(r, "rounds", 2), 1, 3)
	base := benchmarkLLM(ctx, a.harness.LLM, sshGPUBenchmarkPrompt, rounds)
	accelerated := benchmarkLLM(ctx, a.gpuLLM, sshGPUBenchmarkPrompt, rounds)
	benchmark := sshGPUBenchmark{
		HostID: host.ID, HostName: host.Name, Detected: info,
		Default: base, GPU: accelerated, Rounds: rounds, SampledAt: fmtT(nowT()),
	}
	if base.AvgMs > 0 && accelerated.AvgMs > 0 {
		benchmark.SpeedupPercent = round1((float64(base.AvgMs-accelerated.AvgMs) / float64(base.AvgMs)) * 100)
	}
	a.audit(r, "ssh.gpu.benchmark", host.Name,
		fmt.Sprintf("默认 %dms / GPU %dms，提升 %.1f%%", base.AvgMs, accelerated.AvgMs, benchmark.SpeedupPercent))
	writeJSON(w, http.StatusOK, benchmark)
}
