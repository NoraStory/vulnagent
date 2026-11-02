package main

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// sshAccelLiveScript 轻量实时采样：只读取运行态字段，不重复探测 CPU/驱动/系统信息
const sshAccelLiveScript = `export LC_ALL=C
if ! command -v nvidia-smi >/dev/null 2>&1; then
  echo "NOGPU|未检测到 nvidia-smi"
  exit 0
fi
nvidia-smi --query-gpu=index,uuid,name,memory.total,memory.used,utilization.gpu,utilization.memory,power.draw,power.limit,temperature.gpu,fan.speed,pstate,clocks_throttle_reasons.active --format=csv,noheader,nounits 2>/dev/null | head -8 | awk '{print "GPU|" $0}'
`

// accelLiveTTL 实时指标缓存，避免多个页面轮询时重复建立 SSH 会话
const accelLiveTTL = 3 * time.Second

type accelLiveGPU struct {
	Index             int     `json:"index"`
	UUID              string  `json:"uuid"`
	Name              string  `json:"name"`
	MemoryMB          int     `json:"memoryMb"`
	MemoryUsedMB      int     `json:"memoryUsedMb"`
	Utilization       float64 `json:"utilization"`
	MemoryUtilization float64 `json:"memoryUtilization"`
	PowerDrawW        float64 `json:"powerDrawW"`
	PowerLimitW       float64 `json:"powerLimitW"`
	TempC             float64 `json:"tempC"`
	FanPercent        float64 `json:"fanPercent"`
	PState            string  `json:"pstate"`
	Throttle          string  `json:"throttle"`
}

type sshAccelLive struct {
	HostID    int64          `json:"hostId"`
	HostName  string         `json:"hostName"`
	HostAddr  string         `json:"hostAddr"`
	SampledAt string         `json:"sampledAt"`
	ElapsedMs int64          `json:"elapsedMs"`
	Available bool           `json:"available"`
	GPUs      []accelLiveGPU `json:"gpus"`
	Error     string         `json:"error,omitempty"`
}

func parseSSHAccelLive(output string) sshAccelLive {
	live := sshAccelLive{GPUs: []accelLiveGPU{}}
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
		case "NOGPU":
			live.Error = strings.TrimSpace(parts[1])
		case "GPU":
			fields := splitAccelCSV(parts[1])
			if len(fields) < 13 {
				continue
			}
			live.GPUs = append(live.GPUs, accelLiveGPU{
				Index:             atoiCSV(fields[0]),
				UUID:              fields[1],
				Name:              fields[2],
				MemoryMB:          atoiCSV(fields[3]),
				MemoryUsedMB:      atoiCSV(fields[4]),
				Utilization:       floatCSV(fields[5]),
				MemoryUtilization: floatCSV(fields[6]),
				PowerDrawW:        floatCSV(fields[7]),
				PowerLimitW:       floatCSV(fields[8]),
				TempC:             floatCSV(fields[9]),
				FanPercent:        floatCSV(fields[10]),
				PState:            fields[11],
				Throttle:          fields[12],
			})
		}
	}
	live.Available = len(live.GPUs) > 0
	if !live.Available && live.Error == "" {
		live.Error = "未检测到可用的 NVIDIA GPU"
	}
	return live
}

func (a *App) sampleAccelLive(ctx context.Context, host sshHost) (sshAccelLive, error) {
	started := time.Now()
	probeCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	client, _, release, err := a.acquireSSHHost(probeCtx, host)
	if err != nil {
		return sshAccelLive{}, err
	}
	defer release()

	output, _, runErr := runSSHCommand(probeCtx, client, sshAccelLiveScript, 8*time.Second)
	live := parseSSHAccelLive(output)
	live.HostID = host.ID
	live.HostName = host.Name
	live.HostAddr = host.addr()
	live.SampledAt = fmtT(nowT())
	live.ElapsedMs = time.Since(started).Milliseconds()
	if runErr != nil && !live.Available {
		if live.Error == "" {
			live.Error = runErr.Error()
		}
		return live, runErr
	}
	return live, nil
}

func (a *App) cachedAccelLive(hostID int64) (sshAccelLive, bool) {
	a.accelLiveMu.Lock()
	defer a.accelLiveMu.Unlock()
	live, ok := a.accelLive[hostID]
	if !ok {
		return sshAccelLive{}, false
	}
	sampled, err := time.Parse(time.RFC3339, live.SampledAt)
	if err != nil || time.Since(sampled) >= accelLiveTTL {
		return sshAccelLive{}, false
	}
	return live, true
}

func (a *App) rememberAccelLive(live sshAccelLive) {
	a.accelLiveMu.Lock()
	defer a.accelLiveMu.Unlock()
	if a.accelLive == nil {
		a.accelLive = make(map[int64]sshAccelLive)
	}
	a.accelLive[live.HostID] = live
}

// handleSSHHostAccelLive 轻量实时 GPU 指标，供页面短轮询（viewer+）
func (a *App) handleSSHHostAccelLive(w http.ResponseWriter, r *http.Request) {
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
		if cached, ok := a.cachedAccelLive(host.ID); ok {
			writeJSON(w, http.StatusOK, cached)
			return
		}
	}
	live, err := a.sampleAccelLive(r.Context(), host)
	if err != nil {
		if live.HostID != 0 {
			writeJSON(w, http.StatusBadGateway, live)
			return
		}
		writeErr(w, http.StatusBadGateway, "ssh_failed", err.Error())
		return
	}
	a.rememberAccelLive(live)
	writeJSON(w, http.StatusOK, live)
}
