package main

import (
	"net/http"
	"strconv"

	"vulnagent/server/internal/application/ports"
	"vulnagent/server/internal/collect"
)

// toPortsTelemetry 把采集层的遥测结构转换为持久化层结构。
func toPortsTelemetry(in collect.Telemetry) ports.HostTelemetry {
	out := ports.HostTelemetry{
		CollectedAt: in.CollectedAt,
		Metrics: ports.HostMetrics{
			CPUPercent:   in.Metrics.CPUPercent,
			Load1:        in.Metrics.Load1,
			Load5:        in.Metrics.Load5,
			Load15:       in.Metrics.Load15,
			MemUsed:      in.Metrics.MemUsed,
			MemTotal:     in.Metrics.MemTotal,
			SwapUsed:     in.Metrics.SwapUsed,
			SwapTotal:    in.Metrics.SwapTotal,
			DiskReadBps:  in.Metrics.DiskReadBps,
			DiskWriteBps: in.Metrics.DiskWriteBps,
			NetRxBps:     in.Metrics.NetRxBps,
			NetTxBps:     in.Metrics.NetTxBps,
			UptimeSec:    in.Metrics.UptimeSec,
			ProcessCount: in.Metrics.ProcessCount,
		},
		Hardware: ports.HostHardware{
			CPUModel:       in.Hardware.CPUModel,
			CPUCores:       in.Hardware.CPUCores,
			CPUThreads:     in.Hardware.CPUThreads,
			MemTotal:       in.Hardware.MemTotal,
			Kernel:         in.Hardware.Kernel,
			Virtualization: in.Hardware.Virtualization,
			Serial:         in.Hardware.Serial,
			Disks:          make([]ports.DiskInfo, 0, len(in.Hardware.Disks)),
			NICs:           make([]ports.NICInfo, 0, len(in.Hardware.NICs)),
		},
		Services: make([]ports.HostService, 0, len(in.Services)),
		Ports:    make([]ports.HostPort, 0, len(in.Ports)),
	}
	for _, disk := range in.Hardware.Disks {
		out.Hardware.Disks = append(out.Hardware.Disks, ports.DiskInfo{
			Device: disk.Device, Model: disk.Model, Serial: disk.Serial, SizeBytes: disk.SizeBytes,
		})
	}
	for _, nic := range in.Hardware.NICs {
		out.Hardware.NICs = append(out.Hardware.NICs, ports.NICInfo{
			Name: nic.Name, MAC: nic.MAC, SpeedMbps: nic.SpeedMbps,
		})
	}
	for _, svc := range in.Services {
		out.Services = append(out.Services, ports.HostService{
			Name: svc.Name, State: svc.State, Enabled: svc.Enabled, Detail: svc.Detail,
		})
	}
	for _, port := range in.Ports {
		out.Ports = append(out.Ports, ports.HostPort{
			Proto: port.Proto, Addr: port.Addr, Port: port.Port, Process: port.Process, PID: port.PID,
		})
	}
	return out
}

// handleAssetTelemetry 返回资产最新遥测快照与性能时序
func (a *App) handleAssetTelemetry(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "viewer"); !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "无效的资产 ID")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 48
	}
	if limit > 1000 {
		limit = 1000
	}

	snapshot, found, err := a.telemetryRepo().Latest(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "查询主机遥测失败")
		return
	}
	series, err := a.telemetryRepo().Series(r.Context(), id, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "查询性能时序失败")
		return
	}
	var current *ports.HostTelemetry
	if found {
		current = &snapshot
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"telemetry": current,
		"series":    series,
	})
}
