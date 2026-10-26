package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"vulnagent/server/internal/application/ports"
	"vulnagent/server/internal/collect"
)

func TestToPortsTelemetry(t *testing.T) {
	in := collect.Telemetry{
		CollectedAt: "2026-01-01T10:00:00+08:00",
		Metrics: collect.Metrics{
			CPUPercent: 12.5, Load1: 0.8, MemUsed: 1 << 30, MemTotal: 2 << 30,
			NetRxBps: 100, NetTxBps: 200, DiskReadBps: 300, DiskWriteBps: 400,
			UptimeSec: 7200, ProcessCount: 88,
		},
		Hardware: collect.Hardware{
			CPUModel: "Test CPU", CPUCores: 2, CPUThreads: 4, MemTotal: 2 << 30,
			Kernel: "6.1", Virtualization: "virtual", Serial: "SN-1",
			Disks: []collect.DiskInfo{{Device: "vda", Model: "Disk", Serial: "D-1", SizeBytes: 10 << 30}},
			NICs:  []collect.NICInfo{{Name: "eth0", MAC: "aa:bb", SpeedMbps: 1000}},
		},
		Services: []collect.Service{{Name: "nginx", State: "active", Enabled: true, Detail: "web"}},
		Ports:    []collect.Port{{Proto: "tcp", Addr: "0.0.0.0", Port: 80, Process: "nginx", PID: 10}},
	}

	out := toPortsTelemetry(in)
	if out.CollectedAt != in.CollectedAt || out.Metrics.CPUPercent != 12.5 || out.Metrics.ProcessCount != 88 {
		t.Fatalf("指标映射异常：%+v", out.Metrics)
	}
	if out.Hardware.CPUModel != "Test CPU" || len(out.Hardware.Disks) != 1 || len(out.Hardware.NICs) != 1 {
		t.Fatalf("硬件映射异常：%+v", out.Hardware)
	}
	if len(out.Services) != 1 || out.Services[0].Name != "nginx" || !out.Services[0].Enabled {
		t.Fatalf("服务映射异常：%+v", out.Services)
	}
	if len(out.Ports) != 1 || out.Ports[0].Port != 80 || out.Ports[0].PID != 10 {
		t.Fatalf("端口映射异常：%+v", out.Ports)
	}
}

func TestHandleAssetTelemetry(t *testing.T) {
	app, _, assetID := newTicketTestApp(t)
	snapshot := toPortsTelemetry(collect.Telemetry{
		CollectedAt: "2026-01-01T10:00:00+08:00",
		Metrics:     collect.Metrics{CPUPercent: 42, MemUsed: 4 << 30, MemTotal: 8 << 30, ProcessCount: 100},
		Hardware: collect.Hardware{
			CPUModel: "Test CPU", CPUCores: 4, CPUThreads: 8, MemTotal: 8 << 30,
			Disks: []collect.DiskInfo{},
			NICs:  []collect.NICInfo{},
		},
		Services: []collect.Service{{Name: "sshd", State: "active", Enabled: true}},
		Ports:    []collect.Port{{Proto: "tcp", Addr: "0.0.0.0", Port: 22, PID: 1}},
	})
	if err := app.telemetryRepo().Save(context.Background(), assetID, snapshot); err != nil {
		t.Fatalf("写入遥测失败：%v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/assets/"+strconv.FormatInt(assetID, 10)+"/telemetry?limit=2", nil)
	req.SetPathValue("id", strconv.FormatInt(assetID, 10))
	req = req.WithContext(context.WithValue(req.Context(), ctxKeyUser{}, User{
		Username: "u", Name: "只读", Role: "viewer",
	}))
	rec := httptest.NewRecorder()
	app.handleAssetTelemetry(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("查询遥测失败：%d %s", rec.Code, rec.Body.String())
	}

	var payload struct {
		Telemetry *ports.HostTelemetry `json:"telemetry"`
		Series    []ports.MetricPoint  `json:"series"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("解析遥测响应失败：%v", err)
	}
	if payload.Telemetry == nil {
		t.Fatal("响应应包含最新遥测")
	}
	if payload.Telemetry.Metrics.CPUPercent != 42 || payload.Telemetry.Hardware.CPUModel != "Test CPU" {
		t.Fatalf("遥测内容异常：%+v", payload.Telemetry)
	}
	if len(payload.Telemetry.Services) != 1 || len(payload.Telemetry.Ports) != 1 {
		t.Fatalf("服务/端口数量异常：%+v", payload.Telemetry)
	}
	if len(payload.Series) != 1 || payload.Series[0].CPUPercent != 42 {
		t.Fatalf("时序内容异常：%+v", payload.Series)
	}
}
