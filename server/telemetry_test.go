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
	"vulnagent/server/internal/domain/harness"
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
		Processes: []collect.Process{
			{Name: "nginx", PID: 10, MemBytes: 256 << 20},
			{Name: "postgres", PID: 20, MemBytes: 1 << 30},
		},
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
	if len(out.Processes) != 2 || out.Processes[1].Name != "postgres" || out.Processes[1].MemBytes != 1<<30 {
		t.Fatalf("进程映射异常：%+v", out.Processes)
	}
}

func TestHarnessHostTelemetryTools(t *testing.T) {
	app, _, assetID := newTicketTestApp(t)
	snapshot := toPortsTelemetry(collect.Telemetry{
		CollectedAt: "2026-01-01T10:00:00+08:00",
		Metrics:     collect.Metrics{CPUPercent: 37.5, MemUsed: 4 << 30, MemTotal: 8 << 30, ProcessCount: 120},
		Hardware: collect.Hardware{
			CPUModel: "Test CPU", CPUCores: 4, CPUThreads: 8, MemTotal: 8 << 30,
			Disks: []collect.DiskInfo{{Device: "vda", SizeBytes: 100 << 30}},
			NICs:  []collect.NICInfo{{Name: "eth0", SpeedMbps: 1000}},
		},
		Services:  []collect.Service{{Name: "sshd", State: "active", Enabled: true}},
		Ports:     []collect.Port{{Proto: "tcp", Addr: "0.0.0.0", Port: 22, PID: 1}},
		Processes: []collect.Process{{Name: "chrome", PID: 4321, MemBytes: 2 << 30}, {Name: "sshd", PID: 1, MemBytes: 32 << 20}},
	})
	if err := app.telemetryRepo().Save(context.Background(), assetID, snapshot); err != nil {
		t.Fatalf("写入遥测失败：%v", err)
	}

	var metricsTool, hardwareTool harness.Tool
	for _, tool := range app.harnessTools() {
		switch tool.Spec.Name {
		case "host_metrics":
			metricsTool = tool
		case "host_hardware":
			hardwareTool = tool
		}
	}
	if metricsTool.Spec.Name == "" || hardwareTool.Spec.Name == "" {
		t.Fatal("工具集缺少 host_metrics 或 host_hardware")
	}
	if metricsTool.Spec.MinRole != "viewer" || hardwareTool.Spec.MinRole != "viewer" {
		t.Fatal("遥测读取工具应为低风险只读、对 viewer 开放")
	}

	raw, _ := json.Marshal(map[string]any{"assetId": assetID, "limit": 5})
	out, err := metricsTool.Run(raw)
	if err != nil {
		t.Fatalf("host_metrics 执行失败：%v", err)
	}
	payload, ok := out.(map[string]any)
	if !ok {
		t.Fatalf("host_metrics 返回值类型异常：%T", out)
	}
	metrics, ok := payload["metrics"].(ports.HostMetrics)
	if !ok || metrics.CPUPercent != 37.5 || metrics.ProcessCount != 120 {
		t.Fatalf("host_metrics 指标异常：%+v", payload["metrics"])
	}
	if payload["sampledAt"] != snapshot.CollectedAt {
		t.Fatalf("采样时间异常：%v", payload["sampledAt"])
	}
	top, ok := payload["topProcesses"].([]ports.HostProcess)
	if !ok || len(top) != 2 || top[0].Name != "chrome" || top[0].MemBytes != 2<<30 {
		t.Fatalf("topProcesses 应返回进程内存明细：%+v", payload["topProcesses"])
	}

	out, err = hardwareTool.Run(json.RawMessage(`{"assetId":` + strconv.FormatInt(assetID, 10) + `}`))
	if err != nil {
		t.Fatalf("host_hardware 执行失败：%v", err)
	}
	payload, ok = out.(map[string]any)
	if !ok {
		t.Fatalf("host_hardware 返回值类型异常：%T", out)
	}
	hardware, ok := payload["hardware"].(ports.HostHardware)
	if !ok || hardware.CPUModel != "Test CPU" || len(hardware.Disks) != 1 || len(hardware.NICs) != 1 {
		t.Fatalf("host_hardware 硬件信息异常：%+v", payload["hardware"])
	}
	if payload["servicesTotal"] != 1 || payload["portsTotal"] != 1 {
		t.Fatalf("host_hardware 服务/端口统计异常：%+v", payload)
	}

	// 未上报遥测的资产应返回 found=false 而不是报错
	out, err = metricsTool.Run(json.RawMessage(`{"assetId":999999}`))
	if err != nil {
		t.Fatalf("未知资产不应报错：%v", err)
	}
	if found, _ := out.(map[string]any)["found"].(bool); found {
		t.Fatal("未知资产不应返回 found=true")
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
