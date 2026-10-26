package sqlite

import (
	"context"
	"path/filepath"
	"testing"

	"vulnagent/server/internal/application/ports"
)

func openTelemetryDB(t *testing.T) *TelemetryRepo {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "telemetry.db"))
	if err != nil {
		t.Fatalf("打开测试库失败：%v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewTelemetryRepo(db)
}

func sampleTelemetry(at string, cpu float64) ports.HostTelemetry {
	return ports.HostTelemetry{
		CollectedAt: at,
		Metrics: ports.HostMetrics{
			CPUPercent: cpu, Load1: 0.5, MemUsed: 4 << 30, MemTotal: 8 << 30,
			NetRxBps: 1024, NetTxBps: 2048, DiskReadBps: 4096, DiskWriteBps: 8192,
			UptimeSec: 3600, ProcessCount: 120,
		},
		Hardware: ports.HostHardware{
			CPUModel: "Test CPU", CPUCores: 4, CPUThreads: 8, MemTotal: 8 << 30,
			Kernel: "6.1.0", Virtualization: "physical", Serial: "SN-001",
			Disks: []ports.DiskInfo{{Device: "sda", Model: "TestDisk", Serial: "D-1", SizeBytes: 100 << 30}},
			NICs:  []ports.NICInfo{{Name: "eth0", MAC: "00:11:22:33:44:55", SpeedMbps: 1000}},
		},
		Services: []ports.HostService{{Name: "nginx", State: "active", Enabled: true, Detail: "web server"}},
		Ports:    []ports.HostPort{{Proto: "tcp", Addr: "0.0.0.0", Port: 22, Process: "sshd", PID: 872}},
	}
}

func TestTelemetryRepoSaveAndLatest(t *testing.T) {
	repo := openTelemetryDB(t)
	ctx := context.Background()

	if _, found, err := repo.Latest(ctx, 7); err != nil || found {
		t.Fatalf("空库不应返回快照：found=%v err=%v", found, err)
	}

	want := sampleTelemetry("2026-01-01T10:00:00+08:00", 12.5)
	if err := repo.Save(ctx, 7, want); err != nil {
		t.Fatalf("写入遥测失败：%v", err)
	}
	got, found, err := repo.Latest(ctx, 7)
	if err != nil || !found {
		t.Fatalf("读取最新遥测失败：found=%v err=%v", found, err)
	}
	if got.CollectedAt != want.CollectedAt || got.Metrics.CPUPercent != want.Metrics.CPUPercent {
		t.Fatalf("指标不一致：%+v", got.Metrics)
	}
	if got.Hardware.CPUModel != "Test CPU" || len(got.Hardware.Disks) != 1 || len(got.Hardware.NICs) != 1 {
		t.Fatalf("硬件清单不一致：%+v", got.Hardware)
	}
	if len(got.Services) != 1 || got.Services[0].Name != "nginx" || !got.Services[0].Enabled {
		t.Fatalf("服务清单不一致：%+v", got.Services)
	}
	if len(got.Ports) != 1 || got.Ports[0].Port != 22 || got.Ports[0].PID != 872 {
		t.Fatalf("端口清单不一致：%+v", got.Ports)
	}

	// 第二次写入应整体替换快照，而不是叠加
	want2 := sampleTelemetry("2026-01-01T11:00:00+08:00", 30)
	want2.Services = []ports.HostService{{Name: "sshd", State: "active", Enabled: true}}
	want2.Ports = []ports.HostPort{}
	if err := repo.Save(ctx, 7, want2); err != nil {
		t.Fatalf("二次写入失败：%v", err)
	}
	got, _, _ = repo.Latest(ctx, 7)
	if got.CollectedAt != want2.CollectedAt || len(got.Services) != 1 || got.Services[0].Name != "sshd" {
		t.Fatalf("快照未整体替换：%+v", got)
	}
	if len(got.Ports) != 0 {
		t.Fatalf("端口应被清空：%+v", got.Ports)
	}
}

func TestTelemetryRepoSeriesOrderAndLimit(t *testing.T) {
	repo := openTelemetryDB(t)
	ctx := context.Background()
	for i, at := range []string{
		"2026-01-01T10:00:00+08:00",
		"2026-01-01T11:00:00+08:00",
		"2026-01-01T12:00:00+08:00",
	} {
		if err := repo.Save(ctx, 3, sampleTelemetry(at, float64((i+1)*10))); err != nil {
			t.Fatalf("写入第 %d 条遥测失败：%v", i+1, err)
		}
	}

	all, err := repo.Series(ctx, 3, 10)
	if err != nil || len(all) != 3 {
		t.Fatalf("时序查询失败：len=%d err=%v", len(all), err)
	}
	if all[0].TS >= all[1].TS || all[1].TS >= all[2].TS {
		t.Fatalf("时序应按时间升序：%+v", all)
	}

	limited, err := repo.Series(ctx, 3, 2)
	if err != nil || len(limited) != 2 {
		t.Fatalf("limit 未生效：len=%d err=%v", len(limited), err)
	}
	if limited[0].TS != "2026-01-01T11:00:00+08:00" || limited[1].TS != "2026-01-01T12:00:00+08:00" {
		t.Fatalf("limit 应保留最近两条：%+v", limited)
	}
}
