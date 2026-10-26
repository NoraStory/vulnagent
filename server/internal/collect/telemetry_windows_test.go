//go:build windows

package collect

import "testing"

func TestParseWindowsTelemetry(t *testing.T) {
	fixture := []byte(`{
		"cpuName":"Intel(R) Xeon(R) Gold 6248R CPU @ 3.00GHz",
		"cpuLoad":37.5,"cores":24,"threads":48,
		"memTotal":68719476736,"memFree":17179869184,
		"swapTotal":8589934592,"swapFree":4294967296,
		"uptimeSec":86400,"kernel":"10.0.20348","serial":"SN-WIN-01",
		"manufacturer":"VMware, Inc.","model":"VMware7,1","procCount":210,
		"diskReadBps":1048576,"diskWriteBps":2097152,"netRxBps":4096,"netTxBps":8192,
		"disks":[{"device":"\\\\.\\PHYSICALDRIVE0","model":"Virtual Disk","serial":"D-001","size":107374182400}],
		"nics":[{"name":"Ethernet0","mac":"00:50:56:AA:BB:CC","speed":10000000000},{"name":"Ethernet1","mac":"00:50:56:AA:BB:DD","speed":9223372036854775807}],
		"services":[{"name":"W3SVC","state":"Running","startType":"Automatic"}],
		"ports":[{"proto":"tcp","addr":"0.0.0.0","port":443,"pid":4,"process":"svchost"}],
		"processes":[{"name":"chrome","pid":4321,"memBytes":2147483648},{"name":"svchost","pid":4,"memBytes":104857600}]
	}`)

	got, err := parseWindowsTelemetry(fixture, Telemetry{})
	if err != nil {
		t.Fatalf("解析 Windows 遥测失败：%v", err)
	}
	if got.Metrics.CPUPercent != 37.5 || got.Metrics.ProcessCount != 210 {
		t.Fatalf("性能指标解析异常：%+v", got.Metrics)
	}
	if got.Metrics.MemUsed != 68719476736-17179869184 {
		t.Fatalf("内存使用量计算异常：%d", got.Metrics.MemUsed)
	}
	if got.Metrics.SwapUsed != 8589934592-4294967296 {
		t.Fatalf("交换分区计算异常：%d", got.Metrics.SwapUsed)
	}
	if got.Hardware.CPUModel == "" || got.Hardware.CPUCores != 24 || got.Hardware.CPUThreads != 48 {
		t.Fatalf("CPU 信息异常：%+v", got.Hardware)
	}
	if got.Hardware.Virtualization != "virtual" {
		t.Fatalf("虚拟化识别异常：%s", got.Hardware.Virtualization)
	}
	if len(got.Hardware.Disks) != 1 || got.Hardware.Disks[0].SizeBytes != 107374182400 ||
		got.Hardware.Disks[0].Device != "PHYSICALDRIVE0" {
		t.Fatalf("磁盘解析异常：%+v", got.Hardware.Disks)
	}
	if len(got.Hardware.NICs) != 2 || got.Hardware.NICs[0].MAC != "00:50:56:AA:BB:CC" {
		t.Fatalf("网卡解析异常：%+v", got.Hardware.NICs)
	}
	if got.Hardware.NICs[0].SpeedMbps != 10000 || got.Hardware.NICs[1].SpeedMbps != 0 {
		t.Fatalf("网卡速率换算/异常值处理错误：%+v", got.Hardware.NICs)
	}
	if len(got.Services) != 1 || got.Services[0].State != "running" || !got.Services[0].Enabled {
		t.Fatalf("服务解析异常：%+v", got.Services)
	}
	if len(got.Ports) != 1 || got.Ports[0].Port != 443 || got.Ports[0].PID != 4 || got.Ports[0].Process != "svchost" {
		t.Fatalf("端口解析异常：%+v", got.Ports)
	}
	if len(got.Processes) != 2 || got.Processes[0].Name != "chrome" ||
		got.Processes[0].PID != 4321 || got.Processes[0].MemBytes != 2147483648 {
		t.Fatalf("进程内存解析异常：%+v", got.Processes)
	}
}

func TestParseWindowsTelemetryRejectsInvalidJSON(t *testing.T) {
	if _, err := parseWindowsTelemetry([]byte("not-json"), Telemetry{}); err == nil {
		t.Fatal("非法 JSON 应返回错误")
	}
}
