package main

import (
	"testing"
)

func TestParseSSHHostMetrics(t *testing.T) {
	output := `CPU|100|900|200|1000
NET|1000|500|1120|620
MEM|MemTotal|16000000
MEM|MemAvailable|8000000
MEM|SwapTotal|2000000
MEM|SwapFree|1500000
LOAD|0.52|0.40|0.35
UPTIME|123456
CPUS|4
PROCS|123
DISK|/|100000000|42000000|58000000|42%
TOP|1234|12.3|4.5|nginx
`
	metrics, err := parseSSHHostMetrics(output)
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if metrics.CPUPercent < 49.9 || metrics.CPUPercent > 50.1 {
		t.Fatalf("CPU 使用率计算异常：%v", metrics.CPUPercent)
	}
	if metrics.NetRxBps < 199.9 || metrics.NetRxBps > 200.1 {
		t.Fatalf("下行速率计算异常：%v", metrics.NetRxBps)
	}
	if metrics.NetTxBps < 199.9 || metrics.NetTxBps > 200.1 {
		t.Fatalf("上行速率计算异常：%v", metrics.NetTxBps)
	}
	if metrics.MemTotalKB != 16000000 || metrics.MemUsedKB != 8000000 || metrics.MemPercent != 50 {
		t.Fatalf("内存计算异常：%+v", metrics)
	}
	if metrics.SwapUsedKB != 500000 || metrics.SwapPercent != 25 {
		t.Fatalf("Swap 计算异常：%+v", metrics)
	}
	if metrics.Load1 != 0.52 || metrics.CPUCores != 4 || metrics.Processes != 123 || metrics.UptimeSeconds != 123456 {
		t.Fatalf("基础字段异常：%+v", metrics)
	}
	if len(metrics.Disks) != 1 || metrics.Disks[0].Mount != "/" || metrics.Disks[0].Percent != 42 {
		t.Fatalf("磁盘解析异常：%+v", metrics.Disks)
	}
	if len(metrics.Top) != 1 || metrics.Top[0].Command != "nginx" || metrics.Top[0].PID != 1234 {
		t.Fatalf("进程解析异常：%+v", metrics.Top)
	}
}

func TestParseSSHHostMetricsRejectsEmptyOutput(t *testing.T) {
	if _, err := parseSSHHostMetrics(""); err == nil {
		t.Fatal("空输出应返回错误")
	}
	if _, err := parseSSHHostMetrics("LOAD|0.1|0.2|0.3\n"); err == nil {
		t.Fatal("缺少 CPU 与内存数据时应返回错误")
	}
}
