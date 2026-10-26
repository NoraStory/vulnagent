//go:build windows

package collect

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"time"
)

// winPayload PowerShell 采集脚本输出的 JSON 结构
type winPayload struct {
	CPUName      string  `json:"cpuName"`
	CPULoad      float64 `json:"cpuLoad"`
	Cores        int     `json:"cores"`
	Threads      int     `json:"threads"`
	MemTotal     uint64  `json:"memTotal"`
	MemFree      uint64  `json:"memFree"`
	SwapTotal    uint64  `json:"swapTotal"`
	SwapFree     uint64  `json:"swapFree"`
	UptimeSec    int64   `json:"uptimeSec"`
	Kernel       string  `json:"kernel"`
	Serial       string  `json:"serial"`
	Manufacturer string  `json:"manufacturer"`
	Model        string  `json:"model"`
	ProcCount    int     `json:"procCount"`
	DiskReadBps  float64 `json:"diskReadBps"`
	DiskWriteBps float64 `json:"diskWriteBps"`
	NetRxBps     float64 `json:"netRxBps"`
	NetTxBps     float64 `json:"netTxBps"`
	Disks        []struct {
		Device string `json:"device"`
		Model  string `json:"model"`
		Serial string `json:"serial"`
		Size   int64  `json:"size"`
	} `json:"disks"`
	NICs []struct {
		Name  string  `json:"name"`
		MAC   string  `json:"mac"`
		Speed float64 `json:"speed"`
	} `json:"nics"`
	Services []struct {
		Name      string `json:"name"`
		State     string `json:"state"`
		StartType string `json:"startType"`
	} `json:"services"`
	Ports []struct {
		Proto   string `json:"proto"`
		Addr    string `json:"addr"`
		Port    int    `json:"port"`
		PID     int    `json:"pid"`
		Process string `json:"process"`
	} `json:"ports"`
}

// winTelemetryScript 只读采集脚本：性能计数器、硬件、服务与监听端口。
const winTelemetryScript = `$ErrorActionPreference='SilentlyContinue';
$cpu=Get-CimInstance Win32_Processor | Select-Object -First 1;
$os=Get-CimInstance Win32_OperatingSystem;
$cs=Get-CimInstance Win32_ComputerSystem;
$bios=Get-CimInstance Win32_BIOS;
$disks=@(Get-CimInstance Win32_DiskDrive | ForEach-Object { [pscustomobject]@{device=[string]$_.DeviceID;model=[string]$_.Model;serial=[string]$_.SerialNumber;size=[int64]$_.Size} });
$nics=@(Get-CimInstance Win32_NetworkAdapter -Filter "PhysicalAdapter=True" | ForEach-Object { [pscustomobject]@{name=[string]$_.Name;mac=[string]$_.MACAddress;speed=[double]$_.Speed} });
$services=@(Get-Service | Select-Object -First 200 | ForEach-Object { [pscustomobject]@{name=[string]$_.Name;state=[string]$_.Status;startType=[string]$_.StartType} });
$procs=@(Get-Process);
$procMap=@{};
foreach($p in $procs){$procMap[[int]$p.Id]=[string]$p.ProcessName};
$ports=@(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object -First 300 | ForEach-Object { [pscustomobject]@{proto='tcp';addr=[string]$_.LocalAddress;port=[int]$_.LocalPort;pid=[int]$_.OwningProcess;process=[string]$procMap[[int]$_.OwningProcess]} });
$diskPerf=Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk -Filter "Name='_Total'" -ErrorAction SilentlyContinue;
$netPerf=@(Get-CimInstance Win32_PerfFormattedData_Tcpip_NetworkInterface -ErrorAction SilentlyContinue);
$out=[pscustomobject]@{
cpuName=[string]$cpu.Name;cpuLoad=[double]$cpu.LoadPercentage;cores=[int]$cpu.NumberOfCores;threads=[int]$cpu.NumberOfLogicalProcessors;
memTotal=[int64]$cs.TotalPhysicalMemory;memFree=([int64]$os.FreePhysicalMemory*1024);
swapTotal=([int64]$os.TotalVirtualMemorySize*1024-[int64]$cs.TotalPhysicalMemory);swapFree=([int64]$os.FreeVirtualMemory*1024-[int64]$os.FreePhysicalMemory*1024);
uptimeSec=[int64]((Get-Date)-$os.LastBootUpTime).TotalSeconds;kernel=[string]$os.Version;serial=[string]$bios.SerialNumber;
manufacturer=[string]$cs.Manufacturer;model=[string]$cs.Model;procCount=[int]$procs.Count;
diskReadBps=[double]$diskPerf.DiskReadBytesPerSec;diskWriteBps=[double]$diskPerf.DiskWriteBytesPerSec;
netRxBps=[double]($netPerf | Measure-Object -Property BytesReceivedPerSec -Sum).Sum;
netTxBps=[double]($netPerf | Measure-Object -Property BytesSentPerSec -Sum).Sum;
disks=$disks;nics=$nics;services=$services;ports=$ports};
$out | ConvertTo-Json -Depth 6 -Compress`

// collectWindowsTelemetry 通过 PowerShell/CIM 采集 Windows 主机遥测。
func collectWindowsTelemetry(t Telemetry) (Telemetry, []string) {
	shell := ""
	if _, err := exec.LookPath("powershell.exe"); err == nil {
		shell = "powershell.exe"
	} else if _, err := exec.LookPath("pwsh.exe"); err == nil {
		shell = "pwsh.exe"
	} else {
		return t, []string{"未找到 PowerShell，Windows 遥测未采集"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, shell, "-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "Bypass", "-Command", winTelemetryScript).Output()
	if err != nil {
		return t, []string{"Windows 遥测采集失败：" + err.Error()}
	}
	parsed, err := parseWindowsTelemetry(out, t)
	if err != nil {
		return t, []string{"Windows 遥测解析失败：" + err.Error()}
	}
	return parsed, nil
}

// parseWindowsTelemetry 把 PowerShell JSON 映射为统一遥测结构，便于单元测试。
func parseWindowsTelemetry(data []byte, t Telemetry) (Telemetry, error) {
	var raw winPayload
	if err := json.Unmarshal(data, &raw); err != nil {
		return t, err
	}
	t.Metrics.CPUPercent = round2(raw.CPULoad)
	t.Metrics.MemTotal = raw.MemTotal
	t.Metrics.MemUsed = subFloor(raw.MemTotal, raw.MemFree)
	t.Metrics.SwapTotal = raw.SwapTotal
	t.Metrics.SwapUsed = subFloor(raw.SwapTotal, raw.SwapFree)
	t.Metrics.DiskReadBps = round2(raw.DiskReadBps)
	t.Metrics.DiskWriteBps = round2(raw.DiskWriteBps)
	t.Metrics.NetRxBps = round2(raw.NetRxBps)
	t.Metrics.NetTxBps = round2(raw.NetTxBps)
	t.Metrics.UptimeSec = raw.UptimeSec
	t.Metrics.ProcessCount = raw.ProcCount

	hw := Hardware{
		CPUModel:   raw.CPUName,
		CPUCores:   raw.Cores,
		CPUThreads: raw.Threads,
		MemTotal:   raw.MemTotal,
		Kernel:     raw.Kernel,
		Serial:     strings.TrimSpace(raw.Serial),
		Disks:      make([]DiskInfo, 0, len(raw.Disks)),
		NICs:       make([]NICInfo, 0, len(raw.NICs)),
	}
	if isVirtualVendor(raw.Manufacturer + " " + raw.Model) {
		hw.Virtualization = "virtual"
	} else {
		hw.Virtualization = "physical"
	}
	for _, disk := range raw.Disks {
		if disk.Model == "" && disk.Size == 0 {
			continue
		}
		hw.Disks = append(hw.Disks, DiskInfo{
			Device:    strings.TrimPrefix(strings.TrimSpace(disk.Device), `\\.\`),
			Model:     strings.TrimSpace(disk.Model),
			Serial:    strings.TrimSpace(disk.Serial),
			SizeBytes: uint64(maxInt64(disk.Size)),
		})
	}
	for _, nic := range raw.NICs {
		if nic.MAC == "" {
			continue
		}
		// Win32_NetworkAdapter.Speed 单位为 bit/s；未知或异常值统一归零，避免 UI 溢出
		mbps := int64(nic.Speed / 1_000_000)
		if mbps <= 0 || mbps > 800_000 {
			mbps = 0
		}
		hw.NICs = append(hw.NICs, NICInfo{Name: strings.TrimSpace(nic.Name), MAC: nic.MAC, SpeedMbps: mbps})
	}
	t.Hardware = hw

	for _, svc := range raw.Services {
		if svc.Name == "" {
			continue
		}
		t.Services = append(t.Services, Service{
			Name:    svc.Name,
			State:   strings.ToLower(svc.State),
			Enabled: strings.EqualFold(svc.StartType, "Automatic"),
			Detail:  svc.StartType,
		})
	}
	for _, port := range raw.Ports {
		if port.Port <= 0 {
			continue
		}
		proto := port.Proto
		if proto == "" {
			proto = "tcp"
		}
		t.Ports = append(t.Ports, Port{
			Proto:   proto,
			Addr:    port.Addr,
			Port:    port.Port,
			Process: strings.TrimSpace(port.Process),
			PID:     port.PID,
		})
	}
	return t, nil
}

func maxInt64(v int64) int64 {
	if v < 0 {
		return 0
	}
	return v
}

// collectLinuxTelemetry 在 Windows 构建中不参与运行，仅保证调度函数可编译。
func collectLinuxTelemetry(t Telemetry) (Telemetry, []string) {
	return t, []string{"当前平台不支持 Linux 遥测"}
}
