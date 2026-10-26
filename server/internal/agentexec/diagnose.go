package agentexec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

// ActionDiagnose 按语义执行只读主机诊断（命令由服务端固定，不接受任意 shell）
const ActionDiagnose = "diagnose"

type diagnoseParams struct {
	Query  string `json:"query"`
	Target string `json:"target"`
	Path   string `json:"path"`
	Limit  int    `json:"limit"`
}

var diagnoseTargetPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,253}$`)

// linuxDiagnostics 固定命令集：每项按顺序执行并拼接输出
var linuxDiagnostics = map[string][][]string{
	"disk_space":     {{"df", "-hT"}, {"df", "-i"}},
	"disk_layout":    {{"lsblk", "-f"}, {"findmnt", "-rn", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS"}},
	"lvm":            {{"pvs"}, {"vgs"}, {"lvs"}},
	"mem_info":       {{"free", "-m"}, {"vmstat", "-s"}},
	"net_conn":       {{"ss", "-s"}, {"ss", "-lntup"}, {"ip", "-br", "addr"}, {"ip", "route"}},
	"net_ping":       {},
	"net_latency":    {},
	"service_status": {{"systemctl", "--failed", "--no-pager", "--no-legend"}, {"systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--no-legend"}},
	"system_log":     {{"journalctl", "-p", "err", "-n", "200", "--no-pager"}},
	"time_sync":      {{"timedatectl"}, {"chronyc", "tracking"}, {"chronyc", "sources", "-v"}},
	"packages":       {{"rpm", "-qa", "--qf", "%{NAME} %{VERSION}-%{RELEASE}\n"}},
	"repo":           {{"dnf", "repolist"}},
	"cpu_perf":       {{"top", "-b", "-n1"}, {"mpstat", "-P", "ALL", "1", "1"}},
	"io_latency":     {{"iostat", "-xz", "1", "3"}, {"pidstat", "-d", "1", "3"}},
	"irq_balance":    {{"mpstat", "-I", "SUM", "-P", "ALL", "1", "1"}},
	"fs_latency":     {{"findmnt", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS"}},
	"kdump":          {{"kdumpctl", "status"}},
	"cve":            {{"dnf", "updateinfo", "list", "security"}},
	"docker":         {{"docker", "ps", "-a", "--format", "table {{.Names}}\t{{.Status}}\t{{.Image}}"}},
	"k8s":            {{"kubectl", "get", "nodes", "-o", "wide"}},
}

// windowsDiagnostics 固定 PowerShell 只读脚本
var windowsDiagnostics = map[string]string{
	"disk_space": `Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | Select-Object DeviceID,VolumeName,
@{n='SizeGB';e={[math]::Round($_.Size/1GB,2)}},@{n='FreeGB';e={[math]::Round($_.FreeSpace/1GB,2)}} | Format-Table -AutoSize | Out-String -Width 200`,
	"disk_layout": `Get-Disk | Select-Object Number,FriendlyName,@{n='SizeGB';e={[math]::Round($_.Size/1GB,2)}},PartitionStyle,HealthStatus,OperationalStatus | Format-Table -AutoSize | Out-String -Width 200;
Get-Volume | Select-Object DriveLetter,FileSystemLabel,FileSystem,@{n='SizeGB';e={[math]::Round($_.Size/1GB,2)}},@{n='FreeGB';e={[math]::Round($_.SizeRemaining/1GB,2)}},HealthStatus | Format-Table -AutoSize | Out-String -Width 200`,
	"disk_health": `Get-PhysicalDisk | Select-Object FriendlyName,MediaType,HealthStatus,OperationalStatus,@{n='SizeGB';e={[math]::Round($_.Size/1GB,2)}} | Format-Table -AutoSize | Out-String -Width 200;
Get-PhysicalDisk | Get-StorageReliabilityCounter -ErrorAction SilentlyContinue | Select-Object DeviceId,Wear,Temperature,ReadErrorsTotal,WriteErrorsTotal,PowerOnHours | Format-Table -AutoSize | Out-String -Width 200`,
	"mem_info": `Get-CimInstance Win32_OperatingSystem | Select-Object @{n='TotalGB';e={[math]::Round($_.TotalVisibleMemorySize/1MB,2)}},@{n='FreeGB';e={[math]::Round($_.FreePhysicalMemory/1MB,2)}} | Format-List;
Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 10 Name,Id,@{n='MemMB';e={[math]::Round($_.WorkingSet64/1MB,1)}} | Format-Table -AutoSize | Out-String -Width 200`,
	"oom": `Get-WinEvent -FilterHashtable @{LogName='System';Id=2004,2019,2020} -MaxEvents 50 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,ProviderName,Message | Format-List | Out-String -Width 200`,
	"net_conn": `Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object State,LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess | Sort-Object State | Format-Table -AutoSize | Out-String -Width 220;
Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,OwningProcess | Format-Table -AutoSize | Out-String -Width 200`,
	"service_status": `Get-Service | Select-Object Name,DisplayName,Status,StartType | Sort-Object Status,Name | Format-Table -AutoSize | Out-String -Width 220`,
	"system_log":     `Get-WinEvent -FilterHashtable @{LogName='System','Application';Level=1,2;StartTime=(Get-Date).AddDays(-1)} -MaxEvents 100 -ErrorAction SilentlyContinue | Select-Object TimeCreated,LogName,Id,LevelDisplayName,ProviderName,Message | Format-List | Out-String -Width 200`,
	"event_errors":   `Get-WinEvent -FilterHashtable @{LogName='System','Application';Level=1,2;StartTime=(Get-Date).AddDays(-2)} -MaxEvents 150 -ErrorAction SilentlyContinue | Select-Object TimeCreated,LogName,Id,ProviderName,Message | Format-List | Out-String -Width 200`,
	"time_sync": `Get-Service w32time | Format-List Name,Status,StartType;
w32tm /query /status 2>&1 | Out-String`,
	"packages": `Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 30 HotFixID,Description,InstalledOn | Format-Table -AutoSize | Out-String -Width 200`,
	"cve":      `Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 50 HotFixID,Description,InstalledOn | Format-Table -AutoSize | Out-String -Width 200`,
	"win_update": `Get-Service wuauserv,bits | Format-Table -AutoSize | Out-String -Width 160;
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10 HotFixID,InstalledOn | Format-Table -AutoSize | Out-String -Width 160;
Get-ChildItem C:\Windows\SoftwareDistribution\Download -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum | Format-List Count,Sum`,
	"cpu_perf":   `Get-Counter '\Processor(_Total)\% Processor Time','\Memory\Available MBytes','\PhysicalDisk(_Total)\% Disk Time' -SampleInterval 1 -MaxSamples 2 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CounterSamples | Select-Object Path,CookedValue | Format-Table -AutoSize | Out-String -Width 200`,
	"io_latency": `Get-Counter '\PhysicalDisk(_Total)\Avg. Disk sec/Read','\PhysicalDisk(_Total)\Avg. Disk sec/Write','\PhysicalDisk(_Total)\Current Disk Queue Length' -SampleInterval 1 -MaxSamples 2 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CounterSamples | Select-Object Path,CookedValue | Format-Table -AutoSize | Out-String -Width 200`,
	"startup_items": `foreach($k in 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'){ Write-Output "== $k"; if(Test-Path $k){ Get-ItemProperty $k | Format-List | Out-String -Width 200 } };
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue | Select-Object Name,Length,LastWriteTime | Format-Table -AutoSize | Out-String -Width 160`,
	"installed_programs": `foreach($k in 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'){ Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object DisplayName | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate } | Sort-Object DisplayName | Format-Table -AutoSize | Out-String -Width 220`,
	"sessions": `quser 2>&1 | Out-String;
Get-CimInstance Win32_LogonSession -ErrorAction SilentlyContinue | Where-Object {$_.LogonType -in 2,10} | Select-Object LogonId,LogonType,StartTime | Format-Table -AutoSize | Out-String -Width 160`,
	"scheduled_tasks": `Get-ScheduledTask | Select-Object TaskPath,TaskName,State | Sort-Object TaskPath,TaskName | Format-Table -AutoSize | Out-String -Width 220`,
	"smb_shares": `Get-SmbShare -ErrorAction SilentlyContinue | Select-Object Name,Path,Description,Special | Format-Table -AutoSize | Out-String -Width 200;
Get-SmbShareAccess -ErrorAction SilentlyContinue | Select-Object Name,AccountName,AccessControlType,AccessRight | Format-Table -AutoSize | Out-String -Width 200`,
	"dns_nic": `Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Select-Object InterfaceAlias,AddressFamily,ServerAddresses | Format-Table -AutoSize | Out-String -Width 200;
Get-NetIPConfiguration -ErrorAction SilentlyContinue | Select-Object InterfaceAlias,IPv4Address,IPv4DefaultGateway,DNSServer | Format-List | Out-String -Width 200`,
	"firewall": `Get-NetFirewallRule -Enabled True -ErrorAction SilentlyContinue | Select-Object DisplayName,Direction,Action,Profile | Sort-Object Direction,DisplayName | Select-Object -First 300 | Format-Table -AutoSize | Out-String -Width 220`,
	"certs": `Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Select-Object Subject,Issuer,NotBefore,NotAfter,Thumbprint | Sort-Object NotAfter | Format-Table -AutoSize | Out-String -Width 240;
Get-ChildItem Cert:\LocalMachine\WebHosting -ErrorAction SilentlyContinue | Select-Object Subject,NotAfter,Thumbprint | Format-Table -AutoSize | Out-String -Width 200`,
	"iis": `Import-Module WebAdministration -ErrorAction SilentlyContinue;
Get-Website -ErrorAction SilentlyContinue | Select-Object Name,State,PhysicalPath,Bindings | Format-Table -AutoSize | Out-String -Width 240;
Get-IISAppPool -ErrorAction SilentlyContinue | Select-Object Name,State,ProcessModel | Format-Table -AutoSize | Out-String -Width 200`,
	"storage_pool": `Get-StoragePool -ErrorAction SilentlyContinue | Select-Object FriendlyName,HealthStatus,OperationalStatus,@{n='SizeGB';e={[math]::Round($_.Size/1GB,2)}} | Format-Table -AutoSize | Out-String -Width 200;
Get-VirtualDisk -ErrorAction SilentlyContinue | Select-Object FriendlyName,HealthStatus,OperationalStatus,@{n='SizeGB';e={[math]::Round($_.Size/1GB,2)}} | Format-Table -AutoSize | Out-String -Width 200`,
	"backup":         `Get-WBSummary -ErrorAction SilentlyContinue | Format-List | Out-String -Width 200`,
	"docker":         `docker ps -a --format "table {{.Names}}\t{{.Status}}\t{{.Image}}" 2>&1 | Out-String`,
	"k8s":            `kubectl get nodes -o wide 2>&1 | Out-String`,
	"crash_recovery": `Get-WinEvent -FilterHashtable @{LogName='System';Id=7031,7034,1001} -MaxEvents 50 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,ProviderName,Message | Format-List | Out-String -Width 200`,
}

// DiagnoseQueries 返回全部受支持的诊断项（跨平台并集，按字母排序）
func DiagnoseQueries() []string {
	seen := map[string]bool{}
	out := make([]string, 0, 40)
	keys := make([]string, 0, len(linuxDiagnostics)+len(windowsDiagnostics)+6)
	for key := range linuxDiagnostics {
		keys = append(keys, key)
	}
	for key := range windowsDiagnostics {
		keys = append(keys, key)
	}
	keys = append(keys, "service_failed", "security_baseline", "syscall_hotspot")
	for _, key := range keys {
		if !seen[key] {
			seen[key] = true
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}

// diagnose 执行一个只读诊断项
func diagnose(ctx context.Context, raw json.RawMessage, opts Options) (string, error) {
	var p diagnoseParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", fmt.Errorf("参数格式错误：%w", err)
	}
	p.Query = strings.ToLower(strings.TrimSpace(p.Query))
	if p.Query == "" {
		return "", errors.New("query 不能为空")
	}
	if !isDiagnoseQuery(p.Query) {
		return "", fmt.Errorf("不支持的诊断项：%s", p.Query)
	}
	if p.Target != "" && !diagnoseTargetPattern.MatchString(p.Target) {
		return "", errors.New("target 格式不合法")
	}
	if runtime.GOOS == "windows" {
		return runWindowsDiagnose(ctx, p, opts)
	}
	return runLinuxDiagnose(ctx, p, opts)
}

func isDiagnoseQuery(query string) bool {
	for _, item := range DiagnoseQueries() {
		if item == query {
			return true
		}
	}
	return false
}

// SupportedDiagnoseQuery 判断诊断项是否受支持
func SupportedDiagnoseQuery(query string) bool {
	return isDiagnoseQuery(strings.ToLower(strings.TrimSpace(query)))
}

func runLinuxDiagnose(ctx context.Context, p diagnoseParams, opts Options) (string, error) {
	switch p.Query {
	case "oom":
		out, err := runDiagCmd(ctx, "journalctl", "-k", "--no-pager", "-n", "800")
		if err != nil {
			if fallback, ferr := runDiagCmd(ctx, "dmesg", "-T"); ferr == nil {
				out = fallback
			}
		}
		return filterLines(out, []string{"oom", "out of memory", "killed process", "invoked oom-killer"}), nil
	case "net_ping":
		if p.Target == "" {
			return "", errors.New("net_ping 需要 target")
		}
		out, err := runDiagCmd(ctx, "ping", "-c", "4", "-W", "2", p.Target)
		return out, err
	case "net_latency":
		if p.Target == "" {
			return "", errors.New("net_latency 需要 target")
		}
		if out, err := runDiagCmd(ctx, "mtr", "-r", "-c", "5", p.Target); err == nil {
			return out, nil
		}
		out, err := runDiagCmd(ctx, "traceroute", "-n", "-m", "12", p.Target)
		return out, err
	case "disk_health":
		if p.Target != "" {
			out, err := runDiagCmd(ctx, "smartctl", "-a", p.Target)
			return out, err
		}
		out, _ := runDiagCmd(ctx, "lsblk", "-d", "-o", "NAME,MODEL,SIZE,ROTA")
		return out, nil
	case "service_failed":
		out, err := runDiagCmd(ctx, "systemctl", "--failed", "--no-pager", "--no-legend")
		return out, err
	case "security_baseline":
		parts := make([]string, 0, 3)
		for _, args := range [][]string{{"sshd", "-T"}, {"sshd", "-T", "-C", "user=root,host=x,addr=127.0.0.1"}} {
			if out, err := runDiagCmd(ctx, args[0], args[1:]...); err == nil && strings.TrimSpace(out) != "" {
				parts = append(parts, "## "+strings.Join(args, " ")+"\n"+out)
				break
			}
		}
		if out, err := runDiagCmd(ctx, "sysctl", "kernel.randomize_va_space", "net.ipv4.ip_forward", "net.ipv4.tcp_syncookies"); err == nil {
			parts = append(parts, "## sysctl\n"+out)
		}
		if len(parts) == 0 {
			return "", errors.New("安全基线检查需要 sshd/sysctl")
		}
		return strings.Join(parts, "\n"), nil
	case "syscall_hotspot":
		return "", errors.New("syscall_hotspot 需要 perf/strace 权限，暂未开放自动执行；请使用 cpu_perf / io_latency")
	}
	commands, ok := linuxDiagnostics[p.Query]
	if !ok || len(commands) == 0 {
		return "", fmt.Errorf("%s 在当前平台不支持", p.Query)
	}
	parts := make([]string, 0, len(commands))
	for _, args := range commands {
		if p.Query == "packages" && p.Limit > 0 {
			// 大表按行截断在下方统一处理
		}
		out, err := runDiagCmd(ctx, args[0], args[1:]...)
		title := strings.Join(args, " ")
		if err != nil {
			parts = append(parts, fmt.Sprintf("## %s (失败: %v)\n%s", title, err, out))
			continue
		}
		parts = append(parts, "## "+title+"\n"+out)
	}
	return strings.Join(parts, "\n"), nil
}

func runWindowsDiagnose(ctx context.Context, p diagnoseParams, opts Options) (string, error) {
	switch p.Query {
	case "net_ping":
		if p.Target == "" {
			return "", errors.New("net_ping 需要 target")
		}
		return runPowerShell(ctx, fmt.Sprintf(`Test-Connection -ComputerName '%s' -Count 4 | Select-Object Address,ResponseTime,StatusCode | Format-Table -AutoSize | Out-String -Width 160`, escapePowerShell(p.Target)))
	case "net_latency":
		if p.Target == "" {
			return "", errors.New("net_latency 需要 target")
		}
		return runPowerShell(ctx, fmt.Sprintf(`Test-NetConnection -ComputerName '%s' -TraceRoute | Format-List | Out-String -Width 200`, escapePowerShell(p.Target)))
	case "dns_nic":
		script := windowsDiagnostics["dns_nic"]
		if p.Target != "" {
			script += fmt.Sprintf(`; Resolve-DnsName '%s' -ErrorAction SilentlyContinue | Format-Table -AutoSize | Out-String -Width 200`, escapePowerShell(p.Target))
		}
		return runPowerShell(ctx, script)
	case "service_failed":
		return runPowerShell(ctx, `Get-Service | Where-Object {$_.StartType -eq 'Automatic' -and $_.Status -ne 'Running'} | Select-Object Name,DisplayName,Status | Format-Table -AutoSize | Out-String -Width 200`)
	case "security_baseline":
		return runPowerShell(ctx, `Get-MpComputerStatus -ErrorAction SilentlyContinue | Format-List | Out-String -Width 200;
Get-NetFirewallProfile -ErrorAction SilentlyContinue | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | Format-Table -AutoSize | Out-String -Width 160;
Get-LocalUser -ErrorAction SilentlyContinue | Select-Object Name,Enabled,LastLogon,PasswordRequired | Format-Table -AutoSize | Out-String -Width 160`)
	case "syscall_hotspot":
		return "", errors.New("syscall_hotspot 不支持 Windows")
	}
	script, ok := windowsDiagnostics[p.Query]
	if !ok {
		return "", fmt.Errorf("%s 在当前平台不支持", p.Query)
	}
	return runPowerShell(ctx, script)
}

func runPowerShell(ctx context.Context, script string) (string, error) {
	shell := ""
	if _, err := exec.LookPath("powershell.exe"); err == nil {
		shell = "powershell.exe"
	} else if _, err := exec.LookPath("pwsh.exe"); err == nil {
		shell = "pwsh.exe"
	} else {
		return "", errors.New("未找到 PowerShell")
	}
	cctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, shell, "-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "Bypass", "-Command", script).CombinedOutput()
	text := truncate(string(out), 96<<10)
	if err != nil {
		return text, fmt.Errorf("诊断命令失败：%w", err)
	}
	return text, nil
}

func runDiagCmd(ctx context.Context, name string, args ...string) (string, error) {
	if _, err := exec.LookPath(name); err != nil {
		return "", fmt.Errorf("命令不可用：%s", name)
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, name, args...).CombinedOutput()
	text := truncate(string(out), 64<<10)
	if err != nil {
		return text, fmt.Errorf("%s 执行失败：%w", name, err)
	}
	return text, nil
}

func filterLines(out string, keywords []string) string {
	lines := strings.Split(out, "\n")
	kept := make([]string, 0, 64)
	for _, line := range lines {
		lower := strings.ToLower(line)
		for _, keyword := range keywords {
			if strings.Contains(lower, keyword) {
				kept = append(kept, line)
				break
			}
		}
		if len(kept) >= 200 {
			break
		}
	}
	if len(kept) == 0 {
		return "未发现匹配的关键字（oom / out of memory / killed process）"
	}
	return strings.Join(kept, "\n")
}

func escapePowerShell(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}

// diagnosePathAllowed 兼容 future：诊断如需路径参数，仅允许读取白名单根目录。
func diagnosePathAllowed(path string, opts Options) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", nil
	}
	abs, err := safePath(path, opts.ReadRoots)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(abs) {
		return "", errors.New("路径必须为绝对路径")
	}
	return abs, nil
}
