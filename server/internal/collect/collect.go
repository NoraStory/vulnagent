// Package collect 负责主机软件清单采集：系统包、语言依赖与 Agent 自身依赖。
// 采集只读，不修改任何系统状态。
package collect

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Component 归一化后的组件（PURL + 版本）
type Component struct {
	PURL    string `json:"purl"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Eco     string `json:"eco"`
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
	Source  string `json:"source"`
}

// Report 一次采集结果
type Report struct {
	Hostname    string      `json:"hostname"`
	IP          string      `json:"ip"`
	OS          string      `json:"os"`
	OSVersion   string      `json:"os_version"`
	CollectedAt string      `json:"collected_at"`
	Mode        string      `json:"mode"`
	Components  []Component `json:"components"`
	SelfSBOM    []Component `json:"self_sbom"`
	Telemetry   *Telemetry  `json:"telemetry,omitempty"`
	Warnings    []string    `json:"warnings"`
}

// Options 采集选项
type Options struct {
	// IncludeSelf 是否附带 Agent 自身依赖 SBOM
	IncludeSelf bool
	// MaxComponents 组件数量上限，防止异常主机压垮控制面
	MaxComponents int
}

// Collect 采集当前主机软件清单
func Collect(opts Options) (Report, error) {
	if opts.MaxComponents <= 0 {
		opts.MaxComponents = 20000
	}
	rep := Report{
		CollectedAt: time.Now().Format(time.RFC3339),
		Mode:        "full",
		Components:  []Component{},
		SelfSBOM:    []Component{},
		Warnings:    []string{},
	}
	rep.Hostname, _ = os.Hostname()
	rep.IP = primaryIP()
	rep.OS = runtime.GOOS

	switch runtime.GOOS {
	case "linux":
		osID, osVer := linuxOSRelease()
		rep.OS = osID
		rep.OSVersion = osVer
		rep.Components = append(rep.Components, collectDeb()...)
		rep.Components = append(rep.Components, collectRPM()...)
		rep.Components = append(rep.Components, collectAPK()...)
	case "windows":
		name, ver := windowsOSInfo()
		rep.OS = name
		rep.OSVersion = ver
		rep.Components = append(rep.Components, collectWindows()...)
	default:
		rep.Warnings = append(rep.Warnings, "当前平台暂不支持系统包采集："+runtime.GOOS)
	}

	rep.Components = dedupe(rep.Components)
	if len(rep.Components) > opts.MaxComponents {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("组件数量超过上限 %d，已截断", opts.MaxComponents))
		rep.Components = rep.Components[:opts.MaxComponents]
	}
	// 主机遥测（性能/硬件/服务/端口）与软件清单一起上报；失败只降级为警告
	telemetry, telemetryWarnings := collectTelemetry()
	rep.Telemetry = &telemetry
	rep.Warnings = append(rep.Warnings, telemetryWarnings...)
	if opts.IncludeSelf {
		rep.SelfSBOM = SelfSBOM()
	}
	return rep, nil
}

func dedupe(list []Component) []Component {
	seen := make(map[string]bool, len(list))
	out := make([]Component, 0, len(list))
	for _, c := range list {
		if c.PURL == "" || c.Name == "" || c.Version == "" {
			continue
		}
		if seen[c.PURL] {
			continue
		}
		seen[c.PURL] = true
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PURL < out[j].PURL })
	return out
}

func primaryIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP.IsLoopback() {
			continue
		}
		if v4 := ipNet.IP.To4(); v4 != nil {
			return v4.String()
		}
	}
	return ""
}

// ---------- Linux: dpkg ----------

func collectDeb() []Component {
	data, err := os.ReadFile("/var/lib/dpkg/status")
	if err != nil {
		return nil
	}
	var out []Component
	for _, stanza := range strings.Split(string(data), "\n\n") {
		fields := parseStanza(stanza)
		if !strings.HasPrefix(fields["Status"], "install ok installed") {
			continue
		}
		name, version := fields["Package"], fields["Version"]
		if name == "" || version == "" {
			continue
		}
		out = append(out, Component{
			PURL:    "pkg:deb/debian/" + name + "@" + version + "?arch=" + fields["Architecture"],
			Name:    name,
			Version: version,
			Eco:     "deb",
			Vendor:  "debian",
			Product: name,
			Source:  "dpkg",
		})
	}
	return out
}

func parseStanza(stanza string) map[string]string {
	fields := make(map[string]string)
	for _, line := range strings.Split(stanza, "\n") {
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			continue // 续行在演示场景不需要
		}
		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}
		fields[strings.TrimSpace(line[:idx])] = strings.TrimSpace(line[idx+1:])
	}
	return fields
}

// ---------- Linux: rpm ----------

func collectRPM() []Component {
	rpmPath, err := exec.LookPath("rpm")
	if err != nil {
		return nil
	}
	out, err := exec.Command(rpmPath, "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n").Output()
	if err != nil {
		return nil
	}
	var comps []Component
	for _, line := range strings.Split(string(out), "\n") {
		parts := strings.Split(line, "\t")
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			continue
		}
		arch := ""
		if len(parts) > 2 {
			arch = parts[2]
		}
		comps = append(comps, Component{
			PURL:    "pkg:rpm/rhel/" + parts[0] + "@" + parts[1] + "?arch=" + arch,
			Name:    parts[0],
			Version: parts[1],
			Eco:     "rpm",
			Vendor:  "rhel",
			Product: parts[0],
			Source:  "rpm",
		})
	}
	return comps
}

// ---------- Linux: apk ----------

func collectAPK() []Component {
	data, err := os.ReadFile("/lib/apk/db/installed")
	if err != nil {
		return nil
	}
	var comps []Component
	for _, stanza := range strings.Split(string(data), "\n\n") {
		var name, version, arch string
		for _, line := range strings.Split(stanza, "\n") {
			if len(line) < 2 {
				continue
			}
			switch line[0] {
			case 'P':
				name = strings.TrimSpace(line[2:])
			case 'V':
				version = strings.TrimSpace(line[2:])
			case 'A':
				arch = strings.TrimSpace(line[2:])
			}
		}
		if name == "" || version == "" {
			continue
		}
		comps = append(comps, Component{
			PURL:    "pkg:apk/alpine/" + name + "@" + version + "?arch=" + arch,
			Name:    name,
			Version: version,
			Eco:     "apk",
			Vendor:  "alpine",
			Product: name,
			Source:  "apk",
		})
	}
	return comps
}

func linuxOSRelease() (string, string) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "linux", ""
	}
	id, version := "linux", ""
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.Trim(value, `"`)
		switch key {
		case "ID":
			id = value
		case "VERSION_ID":
			version = value
		}
	}
	return id, version
}

// ---------- Windows：注册表卸载项 ----------

var uninstallRoots = []string{
	`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
	`HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
	`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
}

func collectWindows() []Component {
	var comps []Component
	for _, root := range uninstallRoots {
		out, err := exec.Command("reg", "query", root, "/s").Output()
		if err != nil {
			continue
		}
		for name, version := range parseUninstallOutput(string(out)) {
			comps = append(comps, Component{
				PURL:    "pkg:generic/" + purlName(name) + "@" + url.PathEscape(version),
				Name:    name,
				Version: version,
				Eco:     "windows",
				Vendor:  "microsoft",
				Product: strings.ToLower(name),
				Source:  "registry",
			})
		}
	}
	return comps
}

// parseUninstallOutput 解析 reg query 的输出，返回 显示名 → 版本
func parseUninstallOutput(out string) map[string]string {
	result := make(map[string]string)
	var currentName, currentVersion string
	flush := func() {
		if currentName != "" && currentVersion != "" {
			result[currentName] = currentVersion
		}
		currentName, currentVersion = "", ""
	}
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(strings.TrimRight(line, "\r"))
		if trimmed == "" {
			flush()
			continue
		}
		if strings.HasPrefix(trimmed, "HKEY_") {
			flush()
			continue
		}
		fields := splitRegFields(trimmed)
		if len(fields) < 3 {
			continue
		}
		switch fields[0] {
		case "DisplayName":
			currentName = fields[2]
		case "DisplayVersion":
			currentVersion = fields[2]
		}
	}
	flush()
	return result
}

func splitRegFields(line string) []string {
	if strings.Contains(line, "\t") {
		var out []string
		for _, part := range strings.Split(line, "\t") {
			if part = strings.TrimSpace(part); part != "" {
				out = append(out, part)
			}
		}
		return out
	}
	var out []string
	for _, part := range strings.Split(line, "    ") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func purlName(name string) string {
	slug := strings.ToLower(strings.TrimSpace(name))
	slug = strings.ReplaceAll(slug, " ", "-")
	slug = strings.ReplaceAll(slug, "(", "")
	slug = strings.ReplaceAll(slug, ")", "")
	return url.PathEscape(slug)
}

func windowsOSInfo() (string, string) {
	out, err := exec.Command("reg", "query", `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`).Output()
	if err != nil {
		return "windows", ""
	}
	product, display := "", ""
	for _, line := range strings.Split(string(out), "\n") {
		fields := splitRegFields(strings.TrimSpace(strings.TrimRight(line, "\r")))
		if len(fields) < 3 {
			continue
		}
		switch fields[0] {
		case "ProductName":
			product = fields[2]
		case "DisplayVersion":
			display = fields[2]
		}
	}
	if product == "" {
		product = "windows"
	}
	return product, display
}

// ---------- Agent 自身 SBOM ----------

// SelfSBOM 从构建信息读取自身模块与依赖版本
func SelfSBOM() []Component {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return nil
	}
	var comps []Component
	for _, dep := range info.Deps {
		if dep == nil || dep.Path == "" || dep.Version == "" || dep.Version == "(devel)" {
			continue
		}
		comps = append(comps, Component{
			PURL:    "pkg:golang/" + dep.Path + "@" + dep.Version,
			Name:    dep.Path,
			Version: dep.Version,
			Eco:     "golang",
			Vendor:  "golang",
			Product: dep.Path,
			Source:  "self",
		})
	}
	return comps
}

// ComponentCount 便于日志输出
func (r Report) ComponentCount() string {
	return strconv.Itoa(len(r.Components))
}
