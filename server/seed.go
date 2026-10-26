package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"vulnagent/server/internal/infrastructure/sqlite"
)

// ---------- 演示数据定义 ----------

type seedComp struct {
	purl, name, version, eco, vendor, product string
}

func debPkg(name, version string) seedComp {
	return seedComp{purl: "pkg:deb/debian/" + name + "@" + version, name: name, version: version, eco: "deb", vendor: "debian", product: name}
}

func mvnPkg(group, artifact, version string) seedComp {
	return seedComp{purl: "pkg:maven/" + group + "/" + artifact + "@" + version, name: artifact, version: version, eco: "maven", vendor: group, product: artifact}
}

func npmPkg(name, version string) seedComp {
	return seedComp{purl: "pkg:npm/" + name + "@" + version, name: name, version: version, eco: "npm", vendor: "npm", product: name}
}

func goPkg(module, version string) seedComp {
	return seedComp{purl: "pkg:golang/" + module + "@" + version, name: module, version: version, eco: "golang", vendor: "golang", product: module}
}

func ociPkg(name, version string) seedComp {
	return seedComp{purl: "pkg:oci/" + name + "@" + version, name: name, version: version, eco: "oci", vendor: "docker", product: name}
}

func pyPkg(name, version string) seedComp {
	return seedComp{purl: "pkg:pypi/" + name + "@" + version, name: name, version: version, eco: "pypi", vendor: "pypi", product: name}
}

func nugetPkg(name, version string) seedComp {
	return seedComp{purl: "pkg:nuget/" + name + "@" + version, name: name, version: version, eco: "nuget", vendor: "nuget", product: name}
}

type seedAsset struct {
	hostname, ip, osFamily, osVersion string
	env, exposure, tier, owner        string
	source, agentStatus               string
	lastSeenAgo                       time.Duration
	comps                             []seedComp
}

type seedCVE struct {
	id, title, desc, vector string
	score                   float64
	severity                string
	cweID                   int
	cweCN                   string
	published, updated      string
	epss                    float64
	exploit                 string
	poc                     string
	fixed                   string
	names                   []string
	versions                []string
}

// affectedOverrides 补充受影响区间的下界或精确上界（缺省上界 = 修复版本）。
// 这些区间用于演示"按版本区间匹配"，不是生产级漏洞数据。
var affectedOverrides = map[string]struct{ start, end string }{
	"CVE-2021-44228": {"2.0.0", "2.15.0"},
	"CVE-2021-45046": {"2.0.0", "2.17.1"},
	"CVE-2021-45105": {"2.0.0", "2.17.0"},
	"CVE-2021-3156":  {"1.8.2", "1.9.5p2"},
	"CVE-2023-38545": {"7.69.0", "8.4.0"},
	"CVE-2024-3094":  {"5.6.0", "5.6.2"},
	"CVE-2021-41773": {"2.4.49", "2.4.50"},
	"CVE-2024-6387":  {"8.5p1", "9.8p1"},
	"CVE-2023-4911":  {"2.34", "2.38"},
	"CVE-2022-42889": {"1.5", "1.10.0"},
	"CVE-2022-0847":  {"5.8", "5.16.11"},
	"CVE-2022-21449": {"15", "17.0.3"},
	"CVE-2022-34265": {"3.2", "3.2.14"},
	"CVE-2023-32681": {"2.3.0", "2.31.0"},
	"CVE-2021-43798": {"8.0.0", "8.5.1"},
	"CVE-2024-27316": {"2.4.17", "2.4.59"},
	"CVE-2022-0185":  {"5.4", "5.16.2"},
	"CVE-2023-32233": {"5.1", "6.3.4"},
}

// affectedRange 返回该 CVE 的受影响区间（左闭右开）
func (c seedCVE) affectedRange() (start, end string) {
	if o, ok := affectedOverrides[c.id]; ok {
		return o.start, o.end
	}
	return "", c.fixed
}

func atMidnight(date string) string {
	t, err := time.ParseInLocation("2006-01-02", date, cst)
	if err != nil {
		return date + "T00:00:00+08:00"
	}
	return fmtT(t)
}

// demoAssets 12 台演示资产及其组件清单
func demoAssets() []seedAsset {
	return []seedAsset{
		{
			hostname: "web-01", ip: "10.20.1.11", osFamily: "debian", osVersion: "12",
			env: "prod", exposure: "public", tier: "core", owner: "交易平台组",
			source: "agent", agentStatus: "online", lastSeenAgo: 2 * time.Minute,
			comps: []seedComp{
				debPkg("openssl", "3.0.11"), debPkg("openssh-server", "8.2p1"), debPkg("sudo", "1.9.9"),
				debPkg("curl", "7.81.0"), debPkg("bash", "5.1-2"), debPkg("apache2", "2.4.52"),
				debPkg("libc6", "2.31-13+deb11u5"), debPkg("systemd", "252.22"), debPkg("python3", "3.11.2"),
				debPkg("zlib1g", "1.2.11"), debPkg("openjdk-17-jre", "17.0.2"),
				mvnPkg("org.apache.logging.log4j", "log4j-core", "2.14.1"),
				mvnPkg("org.springframework", "spring-beans", "5.3.17"),
				mvnPkg("org.springframework", "spring-core", "5.3.17"),
				npmPkg("lodash", "4.17.20"), npmPkg("express", "4.17.1"), npmPkg("react", "18.2.0"),
			},
		},
		{
			hostname: "web-02", ip: "10.20.1.12", osFamily: "debian", osVersion: "12",
			env: "prod", exposure: "public", tier: "core", owner: "交易平台组",
			source: "agent", agentStatus: "online", lastSeenAgo: 5 * time.Minute,
			comps: []seedComp{
				debPkg("nginx", "1.22.1"), debPkg("openssl", "3.0.11"), debPkg("bash", "5.1-2"),
				debPkg("nodejs", "18.17.0"), debPkg("libwebp7", "1.2.4"), debPkg("zlib1g", "1.2.11"),
				debPkg("libxml2", "2.9.14"), debPkg("python3", "3.11.2"), debPkg("systemd", "252.22"),
				debPkg("git", "2.39.2"),
				npmPkg("lodash", "4.17.20"), npmPkg("axios", "0.21.1"), npmPkg("react", "18.2.0"),
				npmPkg("webpack", "5.73.0"), npmPkg("jquery", "3.4.1"),
			},
		},
		{
			hostname: "api-01", ip: "10.20.2.21", osFamily: "debian", osVersion: "12",
			env: "prod", exposure: "internal", tier: "core", owner: "交易平台组",
			source: "agent", agentStatus: "online", lastSeenAgo: 1 * time.Minute,
			comps: []seedComp{
				mvnPkg("org.apache.logging.log4j", "log4j-core", "2.14.1"),
				mvnPkg("org.springframework", "spring-beans", "5.3.17"),
				mvnPkg("org.springframework", "spring-core", "5.3.17"),
				mvnPkg("org.apache.commons", "commons-text", "1.9"),
				mvnPkg("commons-collections", "commons-collections", "3.2.1"),
				mvnPkg("com.fasterxml.jackson.core", "jackson-databind", "2.13.4"),
				debPkg("openjdk-17-jre", "17.0.2"), debPkg("openssl", "3.0.11"),
				debPkg("openssh-server", "8.2p1"), debPkg("curl", "7.81.0"), debPkg("bash", "5.1-2"),
				debPkg("libc6", "2.31-13+deb11u5"), debPkg("python3", "3.11.2"),
				goPkg("golang.org/x/net", "v0.10.0"),
			},
		},
		{
			hostname: "db-01", ip: "10.20.3.31", osFamily: "debian", osVersion: "12",
			env: "prod", exposure: "internal", tier: "core", owner: "数据平台组",
			source: "agent", agentStatus: "online", lastSeenAgo: 3 * time.Minute,
			comps: []seedComp{
				debPkg("postgresql-15", "15.3"), debPkg("openssl", "3.0.11"), debPkg("bash", "5.1-2"),
				debPkg("zlib1g", "1.2.11"), debPkg("systemd", "252.22"), debPkg("policykit-1", "0.105"),
				debPkg("python3", "3.11.2"), debPkg("rsync", "3.2.7"), debPkg("cron", "3.0"),
				debPkg("libxml2", "2.9.14"),
			},
		},
		{
			hostname: "cache-01", ip: "10.20.3.32", osFamily: "debian", osVersion: "12",
			env: "prod", exposure: "internal", tier: "important", owner: "数据平台组",
			source: "agent", agentStatus: "online", lastSeenAgo: 4 * time.Minute,
			comps: []seedComp{
				debPkg("redis-server", "7.0.11"), debPkg("nginx", "1.20.1"), debPkg("libssl1.1", "1.1.1m"),
				debPkg("bash", "5.1-2"), debPkg("zlib1g", "1.2.11"), debPkg("systemd", "252.22"),
				debPkg("openssl", "3.0.11"), debPkg("python3", "3.11.2"), debPkg("supervisor", "4.2.4"),
			},
		},
		{
			hostname: "k8s-node-01", ip: "10.30.1.41", osFamily: "debian", osVersion: "12",
			env: "prod", exposure: "internal", tier: "core", owner: "容器平台组",
			source: "agent", agentStatus: "online", lastSeenAgo: 2 * time.Minute,
			comps: []seedComp{
				debPkg("containerd", "1.6.20"), debPkg("docker.io", "20.10.24"), debPkg("openssl", "3.0.11"),
				debPkg("openssh-server", "8.2p1"), debPkg("sudo", "1.9.9"), debPkg("bash", "5.1-2"),
				debPkg("libc6", "2.31-13+deb11u5"), debPkg("linux-image-amd64", "5.10.92"),
				debPkg("policykit-1", "0.105"), debPkg("libwebp7", "1.2.4"),
				goPkg("k8s.io/kubernetes", "v1.26.3"), ociPkg("nginx", "1.24.0"),
			},
		},
		{
			hostname: "k8s-node-02", ip: "10.30.1.42", osFamily: "debian", osVersion: "12",
			env: "prod", exposure: "internal", tier: "core", owner: "容器平台组",
			source: "agent", agentStatus: "stale", lastSeenAgo: 6 * time.Hour,
			comps: []seedComp{
				debPkg("containerd", "1.6.20"), debPkg("docker.io", "20.10.24"), debPkg("openssl", "3.0.11"),
				debPkg("bash", "5.1-2"), debPkg("zlib1g", "1.2.11"), debPkg("python3", "3.11.2"),
				debPkg("linux-image-amd64", "5.10.92"), debPkg("systemd", "252.22"),
				debPkg("libxml2", "2.9.14"),
				ociPkg("nginx", "1.24.0"),
				seedComp{purl: "pkg:golang/github.com/grafana/grafana@v8.5.0", name: "grafana", version: "8.5.0", eco: "golang", vendor: "grafana", product: "grafana"},
			},
		},
		{
			hostname: "build-01", ip: "10.30.2.51", osFamily: "debian", osVersion: "12",
			env: "staging", exposure: "internal", tier: "important", owner: "研发效能组",
			source: "agent", agentStatus: "offline", lastSeenAgo: 30 * time.Hour,
			comps: []seedComp{
				debPkg("git", "2.39.2"), debPkg("xz-utils", "5.6.1"), debPkg("python3", "3.11.2"),
				debPkg("nodejs", "18.17.0"), debPkg("maven", "3.8.7"), debPkg("gcc", "12.2.0"),
				debPkg("bash", "5.1-2"), debPkg("unzip", "6.0"), debPkg("curl", "7.81.0"),
				debPkg("openssl", "3.0.11"),
				pyPkg("requests", "2.25.1"), pyPkg("django", "3.2.12"), npmPkg("lodash", "4.17.11"),
			},
		},
		{
			hostname: "jenkins-01", ip: "10.30.2.52", osFamily: "debian", osVersion: "12",
			env: "prod", exposure: "internal", tier: "important", owner: "研发效能组",
			source: "agent", agentStatus: "online", lastSeenAgo: 8 * time.Minute,
			comps: []seedComp{
				mvnPkg("org.jenkins-ci.main", "jenkins-core", "2.387.1"),
				debPkg("openjdk-17-jre", "17.0.2"), debPkg("git", "2.39.2"), debPkg("openssl", "3.0.11"),
				debPkg("bash", "5.1-2"), debPkg("maven", "3.8.7"), debPkg("python3", "3.11.2"),
				debPkg("zlib1g", "1.2.11"), debPkg("nodejs", "18.17.0"), debPkg("systemd", "252.22"),
				npmPkg("lodash", "4.17.20"),
			},
		},
		{
			hostname: "win-app-01", ip: "10.10.4.61", osFamily: "windows", osVersion: "server-2019",
			env: "prod", exposure: "internal", tier: "important", owner: "财务系统组",
			source: "agent", agentStatus: "online", lastSeenAgo: 12 * time.Minute,
			comps: []seedComp{
				nugetPkg("Newtonsoft.Json", "12.0.3"), nugetPkg("Microsoft.Data.SqlClient", "5.1.1"),
				nugetPkg("System.Text.Json", "6.0.5"), nugetPkg("log4net", "2.0.15"),
				nugetPkg("Serilog", "2.10.0"), nugetPkg("Dapper", "2.0.123"),
				nugetPkg("Azure.Identity", "1.7.0"),
				mvnPkg("org.apache.logging.log4j", "log4j-core", "2.14.1"),
			},
		},
		{
			hostname: "legacy-01", ip: "10.10.9.71", osFamily: "debian", osVersion: "10",
			env: "staging", exposure: "isolated", tier: "normal", owner: "财务系统组",
			source: "ssh", agentStatus: "none", lastSeenAgo: 72 * time.Hour,
			comps: []seedComp{
				debPkg("apache2", "2.4.49"), debPkg("tomcat9", "9.0.30"),
				mvnPkg("org.apache.struts", "struts2-core", "2.5.26"),
				debPkg("libssl1.1", "1.1.1m"), debPkg("openssh-server", "8.2p1"),
				debPkg("sudo", "1.9.9"), debPkg("bash", "5.1-2"),
				debPkg("libc6", "2.31-13+deb11u5"), debPkg("python3", "3.11.2"),
				debPkg("policykit-1", "0.105"), debPkg("curl", "7.81.0"), debPkg("zlib1g", "1.2.11"),
				debPkg("libxml2", "2.9.14"),
			},
		},
		{
			hostname: "vulnagent-self", ip: "127.0.0.1", osFamily: "linux", osVersion: "6.8",
			env: "prod", exposure: "internal", tier: "core", owner: "安全平台组",
			source: "self", agentStatus: "none", lastSeenAgo: 30 * time.Second,
			comps: []seedComp{
				goPkg("github.com/gin-gonic/gin", "v1.9.1"), goPkg("golang.org/x/net", "v0.10.0"),
				goPkg("golang.org/x/crypto", "v0.6.0"), goPkg("modernc.org/sqlite", "v1.28.0"),
				goPkg("github.com/gorilla/websocket", "v1.5.0"), goPkg("github.com/jackc/pgx/v5", "v5.3.1"),
				goPkg("golang.org/x/text", "v0.9.0"),
				npmPkg("react", "18.2.0"), npmPkg("vite", "4.5.0"),
			},
		},
	}
}

// demoCVEs 29 条真实 CVE，用于演示匹配与排序
func demoCVEs() []seedCVE {
	return []seedCVE{
		{
			id: "CVE-2021-44228", title: "Apache Log4j2 JNDI 远程代码执行（Log4Shell）",
			desc:   "Apache Log4j2 在启用消息查找时未限制 ${jndi:} 前缀，攻击者可通过可控的日志字段触发 JNDI 加载并执行任意代码，互联网上已存在大规模在野利用。",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", score: 10.0, severity: "critical",
			cweID: 502, cweCN: "反序列化不可信数据", published: "2021-12-10", updated: "2024-09-10",
			epss: 0.944, exploit: "kev", poc: "https://github.com/apache/logging-log4j2/pull/608",
			fixed: "2.17.1", names: []string{"log4j-core"}, versions: []string{"2.14.1"},
		},
		{
			id: "CVE-2021-45046", title: "Apache Log4j2 线程上下文查找导致代码执行",
			desc:   "2.15.0 的修复并不完整，攻击者仍可通过线程上下文注入构造恶意 JNDI 查找，在特定配置下造成信息泄露或远程代码执行。",
			vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H", score: 9.0, severity: "critical",
			cweID: 502, cweCN: "反序列化不可信数据", published: "2021-12-15", updated: "2024-08-08",
			epss: 0.912, exploit: "kev", poc: "https://github.com/apache/logging-log4j2/pull/618",
			fixed: "2.17.1", names: []string{"log4j-core"}, versions: []string{"2.14.1"},
		},
		{
			id: "CVE-2021-45105", title: "Apache Log4j2 递归查找导致拒绝服务",
			desc:   "Log4j2 在解析包含递归变量的日志消息时可能陷入无限递归，导致线程栈溢出并使进程退出。",
			vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", score: 5.9, severity: "medium",
			cweID: 674, cweCN: "未受控递归", published: "2021-12-18", updated: "2023-11-02",
			epss: 0.31, exploit: "none", poc: "",
			fixed: "2.17.1", names: []string{"log4j-core"}, versions: []string{"2.14.1"},
		},
		{
			id: "CVE-2022-22965", title: "Spring Framework DataBinder 远程代码执行（Spring4Shell）",
			desc:   "在 JDK 9+ 且以 WAR 包部署于 Tomcat 的场景下，攻击者可通过构造请求参数访问 class.module.classLoader 并写入 WebShell。",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score: 9.8, severity: "critical",
			cweID: 94, cweCN: "代码注入", published: "2022-04-01", updated: "2024-08-05",
			epss: 0.943, exploit: "kev", poc: "https://github.com/BobTheShoplifter/Spring4Shell-POC",
			fixed: "5.3.18", names: []string{"spring-beans"}, versions: []string{"5.3.17"},
		},
		{
			id: "CVE-2021-3156", title: "sudo 堆缓冲区溢出本地提权（Baron Samedit）",
			desc:   "sudo 在处理 sudoedit 与 shell 转义参数时存在堆溢出，普通用户可在默认配置下提升为 root。",
			vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", score: 7.8, severity: "high",
			cweID: 122, cweCN: "堆缓冲区溢出", published: "2021-01-26", updated: "2024-06-20",
			epss: 0.42, exploit: "kev", poc: "https://github.com/blasty/CVE-2021-3156",
			fixed: "1.9.5p2", names: []string{"sudo"}, versions: []string{"1.9.9"},
		},
		{
			id: "CVE-2023-38545", title: "curl SOCKS5 代理握手堆缓冲区溢出",
			desc:   "curl 在 SOCKS5 代理握手期间处理超长主机名时会写越界，可被恶意代理利用执行代码。",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", score: 8.8, severity: "high",
			cweID: 787, cweCN: "越界写入", published: "2023-10-11", updated: "2024-04-30",
			epss: 0.36, exploit: "poc", poc: "https://github.com/curl/curl/commit/fb4414f",
			fixed: "8.4.0", names: []string{"curl"}, versions: []string{"7.81.0"},
		},
		{
			id: "CVE-2024-3094", title: "xz-utils 供应链后门（liblzma）",
			desc:   "xz 5.6.0/5.6.1 的构建脚本被植入后门，通过 liblzma 劫持 OpenSSH sshd 的认证流程，可实现未授权远程代码执行。",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", score: 10.0, severity: "critical",
			cweID: 506, cweCN: "内嵌恶意代码", published: "2024-03-29", updated: "2024-10-15",
			epss: 0.71, exploit: "kev", poc: "https://github.com/tukaani-project/xz",
			fixed: "5.6.2", names: []string{"xz-utils"}, versions: []string{"5.6.1"},
		},
		{
			id: "CVE-2021-41773", title: "Apache HTTP Server 路径穿越与远程代码执行",
			desc:   "Apache 2.4.49 的路径规范化存在缺陷，攻击者可穿越到根目录读取任意文件，启用 CGI 时可进一步执行命令。",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", score: 7.5, severity: "high",
			cweID: 22, cweCN: "路径穿越", published: "2021-10-05", updated: "2024-01-10",
			epss: 0.942, exploit: "kev", poc: "https://github.com/blasty/CVE-2021-41773",
			fixed: "2.4.51", names: []string{"apache2"}, versions: []string{"2.4.49"},
		},
		{
			id: "CVE-2020-1938", title: "Apache Tomcat AJP 协议文件包含（Ghostcat）",
			desc:   "Tomcat AJP 连接器未限制可读取的文件范围，攻击者可读取 webapp 目录下的任意文件，并可能包含 JSP 执行代码。",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score: 9.8, severity: "critical",
			cweID: 22, cweCN: "路径穿越", published: "2020-02-24", updated: "2023-06-14",
			epss: 0.95, exploit: "kev", poc: "https://github.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi",
			fixed: "9.0.31", names: []string{"tomcat9", "tomcat-embed-core"}, versions: []string{"9.0.30"},
		},
		{
			id: "CVE-2023-44487", title: "HTTP/2 Rapid Reset 拒绝服务",
			desc:   "攻击者通过快速建立并重置 HTTP/2 流，绕过并发限制造成服务端资源耗尽，主流 HTTP/2 实现均受影响。",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", score: 7.5, severity: "high",
			cweID: 400, cweCN: "资源耗尽", published: "2023-10-10", updated: "2024-09-18",
			epss: 0.55, exploit: "poc", poc: "https://github.com/golang/go/issues/63417",
			fixed: "v0.17.0", names: []string{"golang.org/x/net"}, versions: []string{"v0.10.0"},
		},
		{
			id: "CVE-2024-6387", title: "OpenSSH 信号处理器竞争条件远程代码执行（regreSSHion）",
			desc:   "sshd 的 SIGALRM 处理函数存在异步信号安全问题，在 glibc 环境下可能被利用实现未认证远程代码执行。",
			vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", score: 8.1, severity: "high",
			cweID: 364, cweCN: "信号竞争条件", published: "2024-07-01", updated: "2024-10-01",
			epss: 0.53, exploit: "poc", poc: "https://github.com/7etsuo/CVE-2024-6387",
			fixed: "9.8p1", names: []string{"openssh-server"}, versions: []string{"8.2p1"},
		},
		{
			id: "CVE-2021-23337", title: "lodash 命令注入",
			desc:   "lodash 的 template 等函数未过滤输入中的特殊字符，拼接后可能造成命令注入。",
			vector: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", score: 7.2, severity: "high",
			cweID: 77, cweCN: "命令注入", published: "2021-02-15", updated: "2023-08-09",
			epss: 0.28, exploit: "poc", poc: "https://github.com/lodash/lodash/pull/5065",
			fixed: "4.17.21", names: []string{"lodash"}, versions: []string{"4.17.20", "4.17.11"},
		},
		{
			id: "CVE-2023-4911", title: "glibc ld.so 缓冲区溢出（Looney Tunables）",
			desc:   "glibc 动态链接器在处理 GLIBC_TUNABLES 环境变量时存在缓冲区溢出，本地攻击者可提升至 root。",
			vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", score: 7.8, severity: "high",
			cweID: 787, cweCN: "越界写入", published: "2023-10-03", updated: "2024-05-22",
			epss: 0.52, exploit: "kev", poc: "https://github.com/leesh3288/CVE-2023-4911",
			fixed: "2.36-9+deb12u3", names: []string{"libc6"}, versions: []string{"2.31-13+deb11u5"},
		},
		{
			id: "CVE-2022-0778", title: "OpenSSL BN_mod_sqrt 无限循环拒绝服务",
			desc:   "OpenSSL 解析特制证书中的 ANSI X9.62 曲线参数时进入无限循环，导致进程 CPU 占满。",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", score: 7.5, severity: "high",
			cweID: 835, cweCN: "无限循环", published: "2022-03-15", updated: "2023-11-07",
			epss: 0.24, exploit: "poc", poc: "https://github.com/openssl/openssl/commit/9e2095a",
			fixed: "1.1.1n", names: []string{"libssl1.1"}, versions: []string{"1.1.1m"},
		},
		{
			id: "CVE-2020-17530", title: "Apache Struts2 OGNL 表达式注入（S2-061）",
			desc:   "Struts2 在标签属性二次求值时未过滤 OGNL 表达式，攻击者可通过请求参数执行任意代码。",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score: 9.8, severity: "critical",
			cweID: 94, cweCN: "代码注入", published: "2020-12-11", updated: "2023-09-06",
			epss: 0.94, exploit: "poc", poc: "https://github.com/wuzuowei/CVE-2020-17530",
			fixed: "2.5.30", names: []string{"struts2-core"}, versions: []string{"2.5.26"},
		},
		{
			id: "CVE-2022-42889", title: "Apache Commons Text 字符串插值远程代码执行（Text4Shell）",
			desc:   "Commons Text 的 StringSubstitutor 默认插值器支持 script、dns、url 前缀，攻击者可构造输入执行任意代码或发起外连。",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score: 9.8, severity: "critical",
			cweID: 94, cweCN: "代码注入", published: "2022-10-13", updated: "2024-02-15",
			epss: 0.88, exploit: "poc", poc: "https://github.com/karthikuj/CVE-2022-42889-text4shell",
			fixed: "1.10.0", names: []string{"commons-text"}, versions: []string{"1.9"},
		},
		{
			id: "CVE-2019-10744", title: "lodash 原型污染",
			desc:   "lodash 的 defaultsDeep 等函数可被构造的 __proto__ 键污染 Object 原型，进而影响依赖该原型的业务逻辑。",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", score: 9.1, severity: "critical",
			cweID: 1321, cweCN: "原型污染", published: "2019-07-15", updated: "2023-02-03",
			epss: 0.16, exploit: "poc", poc: "https://github.com/lodash/lodash/pull/4336",
			fixed: "4.17.12", names: []string{"lodash"}, versions: []string{"4.17.11"},
		},
		{
			id: "CVE-2022-0847", title: "Linux 内核 Dirty Pipe 本地提权",
			desc:   "内核管道缓冲区标志位未正确初始化，本地用户可覆写只读文件页面缓存，从而修改 SUID 程序实现提权。",
			vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", score: 7.8, severity: "high",
			cweID: 665, cweCN: "初始化不当", published: "2022-03-10", updated: "2024-07-11",
			epss: 0.62, exploit: "kev", poc: "https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit",
			fixed: "5.16.11", names: []string{"linux-image-amd64"}, versions: []string{"5.10.92"},
		},
		{
			id: "CVE-2021-4034", title: "polkit pkexec 本地提权（PwnKit）",
			desc:   "pkexec 在处理参数时存在越界读写，本地任意用户可通过构造 argv 获得 root 权限，利用代码已公开。",
			vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", score: 7.8, severity: "high",
			cweID: 787, cweCN: "越界写入", published: "2022-01-28", updated: "2024-03-19",
			epss: 0.83, exploit: "kev", poc: "https://github.com/berdav/CVE-2021-4034",
			fixed: "0.105-31+deb11u1", names: []string{"policykit-1"}, versions: []string{"0.105"},
		},
		{
			id: "CVE-2023-4863", title: "libwebp 堆缓冲区溢出",
			desc:   "libwebp 在解析特制 WebP 无损图像时发生堆溢出，浏览器或图像处理链路可被利用执行代码。",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", score: 8.8, severity: "high",
			cweID: 787, cweCN: "越界写入", published: "2023-09-12", updated: "2024-08-20",
			epss: 0.72, exploit: "kev", poc: "https://github.com/webmproject/libwebp/commit/2af26267",
			fixed: "1.3.2", names: []string{"libwebp7"}, versions: []string{"1.2.4"},
		},
		{
			id: "CVE-2022-21449", title: "Java ECDSA 签名校验绕过（Psychic Signatures）",
			desc:   "Java 15 至 17.0.2 的 ECDSA 实现未校验 r、s 是否为零，攻击者可伪造空签名通过验签。",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", score: 7.5, severity: "high",
			cweID: 347, cweCN: "签名校验不当", published: "2022-04-19", updated: "2023-12-12",
			epss: 0.21, exploit: "poc", poc: "https://github.com/Ch4m1ng/CVE-2022-21449",
			fixed: "17.0.3", names: []string{"openjdk-17-jre"}, versions: []string{"17.0.2"},
		},
		{
			id: "CVE-2022-34265", title: "Django Trunc/Extract 数据库函数注入",
			desc:   "Django 在处理 Trunc 与 Extract 的 kind 参数时未充分转义，攻击者可注入 SQL 片段读取或篡改数据。",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score: 9.8, severity: "critical",
			cweID: 89, cweCN: "SQL 注入", published: "2022-07-04", updated: "2023-10-25",
			epss: 0.37, exploit: "poc", poc: "https://github.com/django/django/commit/1ba2b1b",
			fixed: "3.2.14", names: []string{"django"}, versions: []string{"3.2.12"},
		},
		{
			id: "CVE-2021-3749", title: "axios 正则拒绝服务（ReDoS）",
			desc:   "axios 的 trim 正则存在灾难性回溯，攻击者通过构造超长请求头或参数即可造成 CPU 占满。",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", score: 7.5, severity: "high",
			cweID: 1333, cweCN: "正则复杂度", published: "2021-08-31", updated: "2023-05-17",
			epss: 0.18, exploit: "none", poc: "",
			fixed: "0.21.2", names: []string{"axios"}, versions: []string{"0.21.1"},
		},
		{
			id: "CVE-2023-32681", title: "requests 代理凭据泄露",
			desc:   "requests 在遇到重定向到不同主机时未剥离 Proxy-Authorization 头，可能将代理凭据泄露给第三方。",
			vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N", score: 6.1, severity: "medium",
			cweID: 200, cweCN: "敏感信息泄露", published: "2023-05-26", updated: "2024-01-22",
			epss: 0.09, exploit: "none", poc: "",
			fixed: "2.31.0", names: []string{"requests"}, versions: []string{"2.25.1"},
		},
		{
			id: "CVE-2021-23017", title: "nginx DNS 解析器一字节堆覆盖",
			desc:   "nginx 在使用 resolver 解析上游域名时存在差一错误，攻击者控制的 DNS 响应可覆盖堆内存并可能导致代码执行。",
			vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", score: 7.7, severity: "high",
			cweID: 193, cweCN: "差一错误", published: "2021-06-01", updated: "2023-04-11",
			epss: 0.15, exploit: "poc", poc: "https://github.com/nginx/nginx/commit/1e7c4b1",
			fixed: "1.21.0", names: []string{"nginx"}, versions: []string{"1.20.1"},
		},
		{
			id: "CVE-2021-43798", title: "Grafana 目录穿越任意文件读取",
			desc:   "Grafana 插件静态资源路由未做路径校验，未授权攻击者可读取服务器上的任意文件，包括配置文件与密钥。",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", score: 7.5, severity: "high",
			cweID: 22, cweCN: "路径穿越", published: "2021-12-07", updated: "2024-02-28",
			epss: 0.94, exploit: "poc", poc: "https://github.com/grafana/grafana/security/advisories/GHSA-8pjx-jj86-j47p",
			fixed: "8.5.1", names: []string{"grafana"}, versions: []string{"8.5.0"},
		},
		{
			id: "CVE-2024-27316", title: "Apache HTTP Server HTTP/2 CONTINUATION 洪泛拒绝服务",
			desc:   "Apache 在未及时清理 HTTP/2 CONTINUATION 帧时造成内存持续增长，攻击者可耗尽服务端内存。",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", score: 7.5, severity: "high",
			cweID: 400, cweCN: "资源耗尽", published: "2024-04-04", updated: "2024-09-05",
			epss: 0.33, exploit: "poc", poc: "https://httpd.apache.org/security/vulnerabilities_24.html",
			fixed: "2.4.59", names: []string{"apache2"}, versions: []string{"2.4.52"},
		},
		{
			id: "CVE-2022-0185", title: "Linux 内核 fs_context 堆溢出容器逃逸",
			desc:   "内核 legacy_parse_param 未限制参数长度导致堆溢出，具备 CAP_SYS_ADMIN 的容器内用户可逃逸到宿主机。",
			vector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score: 8.4, severity: "high",
			cweID: 190, cweCN: "整数溢出", published: "2022-01-18", updated: "2023-12-06",
			epss: 0.45, exploit: "poc", poc: "https://github.com/Crusaders-of-Rust/CVE-2022-0185",
			fixed: "5.16.2", names: []string{"linux-image-amd64"}, versions: []string{"5.10.92"},
		},
		{
			id: "CVE-2023-32233", title: "Linux 内核 nf_tables 释放后使用",
			desc:   "nf_tables 在处理批量请求时存在释放后使用，本地用户可获得 root 权限。",
			vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", score: 7.8, severity: "high",
			cweID: 416, cweCN: "释放后使用", published: "2023-05-08", updated: "2024-04-16",
			epss: 0.57, exploit: "kev", poc: "https://github.com/LiveOverflow/CVE-2023-32233",
			fixed: "6.3.4", names: []string{"linux-image-amd64"}, versions: []string{"5.10.92"},
		},
	}
}

// ---------- 灌数据 ----------

var findingStatusPattern = []string{
	"open", "open", "triaged", "open", "fixing", "open", "fixed", "triaged", "open", "verified",
	"fixing", "open", "triaged", "risk_accepted", "open", "fixed", "false_positive", "open", "closed", "triaged",
}

var statusDetail = map[string]string{
	"triaged":        "已确认受影响，等待排期",
	"fixing":         "已排期变更窗口处理",
	"fixed":          "补丁已上线，等待复扫验证",
	"verified":       "复扫通过，组件版本已升级",
	"risk_accepted":  "业务侧接受风险，已补充补偿控制",
	"false_positive": "经人工复核为误报，组件未加载受影响功能",
	"closed":         "修复完成并关闭",
}

// ensureRiskPolicy 风险策略始终存在，避免历史库或生产库缺失
func ensureRiskPolicy(db *sql.DB) error {
	policy := defaultPolicy()
	wJSON, _ := json.Marshal(policy.Weights)
	tJSON, _ := json.Marshal(policy.Thresholds)
	_, err := db.Exec(`INSERT INTO risk_policy(id, weights, thresholds, updated_at) VALUES(1,?,?,?)
		ON CONFLICT(id) DO NOTHING`, string(wJSON), string(tJSON), fmtT(nowT()))
	return err
}

func seedDemo(db *sql.DB) error {
	// 风险策略始终保证存在，避免历史库缺失
	if err := ensureRiskPolicy(db); err != nil {
		return err
	}
	policy := defaultPolicy()

	var assetCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM assets`).Scan(&assetCount); err != nil {
		return err
	}

	// CVE 目录与受影响区间始终保证存在且可重复执行
	if err := seedCatalog(db); err != nil {
		return err
	}
	if assetCount > 0 {
		// 历史库：演示数据已存在但可能缺标记，这里补齐
		return setMeta(db, "demo_mode", "1")
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	now := nowT()
	cves := demoCVEs()

	// 1. 资产与组件
	assets := demoAssets()
	assetIDs := make(map[string]int64, len(assets))
	for _, a := range assets {
		lastSeen := now.Add(-a.lastSeenAgo)
		res, err := tx.Exec(`INSERT INTO assets(hostname, ip, os_family, os_version, env, exposure, tier,
			owner, source, agent_status, last_seen_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
			a.hostname, a.ip, a.osFamily, a.osVersion, a.env, a.exposure, a.tier,
			a.owner, a.source, a.agentStatus, fmtT(lastSeen))
		if err != nil {
			return err
		}
		assetID, _ := res.LastInsertId()
		assetIDs[a.hostname] = assetID
		for _, comp := range a.comps {
			if _, err := tx.Exec(`INSERT INTO components(asset_id, purl, eco, name, version, vendor, product, inferred)
				VALUES(?,?,?,?,?,?,?,0)`, assetID, comp.purl, comp.eco, comp.name, comp.version, comp.vendor, comp.product); err != nil {
				return err
			}
		}
	}

	// 3. findings：按组件与受影响版本区间匹配生成
	byProduct := make(map[string][]seedCVE)
	for _, c := range cves {
		for _, n := range c.names {
			byProduct[strings.ToLower(n)] = append(byProduct[strings.ToLower(n)], c)
		}
	}
	assignees := []string{"李维", "王倩", "赵鹏"}
	idx := 0
	ticketSeq := 120
	type eventRow struct {
		findingID int64
		event     string
		actor     string
		detail    string
		createdAt time.Time
	}
	var events []eventRow

	for _, a := range assets {
		assetID := assetIDs[a.hostname]
		for _, comp := range a.comps {
			for _, c := range byProduct[strings.ToLower(comp.product)] {
				if !matchSeedAffected(c, comp) {
					continue
				}
				risk, priority, breakdown := policy.Score(c.score, c.epss, c.exploit, a.exposure, a.tier)
				status := findingStatusPattern[idx%len(findingStatusPattern)]
				assignee := ""
				if status != "open" || idx%4 != 0 {
					assignee = assignees[idx%len(assignees)]
				}
				ticketID := ""
				if status == "fixing" || status == "fixed" || status == "verified" {
					ticketID = fmt.Sprintf("VA-2026-%04d", ticketSeq)
					ticketSeq++
				}
				firstSeen := now.Add(-time.Duration(6+(idx*53)%470) * time.Hour)
				lastSeen := now.Add(-time.Duration(idx%7) * time.Hour)
				if lastSeen.Before(firstSeen) {
					lastSeen = firstSeen
				}
				res, err := tx.Exec(`INSERT INTO findings(asset_id, purl, component_name, component_version, eco,
					cve_id, cvss, epss, exploit, asset_weight, risk, priority, score_breakdown, status, inferred,
					fixed_version, assignee, ticket_id, first_seen, last_seen)
					VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,?,?,?,?,?)`,
					assetID, comp.purl, comp.name, comp.version, comp.eco, c.id, c.score, c.epss,
					c.exploit, assetWeight(a.exposure, a.tier), risk, priority, marshalBreakdown(breakdown),
					status, c.fixed, assignee, ticketID, fmtT(firstSeen), fmtT(lastSeen))
				if err != nil {
					return err
				}
				fid, _ := res.LastInsertId()

				if ticketID != "" {
					ticketAt := firstSeen.Add(time.Duration(2+idx%10) * time.Hour)
					if ticketAt.After(now) {
						ticketAt = now.Add(-time.Duration(idx%9+1) * time.Minute)
					}
					if _, err := tx.Exec(`INSERT INTO tickets(id, finding_id, cve_id, asset_id, priority,
						status, assignee, created_by, note, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
						ticketID, fid, c.id, assetID, priority, status,
						firstNonEmpty(assignee, "李维"), firstNonEmpty(assignee, "李维"),
						"控制面本地工单，需在变更窗口内完成修复并复扫验证",
						fmtT(ticketAt), fmtT(ticketAt)); err != nil {
						return err
					}
				}

				if status != "open" {
					clamp := func(t time.Time) time.Time {
						if t.After(now) {
							return now.Add(-time.Duration(idx%9+1) * time.Minute)
						}
						return t
					}
					detail := statusDetail[status]
					events = append(events, eventRow{
						findingID: fid,
						event:     "status: open → " + status,
						actor:     firstNonEmpty(assignee, "李维"),
						detail:    detail,
						createdAt: clamp(firstSeen.Add(time.Duration(3+idx%20) * time.Hour)),
					})
					if ticketID != "" {
						events = append(events, eventRow{
							findingID: fid,
							event:     "ticket: " + ticketID + " 已创建",
							actor:     firstNonEmpty(assignee, "李维"),
							detail:    "控制面本地工单已创建，需在变更窗口内完成修复",
							createdAt: clamp(firstSeen.Add(time.Duration(2+idx%10) * time.Hour)),
						})
					}
					if status == "verified" {
						events = append(events, eventRow{
							findingID: fid,
							event:     "rescan: 复扫通过",
							actor:     "系统",
							detail:    "组件版本已不低于修复版本，自动验证通过",
							createdAt: lastSeen,
						})
					}
				}
				idx++
			}
		}
	}

	for _, e := range events {
		if _, err := tx.Exec(`INSERT INTO finding_events(finding_id, event, actor, detail, created_at)
			VALUES(?,?,?,?,?)`, e.findingID, e.event, e.actor, e.detail, fmtT(e.createdAt)); err != nil {
			return err
		}
	}

	// 4. 情报同步状态
	type syncSeed struct {
		source string
		ago    time.Duration
		status string
		count  int
		errMsg string
	}
	syncs := []syncSeed{
		{"cve", 2 * time.Hour, "ok", 241873, ""},
		{"poc", 1 * time.Hour, "ok", 6120, ""},
		{"epss", 7 * time.Hour, "warn", 241873, "离线包导入，滞后 1 天"},
	}
	for _, s := range syncs {
		if _, err := tx.Exec(`INSERT INTO sync_cursors(source, last_run_at, status, count, error)
			VALUES(?,?,?,?,?)`, s.source, fmtT(now.Add(-s.ago)), s.status, s.count, s.errMsg); err != nil {
			return err
		}
	}

	// 5. 审计日志
	audits := demoAudits(now)
	for _, au := range audits {
		if _, err := tx.Exec(`INSERT INTO audit_logs(actor, role, action, target, ip, ua, detail, created_at)
			VALUES(?,?,?,?,?,?,?,?)`, au.actor, au.role, au.action, au.target, au.ip, "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", au.detail, fmtT(au.at)); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	if err := setMeta(db, "demo_mode", "1"); err != nil {
		return err
	}
	slog.Info("演示数据已灌入", "assets", len(assets), "cves", len(cves), "findings", idx)
	return nil
}

// seedCatalog 写入 CVE、POC 与受影响版本区间，可重复执行
func seedCatalog(db *sql.DB) error {
	now := nowT()
	for i, c := range demoCVEs() {
		if _, err := db.Exec(`INSERT OR REPLACE INTO cves(cve_id, title, description, cvss_vector, cvss_score,
			severity, cwe_id, cwe_cn, published_at, updated_at, record_state, official, epss, exploit_state, fixed_version)
			VALUES(?,?,?,?,?,?,?,?,?,?,'published',1,?,?,?)`,
			c.id, c.title, c.desc, c.vector, c.score, c.severity, c.cweID, c.cweCN,
			atMidnight(c.published), atMidnight(c.updated), c.epss, c.exploit, c.fixed); err != nil {
			return err
		}
		if c.poc != "" {
			inserted := now.Add(-time.Duration((i%9)+1) * 24 * time.Hour)
			if _, err := db.Exec(`INSERT OR IGNORE INTO cve_poc(cve_id, link, inserted_at) VALUES(?,?,?)`,
				c.id, c.poc, fmtT(inserted)); err != nil {
				return err
			}
		}
		start, end := c.affectedRange()
		for _, name := range c.names {
			if _, err := db.Exec(`INSERT OR REPLACE INTO cve_affected(cve_id, product, version_start_incl,
				version_end_excl, fixed_version) VALUES(?,?,?,?,?)`,
				c.id, strings.ToLower(name), start, end, c.fixed); err != nil {
				return err
			}
		}
	}
	return nil
}

// matchSeedAffected 使用统一的版本区间规则判断演示组件是否命中
func matchSeedAffected(c seedCVE, comp seedComp) bool {
	start, end := c.affectedRange()
	return AffectedRange{
		CveID:            c.id,
		Product:          comp.product,
		VersionStartIncl: start,
		VersionEndExcl:   end,
	}.Matches(comp.eco, comp.version)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

type auditSeed struct {
	actor, role, action, target, ip, detail string
	at                                      time.Time
}

func demoAudits(now time.Time) []auditSeed {
	rows := []auditSeed{
		{"张启明", "admin", "auth.login", "admin", "10.20.9.11", "登录成功", now.Add(-71 * time.Hour)},
		{"李维", "operator", "scan.trigger", "分组：生产 Web", "10.20.9.31", "触发全量扫描，覆盖 4 台资产", now.Add(-69 * time.Hour)},
		{"李维", "operator", "finding.status", "CVE-2021-44228 @ web-01", "10.20.9.31", "open → fixing", now.Add(-66 * time.Hour)},
		{"李维", "operator", "finding.ticket", "CVE-2021-44228 @ web-01", "10.20.9.31", "创建工单 VA-2026-0120", now.Add(-66 * time.Hour)},
		{"陈可", "viewer", "auth.login", "viewer", "10.20.9.77", "登录成功", now.Add(-64 * time.Hour)},
		{"张启明", "admin", "sync.trigger", "epss", "10.20.9.11", "手动触发 EPSS 同步", now.Add(-62 * time.Hour)},
		{"系统", "system", "sync.finish", "cve", "127.0.0.1", "增量同步完成，新增 1832 条", now.Add(-60 * time.Hour)},
		{"李维", "operator", "finding.status", "CVE-2021-3156 @ k8s-node-01", "10.20.9.31", "triaged → fixing", now.Add(-58 * time.Hour)},
		{"李维", "operator", "findings.rescan", "CVE-2022-22965 @ api-01", "10.20.9.31", "触发单资产复扫 scan-20261020-1010", now.Add(-56 * time.Hour)},
		{"张启明", "admin", "policy.update", "risk-policy", "10.20.9.11", "调整 exploit 权重 0.20 → 0.25", now.Add(-54 * time.Hour)},
		{"王倩", "operator", "finding.status", "CVE-2024-3094 @ build-01", "10.20.9.42", "open → triaged", now.Add(-52 * time.Hour)},
		{"王倩", "operator", "finding.ticket", "CVE-2024-3094 @ build-01", "10.20.9.42", "创建工单 VA-2026-0127", now.Add(-52 * time.Hour)},
		{"陈可", "viewer", "export.report", "findings", "10.20.9.77", "导出 CSV 报告（被拒绝，角色不足）", now.Add(-49 * time.Hour)},
		{"李维", "operator", "export.report", "findings", "10.20.9.31", "导出 CSV 报告，共 59 条", now.Add(-47 * time.Hour)},
		{"系统", "system", "selfcheck.run", "sc-20261020-101500", "127.0.0.1", "定时自检：warn（2 项告警）", now.Add(-45 * time.Hour)},
		{"李维", "operator", "finding.status", "CVE-2023-38545 @ cache-01", "10.20.9.31", "open → fixed", now.Add(-40 * time.Hour)},
		{"李维", "operator", "finding.status", "CVE-2023-4911 @ legacy-01", "10.20.9.31", "open → risk_accepted", now.Add(-38 * time.Hour)},
		{"张启明", "admin", "user.login_failed", "operator", "10.20.9.11", "口令错误 1 次", now.Add(-34 * time.Hour)},
		{"王倩", "operator", "scan.trigger", "资产：jenkins-01", "10.20.9.42", "触发单资产扫描", now.Add(-30 * time.Hour)},
		{"系统", "system", "sync.finish", "poc", "127.0.0.1", "POC 增量同步完成，新增 42 条", now.Add(-26 * time.Hour)},
		{"李维", "operator", "finding.status", "CVE-2020-1938 @ legacy-01", "10.20.9.31", "triaged → fixing", now.Add(-22 * time.Hour)},
		{"张启明", "admin", "auth.login", "admin", "10.20.9.11", "登录成功", now.Add(-18 * time.Hour)},
		{"王倩", "operator", "finding.status", "CVE-2021-23337 @ web-02", "10.20.9.42", "open → verified", now.Add(-12 * time.Hour)},
		{"系统", "system", "sync.finish", "epss", "127.0.0.1", "离线包导入，滞后 1 天", now.Add(-7 * time.Hour)},
		{"李维", "operator", "finding.status", "CVE-2024-6387 @ api-01", "10.20.9.31", "open → fixing", now.Add(-5 * time.Hour)},
		{"陈可", "viewer", "auth.login", "viewer", "10.20.9.77", "登录成功", now.Add(-3 * time.Hour)},
		{"系统", "system", "selfcheck.run", "sc-20261022-071500", "127.0.0.1", "自检完成：warn（2 项告警）", now.Add(-2 * time.Hour)},
	}
	return rows
}

// loadPolicy 读取当前风险策略，实现见 sqlite.PolicyRepo
func loadPolicy(db *sql.DB) RiskPolicy {
	w, t, err := sqlite.NewPolicyRepo(db).RiskPolicy(context.Background())
	if err != nil {
		return defaultPolicy()
	}
	return unmarshalPolicy(w, t)
}
