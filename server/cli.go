package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vulnagent/server/internal/collect"
	"vulnagent/server/internal/platform/config"
	"vulnagent/server/internal/sshscan"
)

// runCLI 子命令分发：server（默认）/ collect / agent
func runCLI() {
	if len(os.Args) < 2 {
		runServer()
		return
	}
	switch os.Args[1] {
	case "server":
		runServer()
	case "collect":
		runCollectCommand(os.Args[2:])
	case "agent":
		runAgentCommand(os.Args[2:])
	case "sync":
		runSyncCommand(os.Args[2:])
	case "sshscan":
		runSSHScanCommand(os.Args[2:])
	case "osvscan":
		runOSVScanCommand(os.Args[2:])
	case "backup":
		runBackupCommand(os.Args[2:])
	case "keygen":
		runUpdateKeygen(os.Args[2:])
	case "sign":
		runUpdateSign(os.Args[2:])
	case "self-update":
		runSelfUpdateCommand(os.Args[2:])
	case "helper":
		runHelperCommand()
	case "-h", "--help", "help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "未知子命令：%s\n\n", os.Args[1])
		printUsage()
		os.Exit(2)
	}
}

func printUsage() {
	fmt.Fprint(os.Stderr, `VulnAgent · 安全漏洞运维 Agent

用法:
  vulnagent server                     启动控制面（默认 :8787）
  vulnagent collect [--out sbom.json]  仅采集本机 SBOM，不联网
  vulnagent agent --server <url>       采集并上报到控制面
  vulnagent agent --server <url> --watch  常驻拉取并执行主机作业
  vulnagent helper                     提权 helper（由 Agent 通过 sudo/服务调用）
  vulnagent sync --bundle <file>       导入离线情报包
  vulnagent sync --epss-file <csv>     导入 EPSS 评分并重算排序
  vulnagent sync --epss                从 FIRST 在线拉取 EPSS（需外网）
  vulnagent sync --source cve|poc      在线增量同步（公开接口，可选配置 Key）
  vulnagent sshscan --host <ip>        无 Agent 兜底采集（只读脚本）
  vulnagent osvscan [--asset id|--all] 对语言生态组件做 OSV 在线版本匹配
  vulnagent backup --out <file>        备份数据库（SQLite VACUUM INTO）
  vulnagent keygen [--out dir]         生成自更新签名密钥对
  vulnagent sign --binary <file> --url <url>   生成签名清单
  vulnagent self-update --manifest <file|url>  校验签名与哈希后自更新

Agent 令牌来源优先级：--token > --token-file > VA_AGENT_TOKEN > <数据目录>/agent.token
`)
}

func runCollectCommand(args []string) {
	fs := flag.NewFlagSet("collect", flag.ExitOnError)
	out := fs.String("out", "", "输出 JSON 文件路径（留空打印到标准输出）")
	withSelf := fs.Bool("self", true, "附带自身依赖 SBOM")
	_ = fs.Parse(args)

	report, err := collect.Collect(collect.Options{IncludeSelf: *withSelf})
	if err != nil {
		fmt.Fprintf(os.Stderr, "采集失败：%v\n", err)
		os.Exit(1)
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "序列化失败：%v\n", err)
		os.Exit(1)
	}
	if *out == "" {
		fmt.Println(string(data))
	} else if err := os.WriteFile(*out, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "写入文件失败：%v\n", err)
		os.Exit(1)
	} else {
		fmt.Fprintf(os.Stderr, "已写入 %s\n", *out)
	}
	fmt.Fprintf(os.Stderr, "采集完成：%s / %s %s · %d 个组件 · 自身依赖 %d 个\n",
		report.Hostname, report.OS, report.OSVersion, len(report.Components), len(report.SelfSBOM))
	for _, warning := range report.Warnings {
		fmt.Fprintf(os.Stderr, "警告：%s\n", warning)
	}
}

func runAgentCommand(args []string) {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	server := fs.String("server", "http://127.0.0.1:8787", "控制面地址")
	token := fs.String("token", "", "Agent 令牌（不建议写在命令行历史里）")
	tokenFile := fs.String("token-file", "", "Agent 令牌文件路径")
	withSelf := fs.Bool("self", true, "附带自身依赖 SBOM")
	onlyPrint := fs.Bool("print", false, "只打印采集结果，不上报")
	timeout := fs.Duration("timeout", 60*time.Second, "上报超时时间")
	watch := fs.Bool("watch", false, "常驻运行并拉取主机作业")
	interval := fs.Duration("interval", 15*time.Second, "作业轮询间隔（--watch 模式）")
	_ = fs.Parse(args)

	if *watch && !*onlyPrint {
		accessToken, err := resolveAgentToken(*token, *tokenFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "读取 Agent 令牌失败：%v\n", err)
			os.Exit(1)
		}
		if err := runAgentWatch(*server, accessToken, *interval, *timeout); err != nil {
			fmt.Fprintf(os.Stderr, "Agent 常驻运行失败：%v\n", err)
			os.Exit(1)
		}
		return
	}

	report, err := collect.Collect(collect.Options{IncludeSelf: *withSelf})
	if err != nil {
		fmt.Fprintf(os.Stderr, "采集失败：%v\n", err)
		os.Exit(1)
	}

	if *onlyPrint {
		data, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(data))
		return
	}

	accessToken, err := resolveAgentToken(*token, *tokenFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取 Agent 令牌失败：%v\n", err)
		os.Exit(1)
	}

	body, err := json.Marshal(report)
	if err != nil {
		fmt.Fprintf(os.Stderr, "序列化失败：%v\n", err)
		os.Exit(1)
	}
	endpoint := strings.TrimRight(*server, "/") + "/api/v1/agent/report"
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "构造请求失败：%v\n", err)
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: *timeout}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "上报失败：%v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	fmt.Fprintf(os.Stderr, "已上报 %s：%d 个组件（HTTP %d）\n", report.Hostname, len(report.Components), resp.StatusCode)
	fmt.Println(string(respBody))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		os.Exit(1)
	}
}

// runSyncCommand 导入离线情报包或在线增量同步
func runSyncCommand(args []string) {
	fs := flag.NewFlagSet("sync", flag.ExitOnError)
	bundle := fs.String("bundle", "", "离线情报包路径（JSON）")
	epssFile := fs.String("epss-file", "", "EPSS CSV 文件（cve,epss,percentile）")
	epssRemote := fs.Bool("epss", false, "从 FIRST 在线拉取 EPSS 并重算")
	source := fs.String("source", "cve", "在线同步的情报源：cve|poc")
	maxPages := fs.Int("max-pages", 20, "在线同步最大页数")
	_ = fs.Parse(args)

	dataDir := dataDirFromEnv()
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "创建数据目录失败：%v\n", err)
		os.Exit(1)
	}
	db, err := openDB(config.Load().DBPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "打开数据库失败：%v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	var payload any
	switch {
	case *epssFile != "":
		f, err := os.Open(*epssFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "打开 EPSS 文件失败：%v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		app := &App{db: db}
		res, err := app.importEPSS(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "EPSS 导入失败：%v\n", err)
			os.Exit(1)
		}
		payload = res
	case *bundle != "":
		res, err := importBundle(db, *bundle)
		if err != nil {
			fmt.Fprintf(os.Stderr, "同步失败：%v\n", err)
			os.Exit(1)
		}
		payload = res
	default:
		apiKey := strings.TrimSpace(os.Getenv("VULNAGENT_CVE_API_KEY"))
		if *epssRemote {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			app := &App{db: db}
			res, err := app.syncEPSSFromRemote(ctx)
			if err != nil {
				fmt.Fprintf(os.Stderr, "EPSS 在线刷新失败：%v\n", err)
				os.Exit(1)
			}
			payload = res
			break
		}
		client := newCVEClient(intelBaseURLFromEnv(), apiKey)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		var res syncResult
		switch *source {
		case "cve":
			res, err = syncCVEFromAPI(ctx, db, client, *maxPages)
		case "poc":
			res, err = syncPOCFromAPI(ctx, db, client, *maxPages)
		default:
			err = fmt.Errorf("未知情报源：%s", *source)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "同步失败：%v\n", err)
			os.Exit(1)
		}
		payload = res
	}
	out, _ := json.MarshalIndent(payload, "", "  ")
	fmt.Println(string(out))
}

// runSSHScanCommand 无 Agent 兜底采集，仅输出 JSON，不写入数据库
func runSSHScanCommand(args []string) {
	fs := flag.NewFlagSet("sshscan", flag.ExitOnError)
	host := fs.String("host", "", "目标主机 IP 或域名")
	port := fs.Int("port", 22, "SSH 端口")
	user := fs.String("user", "root", "SSH 用户名")
	password := fs.String("password", "", "SSH 口令（也可用环境变量 VA_SSH_PASSWORD）")
	keyFile := fs.String("key-file", "", "私钥文件路径")
	passphrase := fs.String("passphrase", "", "私钥口令")
	fingerprint := fs.String("fingerprint", "", "期望的主机指纹（SHA256:...）")
	outPath := fs.String("out", "", "输出 JSON 文件路径")
	timeout := fs.Duration("timeout", 25*time.Second, "连接与执行超时")
	_ = fs.Parse(args)

	if *host == "" {
		fmt.Fprintln(os.Stderr, "必须提供 --host")
		os.Exit(2)
	}
	pwd := *password
	if pwd == "" {
		pwd = os.Getenv("VA_SSH_PASSWORD")
	}
	keyPEM := ""
	if *keyFile != "" {
		data, err := os.ReadFile(*keyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "读取私钥失败：%v\n", err)
			os.Exit(1)
		}
		keyPEM = string(data)
	}
	if pwd == "" && keyPEM == "" {
		fmt.Fprintln(os.Stderr, "需要 --password（或 VA_SSH_PASSWORD）或 --key-file")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout+10*time.Second)
	defer cancel()
	res, err := sshscan.Scan(ctx, sshscan.Config{
		Host:               *host,
		Port:               *port,
		User:               *user,
		Password:           pwd,
		PrivateKeyPEM:      keyPEM,
		Passphrase:         *passphrase,
		HostKeyFingerprint: *fingerprint,
		Timeout:            *timeout,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "SSH 采集失败：%v\n", err)
		os.Exit(1)
	}

	payload := map[string]any{
		"host":               *host,
		"os":                 res.OS,
		"osVersion":          res.OSVersion,
		"hostKeyFingerprint": res.HostKeyFingerprint,
		"elapsedMs":          res.Elapsed.Milliseconds(),
		"components":         res.Components,
	}
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "序列化失败：%v\n", err)
		os.Exit(1)
	}
	if *outPath == "" {
		fmt.Println(string(raw))
	} else if err := os.WriteFile(*outPath, raw, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "写入失败：%v\n", err)
		os.Exit(1)
	} else {
		fmt.Fprintf(os.Stderr, "已写入 %s\n", *outPath)
	}
	fmt.Fprintf(os.Stderr, "SSH 采集完成：%d 个组件 · %s %s · 耗时 %s\n",
		len(res.Components), res.OS, res.OSVersion, res.Elapsed.Round(time.Millisecond))
	fmt.Fprintf(os.Stderr, "主机指纹：%s\n", res.HostKeyFingerprint)
}

// runOSVScanCommand 对语言生态组件做 OSV 在线匹配
func runOSVScanCommand(args []string) {
	fs := flag.NewFlagSet("osvscan", flag.ExitOnError)
	assetID := fs.Int64("asset", 0, "只扫描指定资产 ID")
	all := fs.Bool("all", false, "扫描全部资产（默认）")
	_ = fs.Parse(args)

	db, err := openDB(config.Load().DBPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "打开数据库失败：%v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	app := &App{db: db}
	if !*all && *assetID == 0 {
		*all = true
	}
	ids := []int64{}
	if *assetID > 0 {
		ids = append(ids, *assetID)
	}
	res, err := app.osvScanAssets(ids, *all)
	if err != nil {
		fmt.Fprintf(os.Stderr, "OSV 匹配失败：%v\n", err)
		os.Exit(1)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(out))
}

// runBackupCommand 使用 SQLite VACUUM INTO 生成一致性备份
func runBackupCommand(args []string) {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	out := fs.String("out", "", "备份文件路径（.db）")
	_ = fs.Parse(args)
	if strings.TrimSpace(*out) == "" {
		fmt.Fprintln(os.Stderr, "请使用 --out 指定备份文件路径")
		os.Exit(2)
	}
	dataDir := dataDirFromEnv()
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "创建数据目录失败：%v\n", err)
		os.Exit(1)
	}
	db, err := openDB(config.Load().DBPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "打开数据库失败：%v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	target, err := filepath.Abs(*out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "解析备份路径失败：%v\n", err)
		os.Exit(1)
	}
	_ = os.Remove(target)
	if _, err := db.Exec(`VACUUM INTO ?`, target); err != nil {
		fmt.Fprintf(os.Stderr, "备份失败：%v\n", err)
		os.Exit(1)
	}
	info, err := os.Stat(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "备份文件校验失败：%v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "备份完成：%s（%.1f MB）\n", target, float64(info.Size())/(1<<20))
}

func resolveAgentToken(explicit, file string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if env := strings.TrimSpace(os.Getenv("VA_AGENT_TOKEN")); env != "" {
		return env, nil
	}
	if file == "" {
		dataDir := dataDirFromEnv()
		candidates := []string{
			filepath.Join(dataDir, agentTokenFileName),
			filepath.Join("..", "data", agentTokenFileName),
			filepath.Join("data", agentTokenFileName),
		}
		for _, candidate := range candidates {
			if _, err := os.Stat(candidate); err == nil {
				file = candidate
				break
			}
		}
	}
	if file == "" {
		return "", fmt.Errorf("未找到令牌，请使用 --token 或 --token-file 指定")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("令牌文件为空：%s", file)
	}
	return token, nil
}
