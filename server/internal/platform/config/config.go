// Package config 集中解析与校验全部环境变量，是进程唯一的配置来源。
// 除本包外，其他包不应直接读取 os.Getenv。
package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultAddr 默认监听地址
	DefaultAddr = ":8787"
	// DefaultDataDir 默认数据目录（相对当前工作目录）
	DefaultDataDir = "./data"
	// DefaultDBFile 数据库文件名
	DefaultDBFile = "vulnagent.db"
	// DefaultSessionIdle 会话空闲失效时长
	DefaultSessionIdle = 30 * time.Minute
	// DefaultRescanInterval 定时复扫间隔
	DefaultRescanInterval = 30 * time.Minute
	// DefaultRescanDebounce 同一资产复扫的最小间隔
	DefaultRescanDebounce = 10 * time.Minute
	// DefaultIntelBaseURL 免费 CVE 情报站
	DefaultIntelBaseURL = "https://cve.imfht.com"
	// DefaultEPSSURL FIRST 每日全量 EPSS 评分（gzip CSV）
	DefaultEPSSURL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
)

// Config 进程运行配置
type Config struct {
	Addr           string
	DataDir        string
	DBPath         string
	WebDist        string
	SeedDemo       bool
	AdminPassword  string
	SessionIdle    time.Duration
	RescanInterval time.Duration
	RescanDebounce time.Duration
	IntelBaseURL   string
	EPSSURL        string
	CookieSecure   bool
}

// Load 读取环境变量并填充默认值。缺失项一律回落到默认值，不返回错误，
// 避免任何一项拼写错误导致服务无法启动。
func Load() Config {
	dataDir := strings.TrimSpace(os.Getenv("VA_DATA_DIR"))
	if dataDir == "" {
		dataDir = DefaultDataDir
	}
	return Config{
		Addr:           envOr("VA_ADDR", DefaultAddr),
		DataDir:        dataDir,
		DBPath:         filepath.Join(dataDir, DefaultDBFile),
		WebDist:        webDist(),
		SeedDemo:       seedDemo(),
		AdminPassword:  strings.TrimSpace(os.Getenv("VA_ADMIN_PASSWORD")),
		SessionIdle:    durationOr("VA_SESSION_IDLE", DefaultSessionIdle, time.Minute),
		RescanInterval: rescanInterval(),
		RescanDebounce: rescanDebounce(),
		IntelBaseURL:   envOr("VULNAGENT_CVE_BASE_URL", DefaultIntelBaseURL),
		EPSSURL:        envOr("VA_EPSS_URL", DefaultEPSSURL),
		CookieSecure:   truthy("VA_COOKIE_SECURE"),
	}
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func truthy(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "on", "true", "yes":
		return true
	}
	return false
}

// seedDemo 默认开启演示数据，显式关闭时返回 false
func seedDemo() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("VA_SEED_DEMO"))) {
	case "off", "0", "false", "no":
		return false
	}
	return true
}

func durationOr(key string, fallback, min time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	if d, err := time.ParseDuration(raw); err == nil && d >= min {
		return d
	}
	return fallback
}

// rescanInterval 定时复扫间隔，支持 "0"/"off" 关闭
func rescanInterval() time.Duration {
	raw := strings.TrimSpace(os.Getenv("VA_RESCAN_INTERVAL"))
	if raw == "" {
		return DefaultRescanInterval
	}
	if raw == "0" || strings.EqualFold(raw, "off") {
		return 0
	}
	if d, err := time.ParseDuration(raw); err == nil && d >= time.Minute {
		return d
	}
	slog.Warn("VA_RESCAN_INTERVAL 无效，使用默认 30m", "value", raw)
	return DefaultRescanInterval
}

// rescanDebounce 支持 "0"/"off" 关闭防抖，也兼容纯秒数
func rescanDebounce() time.Duration {
	raw := strings.TrimSpace(os.Getenv("VA_RESCAN_DEBOUNCE"))
	if raw == "" {
		return DefaultRescanDebounce
	}
	if raw == "0" || strings.EqualFold(raw, "off") {
		return 0
	}
	if d, err := time.ParseDuration(raw); err == nil && d >= 0 {
		return d
	}
	if secs, err := strconv.Atoi(raw); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	return DefaultRescanDebounce
}

// webDist 依次尝试环境变量与常见相对路径，返回第一个存在的目录；
// 都不存在时返回 ../web/dist，保持与旧行为一致（由静态资源挂载逻辑自行判断）。
func webDist() string {
	if v := strings.TrimSpace(os.Getenv("VA_WEB_DIST")); v != "" {
		if abs, err := filepath.Abs(v); err == nil {
			return abs
		}
		return v
	}
	candidates := []string{"../web/dist", "./web/dist", "web/dist"}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			if abs, err := filepath.Abs(c); err == nil {
				return abs
			}
		}
	}
	abs, err := filepath.Abs(candidates[0])
	if err != nil {
		return candidates[0]
	}
	return abs
}
