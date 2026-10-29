package main

import (
	"context"
	"crypto/cipher"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"vulnagent/server/internal/application/harness"
	"vulnagent/server/internal/platform/config"
)

// 版本元数据：发布时可经 -ldflags "-X main.appVersion=… -X main.buildCommit=… -X main.buildTime=…" 注入；
// 未注入时回落到 Go 构建信息中的 VCS 记录，避免展示写死的假时间。
var (
	appVersion  = "0.1.0-dev"
	buildCommit = ""
	buildTime   = ""
)

func init() {
	commit, builtAt := buildCommit, buildTime
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				if commit == "" {
					commit = setting.Value
				}
			case "vcs.time":
				if builtAt == "" {
					builtAt = setting.Value
				}
			}
		}
	}
	if commit == "" {
		commit = "local"
	}
	if builtAt == "" {
		builtAt = "未知"
	}
	buildCommit, buildTime = commit, builtAt
}

// App 控制面服务上下文
type App struct {
	db         *sql.DB
	sessions   *sessionStore
	dataDir    string
	webDist    string
	selfDigest string

	scanMu       sync.Mutex
	lastScan     map[int64]time.Time
	scanDebounce time.Duration

	loginGuard *loginLimiter

	// Harness：只读连接 + 应用服务
	roOnce  sync.Once
	roDB    *sql.DB
	roErr   error
	harness *harnessapp.Service

	// jobKey 用于主机作业签名（与 Agent 令牌一致）
	jobKey []byte

	// skills 运维技能注册表（从 skill/*.zip 解压到 skills/）
	skills *SkillRegistry

	// SSH 终端面板：凭据加密密钥（首次使用时生成）
	sshOnce   sync.Once
	sshAEAD   cipher.AEAD
	sshKeyErr error

	// SSH Agent 自动执行：命令审批等待队列
	sshApprovalMu sync.Mutex
	sshApprovals  map[string]chan bool

	// SSH 会话协同：在线会话与分享链接
	liveMu sync.Mutex
	live   map[string]*sshLiveSession
}

func (a *App) routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/auth/login", a.handleLogin)
	mux.HandleFunc("POST /api/v1/auth/logout", a.handleLogout)
	mux.HandleFunc("GET /api/v1/me", a.handleMe)
	mux.HandleFunc("POST /api/v1/me/password", a.handlePasswordChange)
	mux.HandleFunc("GET /api/v1/healthz", a.handleHealthz)
	mux.HandleFunc("GET /api/v1/meta", a.handleMeta)

	// Agent Harness：会话、流式对话与人工审批
	mux.HandleFunc("GET /api/v1/agent/tools", a.handleHarnessTools)
	mux.HandleFunc("GET /api/v1/agent/skills", a.handleHarnessSkills)
	mux.HandleFunc("GET /api/v1/agent/sessions", a.handleHarnessSessions)
	mux.HandleFunc("POST /api/v1/agent/sessions", a.handleHarnessCreateSession)
	mux.HandleFunc("PATCH /api/v1/agent/sessions/{id}", a.handleHarnessUpdateSession)
	mux.HandleFunc("GET /api/v1/agent/sessions/{id}/messages", a.handleHarnessMessages)
	mux.HandleFunc("POST /api/v1/agent/sessions/{id}/messages", a.handleHarnessChat)
	mux.HandleFunc("POST /api/v1/agent/sessions/{id}/resume", a.handleHarnessResume)
	mux.HandleFunc("POST /api/v1/agent/approvals/{id}", a.handleHarnessDecision)

	mux.HandleFunc("GET /api/v1/users", a.handleUsersList)
	mux.HandleFunc("POST /api/v1/users", a.handleUserCreate)
	mux.HandleFunc("PATCH /api/v1/users/{username}", a.handleUserUpdate)
	mux.HandleFunc("POST /api/v1/users/{username}/reset-password", a.handleUserResetPassword)
	mux.HandleFunc("POST /api/v1/agent/token/rotate", a.handleAgentTokenRotate)

	// Agent 上报使用 Bearer 令牌，与人类用户的会话相互独立
	mux.HandleFunc("POST /api/v1/agent/report", a.handleAgentReport)

	mux.HandleFunc("GET /api/v1/overview", a.handleOverview)

	mux.HandleFunc("GET /api/v1/findings", a.handleFindings)
	mux.HandleFunc("GET /api/v1/findings/{id}", a.handleFindingDetail)
	mux.HandleFunc("PATCH /api/v1/findings/{id}", a.handleFindingPatch)
	mux.HandleFunc("POST /api/v1/findings/{id}/ticket", a.handleFindingTicket)
	mux.HandleFunc("POST /api/v1/findings/{id}/rescan", a.handleFindingRescan)
	mux.HandleFunc("GET /api/v1/tickets", a.handleTickets)

	// SSH 终端面板：主机凭据、会话桥接与智能助手
	mux.HandleFunc("GET /api/v1/ssh/hosts", a.handleSSHHosts)
	mux.HandleFunc("POST /api/v1/ssh/hosts", a.handleSSHHostCreate)
	mux.HandleFunc("PATCH /api/v1/ssh/hosts/{id}", a.handleSSHHostUpdate)
	mux.HandleFunc("DELETE /api/v1/ssh/hosts/{id}", a.handleSSHHostDelete)
	mux.HandleFunc("POST /api/v1/ssh/hosts/{id}/test", a.handleSSHHostTest)
	mux.HandleFunc("POST /api/v1/ssh/hosts/{id}/scan", a.handleSSHHostScan)
	mux.HandleFunc("GET /api/v1/ssh/sessions", a.handleSSHSessions)
	mux.HandleFunc("GET /api/v1/ssh/sessions/{id}/recording", a.handleSSHRecording)
	mux.HandleFunc("POST /api/v1/ssh/sessions/{id}/share", a.handleSSHShareCreate)
	mux.HandleFunc("GET /api/v1/ssh/sessions/{id}/shares", a.handleSSHShares)
	mux.HandleFunc("DELETE /api/v1/ssh/shares/{id}", a.handleSSHShareRevoke)
	mux.HandleFunc("GET /api/v1/ssh/shared/{token}/info", a.handleSSHShareInfo)
	mux.HandleFunc("GET /api/v1/ssh/shared/{token}", a.handleSharedTerminal)
	mux.HandleFunc("GET /api/v1/ssh/terminal", a.handleSSHTerminal)
	mux.HandleFunc("POST /api/v1/ssh/assistant", a.handleSSHAssistant)
	mux.HandleFunc("GET /api/v1/ssh/snippets", a.handleSSHSnippets)
	mux.HandleFunc("POST /api/v1/ssh/snippets", a.handleSSHSnippetCreate)
	mux.HandleFunc("PATCH /api/v1/ssh/snippets/{id}", a.handleSSHSnippetUpdate)
	mux.HandleFunc("DELETE /api/v1/ssh/snippets/{id}", a.handleSSHSnippetDelete)
	mux.HandleFunc("POST /api/v1/ssh/snippets/{id}/use", a.handleSSHSnippetUse)
	mux.HandleFunc("POST /api/v1/ssh/agent/run", a.handleSSHAgentRun)
	mux.HandleFunc("POST /api/v1/ssh/agent/approvals/{id}", a.handleSSHAgentApproval)
	mux.HandleFunc("GET /api/v1/ssh/agent/runs", a.handleSSHAgentRuns)
	mux.HandleFunc("GET /api/v1/ssh/agent/runs/{id}", a.handleSSHAgentRunDetail)
	mux.HandleFunc("GET /api/v1/ssh/files/list", a.handleSFTPList)
	mux.HandleFunc("GET /api/v1/ssh/files/download", a.handleSFTPDownload)
	mux.HandleFunc("POST /api/v1/ssh/files/upload", a.handleSFTPUpload)
	mux.HandleFunc("POST /api/v1/ssh/files/mkdir", a.handleSFTPMkdir)
	mux.HandleFunc("POST /api/v1/ssh/files/rename", a.handleSFTPRename)
	mux.HandleFunc("DELETE /api/v1/ssh/files", a.handleSFTPDelete)
	mux.HandleFunc("GET /api/v1/ssh/files/preview", a.handleSFTPPreview)
	mux.HandleFunc("POST /api/v1/ssh/files/save", a.handleSFTPSave)

	mux.HandleFunc("GET /api/v1/assets", a.handleAssets)
	mux.HandleFunc("GET /api/v1/assets/{id}", a.handleAssetDetail)
	mux.HandleFunc("GET /api/v1/assets/{id}/telemetry", a.handleAssetTelemetry)
	mux.HandleFunc("GET /api/v1/assets/{id}/jobs", a.handleAssetJobs)
	mux.HandleFunc("POST /api/v1/assets/ssh-scan", a.handleSSHScan)

	// Agent 下行作业：Agent 令牌鉴权
	mux.HandleFunc("GET /api/v1/agent/jobs", a.handleAgentJobs)
	mux.HandleFunc("POST /api/v1/agent/jobs/{id}/claim", a.handleAgentJobClaim)
	mux.HandleFunc("POST /api/v1/agent/jobs/{id}/result", a.handleAgentJobResult)

	mux.HandleFunc("GET /api/v1/product-map", a.handleProductMapList)
	mux.HandleFunc("PUT /api/v1/product-map", a.handleProductMapUpsert)
	mux.HandleFunc("DELETE /api/v1/product-map", a.handleProductMapDelete)

	mux.HandleFunc("POST /api/v1/scans", a.handleScanBatch)

	mux.HandleFunc("GET /api/v1/reports/findings.pdf", a.handleFindingReportPDF)
	mux.HandleFunc("GET /api/v1/reports/findings.csv", a.handleFindingsCSV)
	mux.HandleFunc("GET /api/v1/reports/findings.json", a.handleFindingsJSON)

	mux.HandleFunc("GET /api/v1/metrics", a.handleMetrics)
	mux.HandleFunc("GET /api/v1/trajectory", a.handleTrajectory)

	mux.HandleFunc("GET /api/v1/notify-settings", a.handleNotifyGet)
	mux.HandleFunc("PUT /api/v1/notify-settings", a.handleNotifyUpdate)
	mux.HandleFunc("POST /api/v1/notify-settings/test", a.handleNotifyTest)

	mux.HandleFunc("POST /api/v1/selfcheck/run", a.handleSelfcheckRun)
	mux.HandleFunc("GET /api/v1/selfcheck/latest", a.handleSelfcheckLatest)
	mux.HandleFunc("GET /api/v1/selfcheck/history", a.handleSelfcheckHistory)

	mux.HandleFunc("GET /api/v1/audit-logs", a.handleAuditLogs)
	mux.HandleFunc("GET /api/v1/settings", a.handleSettings)
	mux.HandleFunc("PATCH /api/v1/settings/risk-policy", a.handleRiskPolicy)
	mux.HandleFunc("GET /api/v1/settings/ops-policy", a.handleOpsPolicy)
	mux.HandleFunc("PUT /api/v1/settings/ops-policy", a.handleOpsPolicy)
	mux.HandleFunc("GET /api/v1/sync/status", a.handleSyncStatus)
	mux.HandleFunc("POST /api/v1/sync/epss", a.handleEPSSUpload)
	mux.HandleFunc("POST /api/v1/sync/epss/refresh", a.handleEPSSRefresh)
	mux.HandleFunc("POST /api/v1/sync/osv", a.handleOSVSync)
	mux.HandleFunc("POST /api/v1/sync/{source}", a.handleSyncTrigger)

	// 前端构建产物存在时提供静态资源与 SPA 兜底
	if st, err := os.Stat(a.webDist); err == nil && st.IsDir() {
		mux.Handle("GET /", spaHandler(a.webDist))
		slog.Info("已挂载前端静态资源", "dir", a.webDist)
	}
}

func addrFromEnv() string { return config.Load().Addr }

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
	runCLI()
}

func runServer() {
	cfg := config.Load()
	dataDir := cfg.DataDir
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		slog.Error("创建数据目录失败", "dir", dataDir, "err", err)
		os.Exit(1)
	}
	db, err := openDB(cfg.DBPath)
	if err != nil {
		slog.Error("打开数据库失败", "err", err)
		os.Exit(1)
	}
	defer db.Close()

	if err := ensureUsers(db); err != nil {
		slog.Error("初始化账号失败", "err", err)
		os.Exit(1)
	}
	agentToken, err := ensureAgentToken(db, dataDir)
	if err != nil {
		slog.Error("初始化 Agent 令牌失败", "err", err)
		os.Exit(1)
	}
	if err := ensureRiskPolicy(db); err != nil {
		slog.Error("初始化风险策略失败", "err", err)
		os.Exit(1)
	}
	if seedDemoEnabled() {
		if err := seedDemo(db); err != nil {
			slog.Error("灌入演示数据失败", "err", err)
			os.Exit(1)
		}
	} else {
		slog.Info("演示数据已关闭", "hint", "VA_SEED_DEMO=on 可开启演示数据")
	}

	webDist := cfg.WebDist
	app := &App{db: db, sessions: newSessionStore(), dataDir: dataDir, webDist: webDist,
		selfDigest: computeSelfSBOMDigest(), scanDebounce: scanDebounceFromEnv(),
		lastScan: make(map[int64]time.Time), loginGuard: newLoginLimiter(), jobKey: []byte(agentToken),
		sshApprovals: make(map[string]chan bool)}
	slog.Info("自身依赖 SBOM 摘要", "digest", app.selfDigest)
	// 上次进程退出时仍在运行的 SSH Agent 任务标记为中断，避免长期停留在 running
	if _, err := db.Exec(`UPDATE ssh_agent_runs SET status='failed', error='服务重启，运行中断', finished_at=? WHERE status='running'`,
		fmtT(nowT())); err != nil {
		slog.Warn("清理中断的 SSH Agent 运行失败", "err", err)
	}
	app.skills = loadSkills()
	slog.Info("运维技能已加载", "count", len(app.skills.List()), "dir", app.skills.root)
	app.initHarness(cfg)
	app.cleanupOldJobs()
	defer func() {
		if app.roDB != nil {
			_ = app.roDB.Close()
		}
	}()
	if inserted, err := ensureProductMap(db); err != nil {
		slog.Error("初始化产品映射失败", "err", err)
		os.Exit(1)
	} else if inserted > 0 {
		slog.Info("已写入内置产品映射", "count", inserted)
		if rematched, err := app.rematchAllAssets(); err == nil {
			slog.Info("产品映射已生效", "assets", rematched)
		}
	}
	normalizeSyncCounts(db)
	app.seedSelfcheckHistory()

	scanCtx, stopScans := context.WithCancel(context.Background())
	defer stopScans()
	app.startScanScheduler(scanCtx)
	app.startIntelSyncScheduler(scanCtx)

	mux := http.NewServeMux()
	app.routes(mux)

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           withLogging(withSecurity(app.withAuth(mux))),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("控制面已启动", "addr", srv.Addr, "data", dataDir, "version", appVersion)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errCh:
		slog.Error("服务异常退出", "err", err)
		os.Exit(1)
	case sig := <-stop:
		slog.Info("收到退出信号，开始优雅关闭", "signal", sig.String())
	}
	stopScans()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Warn("优雅关闭超时", "err", err)
	}
	slog.Info("服务已停止")
}

// statusRecorder 记录响应状态码用于请求日志
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Unwrap 让 WebSocket 等需要 http.Hijacker 的处理器能穿透日志包装
func (s *statusRecorder) Unwrap() http.ResponseWriter {
	return s.ResponseWriter
}

// Flush 透传 http.Flusher，保证 SSE（助手对话、SSH Agent）逐条实时下发
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Agent 作业轮询与健康检查频率高，跳过访问日志避免刷屏
		if r.Method == http.MethodGet &&
			(strings.HasPrefix(r.URL.Path, "/api/v1/agent/jobs") || r.URL.Path == "/api/v1/healthz") {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		slog.Info("http request",
			"method", r.Method,
			"path", r.URL.RequestURI(),
			"status", rec.status,
			"durationMs", time.Since(start).Milliseconds(),
		)
	})
}

// spaHandler 静态文件优先，未命中时回退到 index.html。
// index.html 不缓存，避免发布后浏览器继续执行旧构建；带哈希的 /assets/ 长期缓存。
func spaHandler(root string) http.Handler {
	fileServer := http.FileServer(http.Dir(root))
	serveIndex := func(w http.ResponseWriter, r *http.Request) bool {
		index := filepath.Join(root, "index.html")
		data, err := os.ReadFile(index)
		if err != nil {
			http.NotFound(w, r)
			return false
		}
		w.Header().Set("Cache-Control", "no-store, must-revalidate")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(data)
		return true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := path.Clean("/" + r.URL.Path)
		if clean == "/" || clean == "/index.html" {
			serveIndex(w, r)
			return
		}
		target := filepath.Join(root, filepath.FromSlash(clean))
		if st, err := os.Stat(target); err == nil && !st.IsDir() {
			if strings.HasPrefix(clean, "/assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			} else {
				w.Header().Set("Cache-Control", "public, max-age=3600")
			}
			fileServer.ServeHTTP(w, r)
			return
		}
		serveIndex(w, r)
	})
}
