package main

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

const (
	appVersion  = "0.1.0-dev"
	buildCommit = "local"
	buildTime   = "2026-10-22T00:00:00+08:00"
	defaultAddr = ":8787"
)

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
}

func (a *App) routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/auth/login", a.handleLogin)
	mux.HandleFunc("POST /api/v1/auth/logout", a.handleLogout)
	mux.HandleFunc("GET /api/v1/me", a.handleMe)
	mux.HandleFunc("POST /api/v1/me/password", a.handlePasswordChange)
	mux.HandleFunc("GET /api/v1/healthz", a.handleHealthz)

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

	mux.HandleFunc("GET /api/v1/assets", a.handleAssets)
	mux.HandleFunc("GET /api/v1/assets/{id}", a.handleAssetDetail)
	mux.HandleFunc("POST /api/v1/assets/ssh-scan", a.handleSSHScan)

	mux.HandleFunc("GET /api/v1/product-map", a.handleProductMapList)
	mux.HandleFunc("PUT /api/v1/product-map", a.handleProductMapUpsert)
	mux.HandleFunc("DELETE /api/v1/product-map", a.handleProductMapDelete)

	mux.HandleFunc("POST /api/v1/scans", a.handleScanBatch)

	mux.HandleFunc("GET /api/v1/reports/findings.pdf", a.handleFindingReportPDF)
	mux.HandleFunc("GET /api/v1/reports/findings.csv", a.handleFindingsCSV)
	mux.HandleFunc("GET /api/v1/reports/findings.json", a.handleFindingsJSON)

	mux.HandleFunc("GET /api/v1/metrics", a.handleMetrics)

	mux.HandleFunc("GET /api/v1/notify-settings", a.handleNotifyGet)
	mux.HandleFunc("PUT /api/v1/notify-settings", a.handleNotifyUpdate)
	mux.HandleFunc("POST /api/v1/notify-settings/test", a.handleNotifyTest)

	mux.HandleFunc("POST /api/v1/selfcheck/run", a.handleSelfcheckRun)
	mux.HandleFunc("GET /api/v1/selfcheck/latest", a.handleSelfcheckLatest)
	mux.HandleFunc("GET /api/v1/selfcheck/history", a.handleSelfcheckHistory)

	mux.HandleFunc("GET /api/v1/audit-logs", a.handleAuditLogs)
	mux.HandleFunc("GET /api/v1/settings", a.handleSettings)
	mux.HandleFunc("PATCH /api/v1/settings/risk-policy", a.handleRiskPolicy)
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

func addrFromEnv() string {
	if v := os.Getenv("VA_ADDR"); v != "" {
		return v
	}
	return defaultAddr
}

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
	runCLI()
}

func runServer() {
	dataDir := dataDirFromEnv()
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		slog.Error("创建数据目录失败", "dir", dataDir, "err", err)
		os.Exit(1)
	}
	db, err := openDB(filepath.Join(dataDir, "vulnagent.db"))
	if err != nil {
		slog.Error("打开数据库失败", "err", err)
		os.Exit(1)
	}
	defer db.Close()

	if err := ensureUsers(db); err != nil {
		slog.Error("初始化账号失败", "err", err)
		os.Exit(1)
	}
	if _, err := ensureAgentToken(db, dataDir); err != nil {
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

	webDist, _ := filepath.Abs(filepath.Join("..", "web", "dist"))
	app := &App{db: db, sessions: newSessionStore(), dataDir: dataDir, webDist: webDist,
		selfDigest: computeSelfSBOMDigest(), scanDebounce: scanDebounceFromEnv(),
		lastScan: make(map[int64]time.Time), loginGuard: newLoginLimiter()}
	slog.Info("自身依赖 SBOM 摘要", "digest", app.selfDigest)
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

	mux := http.NewServeMux()
	app.routes(mux)

	srv := &http.Server{
		Addr:              addrFromEnv(),
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

func withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

// spaHandler 静态文件优先，未命中时回退到 index.html
func spaHandler(root string) http.Handler {
	fileServer := http.FileServer(http.Dir(root))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := filepath.Clean("/" + r.URL.Path)
		target := filepath.Join(root, clean)
		if st, err := os.Stat(target); err == nil && !st.IsDir() {
			fileServer.ServeHTTP(w, r)
			return
		}
		index := filepath.Join(root, "index.html")
		if _, err := os.Stat(index); err != nil {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, index)
	})
}
