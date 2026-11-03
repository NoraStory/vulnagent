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
	"vulnagent/server/internal/application/ports"
	"vulnagent/server/internal/platform/config"
)

// 版本元数据：发布时可经 -ldflags "-X main.appVersion=… -X main.buildCommit=… -X main.buildTime=…" 注入；
// 未注入时回落到 Go 构建信息中的 VCS 记录，避免展示写死的假时间。
var (
	appVersion  = "0.7.9-dev"
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
	// gpuLLM GPU 推理端点（OpenAI 兼容），未配置时为 nil
	gpuLLM ports.LLM

	// jobKey 用于主机作业签名（与 Agent 令牌一致）
	jobKey []byte

	// skills 运维技能注册表（从 skill/*.zip 解压到 skills/）
	skills *SkillRegistry

	// SSH 终端面板：凭据加密密钥（首次使用时生成）
	sshOnce   sync.Once
	sshAEAD   cipher.AEAD
	sshKeyErr error

	// SSH 只读连接复用池（性能监控、服务加速、GPU 探测共用）
	sshPoolMu sync.Mutex
	sshPool   map[int64]*sshPoolEntry

	// SSH Agent 自动执行：命令审批等待队列与运行取消
	sshApprovalMu   sync.Mutex
	sshApprovals    map[string]chan bool
	sshApprovalMeta map[string]sshApprovalInfo
	sshRunMu        sync.Mutex
	sshRunCancels   map[string]context.CancelFunc

	// 服务加速：最近的加速能力探测结果（用于调度节点列表）
	accelMu       sync.Mutex
	accelProfiles map[int64]sshHostAccelProfile

	// 服务加速：轻量实时 GPU 指标缓存（3 秒）
	accelLiveMu sync.Mutex
	accelLive   map[int64]sshAccelLive

	// SSH 会话协同：在线会话与分享链接
	liveMu sync.Mutex
	live   map[string]*sshLiveSession

	// 网段发现：运行中任务的取消句柄
	discoveryMu     sync.Mutex
	discoveryCancel map[int64]context.CancelFunc

	// 云厂商 / 外部 CMDB 集成：避免同一源并发同步
	integrationMu      sync.Mutex
	integrationSyncing map[int64]bool

	// 集群异步检查/扫描：运行中任务的取消句柄
	clusterJobMu      sync.Mutex
	clusterJobCancels map[string]context.CancelFunc

	// demo 模式由启动时的数据初始化决定，进程内缓存避免每次响应都查库
	demoOnce sync.Once
	demoFlag bool

	// 全量情报索引快照，避免每次资产匹配重复加载
	intelCacheOnce sync.Once
	intelCache     *intelSnapshotCache
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

	// 多 Agent 身份：一次性注册、心跳在线与双向命令通道
	mux.HandleFunc("POST /api/v1/agents/enroll", a.handleAgentEnroll)
	mux.HandleFunc("POST /api/v1/agents/heartbeat", a.handleAgentHeartbeat)
	mux.HandleFunc("GET /api/v1/agents/commands", a.handleAgentCommandPoll)
	mux.HandleFunc("POST /api/v1/agents/commands/{id}/result", a.handleAgentCommandResult)
	mux.HandleFunc("GET /api/v1/agents", a.handleAgents)
	mux.HandleFunc("GET /api/v1/agents/enroll-tokens", a.handleAgentEnrollTokens)
	mux.HandleFunc("POST /api/v1/agents/enroll-tokens", a.handleAgentEnrollTokenCreate)
	mux.HandleFunc("DELETE /api/v1/agents/enroll-tokens/{id}", a.handleAgentEnrollTokenDelete)
	mux.HandleFunc("POST /api/v1/agents/{id}/revoke", a.handleAgentRevoke)
	mux.HandleFunc("GET /api/v1/agents/{id}/commands", a.handleAgentCommands)
	mux.HandleFunc("POST /api/v1/agents/{id}/commands", a.handleAgentCommandCreate)

	mux.HandleFunc("GET /api/v1/overview", a.handleOverview)

	// 项目与集群：分布式后端/数据库/扫描目标的统一运维视图
	mux.HandleFunc("GET /api/v1/projects", a.handleProjects)
	mux.HandleFunc("POST /api/v1/projects", a.handleProjectCreate)
	mux.HandleFunc("PATCH /api/v1/projects/{id}", a.handleProjectUpdate)
	mux.HandleFunc("DELETE /api/v1/projects/{id}", a.handleProjectDelete)
	mux.HandleFunc("GET /api/v1/clusters", a.handleClusters)
	mux.HandleFunc("POST /api/v1/clusters", a.handleClusterCreate)
	mux.HandleFunc("GET /api/v1/clusters/{id}", a.handleClusterDetail)
	mux.HandleFunc("PATCH /api/v1/clusters/{id}", a.handleClusterUpdate)
	mux.HandleFunc("DELETE /api/v1/clusters/{id}", a.handleClusterDelete)
	mux.HandleFunc("POST /api/v1/clusters/{id}/nodes", a.handleClusterNodeCreate)
	mux.HandleFunc("POST /api/v1/clusters/{id}/check", a.handleClusterCheck)
	mux.HandleFunc("POST /api/v1/clusters/{id}/scan", a.handleClusterScan)
	mux.HandleFunc("POST /api/v1/clusters/{id}/jobs", a.handleClusterJobCreate)
	mux.HandleFunc("GET /api/v1/clusters/{id}/jobs", a.handleClusterJobs)
	mux.HandleFunc("GET /api/v1/cluster-jobs/{id}", a.handleClusterJobDetail)
	mux.HandleFunc("POST /api/v1/cluster-jobs/{id}/cancel", a.handleClusterJobCancel)
	mux.HandleFunc("POST /api/v1/clusters/{id}/assets", a.handleClusterAssetsLink)
	mux.HandleFunc("DELETE /api/v1/clusters/{id}/assets/{assetId}", a.handleClusterAssetUnlink)
	mux.HandleFunc("GET /api/v1/clusters/{id}/reliability", a.handleClusterReliability)
	mux.HandleFunc("GET /api/v1/clusters/{id}/checks", a.handleClusterNodeChecks)
	mux.HandleFunc("PATCH /api/v1/cluster-nodes/{id}", a.handleClusterNodeUpdate)
	mux.HandleFunc("DELETE /api/v1/cluster-nodes/{id}", a.handleClusterNodeDelete)
	mux.HandleFunc("POST /api/v1/cluster-nodes/{id}/check", a.handleClusterNodeCheck)
	mux.HandleFunc("POST /api/v1/cluster-nodes/{id}/scan", a.handleClusterNodeScan)

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
	mux.HandleFunc("GET /api/v1/ssh/hosts/{id}/metrics", a.handleSSHHostMetrics)
	mux.HandleFunc("GET /api/v1/ssh/hosts/{id}/gpu", a.handleSSHHostGPU)
	mux.HandleFunc("POST /api/v1/ssh/hosts/{id}/gpu/benchmark", a.handleSSHHostGPUBenchmark)
	mux.HandleFunc("GET /api/v1/ssh/hosts/{id}/accel", a.handleSSHHostAccel)
	mux.HandleFunc("GET /api/v1/ssh/hosts/{id}/accel/live", a.handleSSHHostAccelLive)
	mux.HandleFunc("POST /api/v1/ssh/hosts/{id}/accel/baseline", a.handleSSHHostAccelBaseline)
	mux.HandleFunc("POST /api/v1/ssh/hosts/{id}/accel/compare", a.handleSSHHostAccelCompare)
	mux.HandleFunc("GET /api/v1/accel/hosts", a.handleAccelHosts)
	mux.HandleFunc("POST /api/v1/ssh/hosts/{id}/hashcat/benchmark", a.handleSSHHostHashcatBenchmark)
	mux.HandleFunc("POST /api/v1/ssh/hosts/{id}/hashcat/audit", a.handleSSHHostHashcatAudit)
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
	mux.HandleFunc("POST /api/v1/ssh/agent/runs/{id}/cancel", a.handleSSHAgentRunCancel)
	mux.HandleFunc("GET /api/v1/ssh/files/list", a.handleSFTPList)
	mux.HandleFunc("GET /api/v1/ssh/files/download", a.handleSFTPDownload)
	mux.HandleFunc("POST /api/v1/ssh/files/upload", a.handleSFTPUpload)
	mux.HandleFunc("POST /api/v1/ssh/files/mkdir", a.handleSFTPMkdir)
	mux.HandleFunc("POST /api/v1/ssh/files/rename", a.handleSFTPRename)
	mux.HandleFunc("DELETE /api/v1/ssh/files", a.handleSFTPDelete)
	mux.HandleFunc("GET /api/v1/ssh/files/preview", a.handleSFTPPreview)
	mux.HandleFunc("POST /api/v1/ssh/files/save", a.handleSFTPSave)

	mux.HandleFunc("GET /api/v1/assets", a.handleAssets)
	mux.HandleFunc("GET /api/v1/assets/export", a.handleAssetExport)
	mux.HandleFunc("POST /api/v1/assets/import", a.handleAssetImport)
	mux.HandleFunc("POST /api/v1/assets/merge", a.handleAssetMerge)
	mux.HandleFunc("GET /api/v1/assets/{id}", a.handleAssetDetail)
	mux.HandleFunc("PATCH /api/v1/assets/{id}", a.handleAssetPatch)
	mux.HandleFunc("GET /api/v1/assets/{id}/changes", a.handleAssetChanges)
	mux.HandleFunc("GET /api/v1/assets/{id}/relations", a.handleAssetRelations)
	mux.HandleFunc("POST /api/v1/assets/{id}/relations", a.handleAssetRelationCreate)
	mux.HandleFunc("DELETE /api/v1/assets/relations/{id}", a.handleAssetRelationDelete)
	mux.HandleFunc("POST /api/v1/assets/batch", a.handleAssetBatch)
	mux.HandleFunc("PUT /api/v1/assets/{id}/tags", a.handleAssetTags)
	mux.HandleFunc("GET /api/v1/assets/{id}/telemetry", a.handleAssetTelemetry)
	mux.HandleFunc("GET /api/v1/assets/{id}/jobs", a.handleAssetJobs)
	mux.HandleFunc("GET /api/v1/assets/{id}/ssh-host", a.handleAssetSSHHost)
	mux.HandleFunc("POST /api/v1/assets/{id}/ssh-host", a.handleAssetSSHHostLink)
	mux.HandleFunc("POST /api/v1/assets/ssh-scan", a.handleSSHScan)

	// 业务系统重要性、拓扑与治理待办
	mux.HandleFunc("GET /api/v1/business-systems", a.handleBusinessSystems)
	mux.HandleFunc("PUT /api/v1/business-systems/{name}", a.handleBusinessSystemUpsert)
	mux.HandleFunc("DELETE /api/v1/business-systems/{name}", a.handleBusinessSystemDelete)
	mux.HandleFunc("GET /api/v1/topology", a.handleTopology)
	mux.HandleFunc("GET /api/v1/governance/summary", a.handleGovernanceSummary)
	mux.HandleFunc("GET /api/v1/governance/todos", a.handleGovernanceTodos)

	// 云厂商与外部 CMDB 只读同步
	mux.HandleFunc("GET /api/v1/integrations", a.handleIntegrations)
	mux.HandleFunc("POST /api/v1/integrations", a.handleIntegrations)
	mux.HandleFunc("PUT /api/v1/integrations/{id}", a.handleIntegrationUpdate)
	mux.HandleFunc("DELETE /api/v1/integrations/{id}", a.handleIntegrationUpdate)
	mux.HandleFunc("POST /api/v1/integrations/{id}/test", a.handleIntegrationTest)
	mux.HandleFunc("POST /api/v1/integrations/{id}/sync", a.handleIntegrationSync)

	// 资产自动发现：任务、候选审核与授权网段策略
	mux.HandleFunc("GET /api/v1/discovery/jobs", a.handleDiscoveryJobs)
	mux.HandleFunc("POST /api/v1/discovery/jobs", a.handleDiscoveryJobs)
	mux.HandleFunc("GET /api/v1/discovery/jobs/{id}", a.handleDiscoveryJobDetail)
	mux.HandleFunc("POST /api/v1/discovery/jobs/{id}/cancel", a.handleDiscoveryJobCancel)
	mux.HandleFunc("GET /api/v1/discovery/candidates", a.handleDiscoveryCandidates)
	mux.HandleFunc("POST /api/v1/discovery/candidates/batch", a.handleDiscoveryCandidatesBatch)
	mux.HandleFunc("POST /api/v1/discovery/candidates/{id}/{action}", a.handleDiscoveryCandidateAction)
	mux.HandleFunc("GET /api/v1/settings/discovery", a.handleDiscoveryPolicy)
	mux.HandleFunc("PUT /api/v1/settings/discovery", a.handleDiscoveryPolicy)

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
	mux.HandleFunc("GET /api/v1/settings/runtime", a.handleRuntimeSettings)
	mux.HandleFunc("PUT /api/v1/settings/runtime", a.handleRuntimeSettingsUpdate)
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

	// 网页保存的运行配置优先于 .env；必须在初始化 Harness 与调度器之前注入环境变量。
	runtimeApp := &App{db: db, dataDir: dataDir}
	if err := runtimeApp.applyStoredRuntimeSettings(context.Background()); err != nil {
		slog.Warn("应用网页运行配置失败", "err", err)
	}
	cfg = config.Load()

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
		sshApprovals: make(map[string]chan bool), sshApprovalMeta: make(map[string]sshApprovalInfo),
		sshRunCancels: make(map[string]context.CancelFunc)}
	slog.Info("自身依赖 SBOM 摘要", "digest", app.selfDigest)
	// 上次进程退出时仍在运行的 SSH Agent 任务标记为中断，避免长期停留在 running
	if _, err := db.Exec(`UPDATE ssh_agent_runs SET status='failed', error='服务重启，运行中断', finished_at=? WHERE status='running'`,
		fmtT(nowT())); err != nil {
		slog.Warn("清理中断的 SSH Agent 运行失败", "err", err)
	}
	if n, err := app.discoveryRepo().InterruptUnfinishedJobs(context.Background()); err != nil {
		slog.Warn("清理中断的发现任务失败", "err", err)
	} else if n > 0 {
		slog.Info("已标记中断的发现任务", "count", n)
	}
	app.interruptClusterJobs()
	app.skills = loadSkills()
	slog.Info("运维技能已加载", "count", len(app.skills.List()), "dir", app.skills.root)
	app.initHarness(cfg)
	app.cleanupOldJobs()
	go app.integrationLoop(context.Background())
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
	app.startClusterCheckScheduler(scanCtx)

	mux := http.NewServeMux()
	app.routes(mux)

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           withLogging(withSecurity(withCompression(app.withAuth(mux)))),
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
			(strings.HasPrefix(r.URL.Path, "/api/v1/agent/jobs") ||
				r.URL.Path == "/api/v1/healthz" ||
				r.URL.Path == "/api/v1/agents/commands") {
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
		// API 命名空间不参与 SPA 回退：未匹配的接口应返回 JSON 404，
		// 否则前端会把 index.html 当 JSON 解析，报 "Unexpected token '<'"。
		if clean == "/api" || strings.HasPrefix(clean, "/api/") {
			writeErr(w, http.StatusNotFound, "not_found", "接口不存在")
			return
		}
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
