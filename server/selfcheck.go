package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type selfcheckCheck struct {
	ID         string `json:"id"`
	Group      string `json:"group"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	Detail     string `json:"detail"`
	Hint       string `json:"hint"`
	DurationMs int64  `json:"durationMs"`
}

type selfcheckRun struct {
	Demo        bool             `json:"demo"`
	RunID       string           `json:"runId"`
	StartedAt   string           `json:"startedAt"`
	FinishedAt  string           `json:"finishedAt"`
	DurationMs  int64            `json:"durationMs"`
	Status      string           `json:"status"`
	TriggeredBy string           `json:"triggeredBy"`
	Passed      int              `json:"passed"`
	Warnings    int              `json:"warnings"`
	Failed      int              `json:"failed"`
	Checks      []selfcheckCheck `json:"checks"`
}

// runSelfcheck 对真实数据执行 16 项检查并落库
func (a *App) runSelfcheck(triggeredBy string) (selfcheckRun, error) {
	start := nowT()
	begin := time.Now()
	checks := make([]selfcheckCheck, 0, 16)

	add := func(id, group, name, status, detail, hint string, dur time.Duration) {
		checks = append(checks, selfcheckCheck{
			ID: id, Group: group, Name: name, Status: status,
			Detail: detail, Hint: hint, DurationMs: dur.Milliseconds(),
		})
	}

	// ---- 数据库 ----
	t0 := time.Now()
	var quick string
	errQuick := a.db.QueryRow(`PRAGMA quick_check`).Scan(&quick)
	var tables int
	errTables := a.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`).Scan(&tables)
	if errQuick != nil || errTables != nil || quick != "ok" {
		detail := fmt.Sprintf("quick_check 异常：%v", firstErr(errQuick, errTables))
		add("db.integrity", "数据库", "数据库完整性", "fail", detail, "备份数据目录后重建数据库或从快照恢复", time.Since(t0))
	} else {
		add("db.integrity", "数据库", "数据库完整性", "pass",
			fmt.Sprintf("quick_check 通过，%d 张表", tables), "", time.Since(t0))
	}

	t0 = time.Now()
	var assetN, compN, findingN, cveN int
	a.db.QueryRow(`SELECT COUNT(*) FROM assets`).Scan(&assetN)
	a.db.QueryRow(`SELECT COUNT(*) FROM components`).Scan(&compN)
	a.db.QueryRow(`SELECT COUNT(*) FROM findings`).Scan(&findingN)
	a.db.QueryRow(`SELECT COUNT(*) FROM cves`).Scan(&cveN)
	add("db.volume", "数据库", "数据量统计", "pass",
		fmt.Sprintf("assets=%d components=%d findings=%d cves=%d", assetN, compN, findingN, cveN),
		"", time.Since(t0))

	t0 = time.Now()
	var errW, errR error
	const latencyRounds = 20
	for i := 0; i < latencyRounds; i++ {
		ts := fmtT(nowT())
		if _, errW = a.db.Exec(`INSERT INTO latency_probe(ts) VALUES(?)`, ts); errW != nil {
			break
		}
		var probeBack string
		if errR = a.db.QueryRow(`SELECT ts FROM latency_probe ORDER BY id DESC LIMIT 1`).Scan(&probeBack); errR != nil {
			break
		}
	}
	elapsed := time.Since(t0) / latencyRounds
	latencyText := fmt.Sprintf("读写往返 %.1f µs", float64(elapsed.Nanoseconds())/1000)
	if elapsed >= time.Millisecond {
		latencyText = fmt.Sprintf("读写往返 %.2f ms", float64(elapsed.Nanoseconds())/1e6)
	}
	switch {
	case errW != nil || errR != nil:
		add("db.latency", "数据库", "数据库读写延迟", "fail",
			fmt.Sprintf("读写探测失败：%v", firstErr(errW, errR)), "检查数据目录权限与磁盘状态", elapsed)
	case elapsed > 200*time.Millisecond:
		add("db.latency", "数据库", "数据库读写延迟", "warn",
			latencyText+"，超过 200 ms",
			"检查磁盘 IO 与 SQLite WAL 是否正常", elapsed)
	default:
		add("db.latency", "数据库", "数据库读写延迟", "pass", latencyText, "", elapsed)
	}
	a.db.Exec(`DELETE FROM latency_probe WHERE id < (SELECT MAX(id) FROM latency_probe) - 50`)

	// ---- 情报同步 ----
	t0 = time.Now()
	warnAfter, failAfter := intelFreshnessThresholds()
	lagCVE, cveStatus, cveErr := syncCursorInfo(a.db, "cve")
	switch {
	case cveStatus == "fail":
		detail := fmt.Sprintf("最近一次 CVE 同步失败（%.1f 小时前）", lagCVE)
		if strings.TrimSpace(cveErr) != "" {
			detail += "：" + cveErr
		}
		add("intel.cve_lag", "情报同步", "CVE 情报新鲜度", "fail", detail,
			"检查情报源连通性与 API Key；离线环境请导入情报包", time.Since(t0))
	case lagCVE > failAfter:
		add("intel.cve_lag", "情报同步", "CVE 情报新鲜度", "fail",
			fmt.Sprintf("CVE 情报已滞后 %.1f 小时（阈值 %.0f 小时）", lagCVE, failAfter),
			"检查同步任务调度与情报源连通性，必要时导入离线包", time.Since(t0))
	case lagCVE > warnAfter:
		add("intel.cve_lag", "情报同步", "CVE 情报新鲜度", "warn",
			fmt.Sprintf("CVE 情报已滞后 %.1f 小时（阈值 %.0f 小时）", lagCVE, warnAfter),
			"确认增量同步任务是否正常执行", time.Since(t0))
	default:
		add("intel.cve_lag", "情报同步", "CVE 情报新鲜度", "pass",
			fmt.Sprintf("最后同步于 %.1f 小时前（阈值 %.0f 小时）", lagCVE, warnAfter), "", time.Since(t0))
	}

	t0 = time.Now()
	var epssTotal, epssCovered int
	a.db.QueryRow(`SELECT COUNT(*) FROM cves`).Scan(&epssTotal)
	a.db.QueryRow(`SELECT COUNT(*) FROM cves WHERE epss > 0`).Scan(&epssCovered)
	ratio := 1.0
	if epssTotal > 0 {
		ratio = float64(epssCovered) / float64(epssTotal)
	}
	if epssTotal == 0 {
		add("intel.epss_coverage", "情报同步", "EPSS 覆盖率", "fail", "CVE 库为空，无法计算覆盖率", "先导入 CVE 离线包", time.Since(t0))
	} else if ratio < 0.8 {
		add("intel.epss_coverage", "情报同步", "EPSS 覆盖率", "warn",
			fmt.Sprintf("EPSS 覆盖率 %.1f%%（%d/%d），低于 80%%", ratio*100, epssCovered, epssTotal),
			"导入最新 EPSS 每日数据包", time.Since(t0))
	} else {
		add("intel.epss_coverage", "情报同步", "EPSS 覆盖率", "pass",
			fmt.Sprintf("EPSS 覆盖率 %.1f%%（%d/%d）", ratio*100, epssCovered, epssTotal), "", time.Since(t0))
	}

	t0 = time.Now()
	var pocCount int
	a.db.QueryRow(`SELECT COUNT(*) FROM cve_poc`).Scan(&pocCount)
	lagPOC := syncLagHours(a.db, "poc")
	if pocCount == 0 {
		add("intel.poc_feed", "情报同步", "POC 情报更新", "fail", "POC 情报为空", "导入 POC 情报源", time.Since(t0))
	} else if lagPOC > 24 {
		add("intel.poc_feed", "情报同步", "POC 情报更新", "warn",
			fmt.Sprintf("POC 记录 %d 条，最后更新滞后 %.1f 小时", pocCount, lagPOC),
			"检查 POC 情报同步任务", time.Since(t0))
	} else {
		add("intel.poc_feed", "情报同步", "POC 情报更新", "pass",
			fmt.Sprintf("POC 记录 %d 条，最后更新滞后 %.1f 小时", pocCount, lagPOC), "", time.Since(t0))
	}

	// ---- 采集链路 ----
	t0 = time.Now()
	var agentTotal, agentOnline int
	a.db.QueryRow(`SELECT COUNT(*) FROM assets WHERE source = 'agent'`).Scan(&agentTotal)
	a.db.QueryRow(`SELECT COUNT(*) FROM assets WHERE source = 'agent' AND agent_status = 'online'`).Scan(&agentOnline)
	onlineRatio := 1.0
	if agentTotal > 0 {
		onlineRatio = float64(agentOnline) / float64(agentTotal)
	}
	switch {
	case agentTotal == 0:
		add("collect.agent_online", "采集链路", "Agent 在线率", "fail", "未发现任何 Agent 资产", "为资产安装并注册 Agent", time.Since(t0))
	case onlineRatio < 0.5:
		add("collect.agent_online", "采集链路", "Agent 在线率", "fail",
			fmt.Sprintf("%d/%d 在线（%.0f%%）", agentOnline, agentTotal, onlineRatio*100),
			"检查离线主机网络与 Agent 服务状态", time.Since(t0))
	case onlineRatio < 0.8:
		add("collect.agent_online", "采集链路", "Agent 在线率", "warn",
			fmt.Sprintf("%d/%d 在线（%.0f%%）", agentOnline, agentTotal, onlineRatio*100),
			"检查离线主机网络与 Agent 服务状态", time.Since(t0))
	default:
		add("collect.agent_online", "采集链路", "Agent 在线率", "pass",
			fmt.Sprintf("%d/%d 在线（%.0f%%）", agentOnline, agentTotal, onlineRatio*100), "", time.Since(t0))
	}

	t0 = time.Now()
	cutoff := fmtT(nowT().Add(-24 * time.Hour))
	var staleCount int
	a.db.QueryRow(`SELECT COUNT(*) FROM assets WHERE source != 'self' AND (last_seen_at = '' OR last_seen_at < ?)`, cutoff).Scan(&staleCount)
	if staleCount > 0 {
		add("collect.stale_agents", "采集链路", "失联资产", "warn",
			fmt.Sprintf("%d 台资产超过 24 小时未上报", staleCount),
			"确认主机存活状态，或清理已下线的资产台账", time.Since(t0))
	} else {
		add("collect.stale_agents", "采集链路", "失联资产", "pass", "所有资产均在 24 小时内上报", "", time.Since(t0))
	}

	t0 = time.Now()
	var lastReport string
	a.db.QueryRow(`SELECT COALESCE(MAX(last_seen_at), '') FROM assets WHERE source = 'agent'`).Scan(&lastReport)
	reportLag := hoursSince(lastReport)
	switch {
	case lastReport == "":
		add("collect.last_report", "采集链路", "最近上报时间", "fail", "没有可用的上报记录", "检查 Agent 采集与上报链路", time.Since(t0))
	case reportLag > 48:
		add("collect.last_report", "采集链路", "最近上报时间", "fail",
			fmt.Sprintf("最近一次上报在 %.1f 小时前", reportLag), "检查 Agent 采集与上报链路", time.Since(t0))
	case reportLag > 6:
		add("collect.last_report", "采集链路", "最近上报时间", "warn",
			fmt.Sprintf("最近一次上报在 %.1f 小时前", reportLag), "确认 Agent 定时任务是否正常", time.Since(t0))
	default:
		add("collect.last_report", "采集链路", "最近上报时间", "pass",
			fmt.Sprintf("最近一次上报在 %.1f 分钟前", reportLag*60), "", time.Since(t0))
	}

	// ---- 平台自身 ----
	t0 = time.Now()
	var selfHigh int
	a.db.QueryRow(`SELECT COUNT(*) FROM findings f JOIN assets a ON a.id = f.asset_id
		WHERE a.source = 'self' AND f.priority IN ('P0','P1')`).Scan(&selfHigh)
	if selfHigh > 0 {
		add("self.sbom_findings", "平台自身", "自身 SBOM 高危漏洞", "fail",
			fmt.Sprintf("控制面自身存在 %d 个 P0/P1 漏洞", selfHigh),
			"升级控制面依赖并重新构建镜像", time.Since(t0))
	} else {
		add("self.sbom_findings", "平台自身", "自身 SBOM 高危漏洞", "pass",
			fmt.Sprintf("自身资产 P0/P1 漏洞 %d 个", selfHigh), "", time.Since(t0))
	}

	t0 = time.Now()
	add("self.build_info", "平台自身", "构建信息", "pass",
		fmt.Sprintf("vulnagent %s · commit %s · 构建于 %s", appVersion, buildCommit, buildTime), "", time.Since(t0))

	t0 = time.Now()
	totalSpace, freeSpace, ok := diskFree(a.dataDir)
	if !ok {
		add("self.disk", "平台自身", "数据目录可用空间", "skip",
			"当前平台不支持可用空间检测，已降级跳过", "", time.Since(t0))
	} else {
		const gb = 1024 * 1024 * 1024
		switch {
		case freeSpace < 200*gb/1024: // 小于 200MB
			add("self.disk", "平台自身", "数据目录可用空间", "fail",
				fmt.Sprintf("数据目录可用 %.1f GB / 共 %.1f GB", float64(freeSpace)/gb, float64(totalSpace)/gb),
				"清理历史快照或扩容数据盘", time.Since(t0))
		case freeSpace < gb:
			add("self.disk", "平台自身", "数据目录可用空间", "warn",
				fmt.Sprintf("数据目录可用 %.1f GB / 共 %.1f GB", float64(freeSpace)/gb, float64(totalSpace)/gb),
				"可用空间不足 1 GB，建议清理或扩容", time.Since(t0))
		default:
			add("self.disk", "平台自身", "数据目录可用空间", "pass",
				fmt.Sprintf("数据目录可用 %.1f GB / 共 %.1f GB", float64(freeSpace)/gb, float64(totalSpace)/gb), "", time.Since(t0))
		}
	}

	t0 = time.Now()
	apiKey := strings.TrimSpace(os.Getenv("VULNAGENT_CVE_API_KEY"))
	intelClient := newCVEClient(intelBaseURLFromEnv(), apiKey)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	probeItems, probeErr := intelClient.Latest(ctx, 1, 1, "")
	cancel()
	switch {
	case probeErr == nil:
		label := "公开接口"
		if apiKey != "" {
			label = "API Key"
		}
		add("self.intel_api", "平台自身", "情报接口连通性", "pass",
			fmt.Sprintf("情报接口可访问（%s，返回 %d 条）", label, len(probeItems)), "", time.Since(t0))
	default:
		add("self.intel_api", "平台自身", "情报接口连通性", "warn",
			"情报接口不可用："+probeErr.Error(),
			"检查网络出口与 VULNAGENT_CVE_BASE_URL 配置后重试", time.Since(t0))
	}

	// ---- 权限与审计 ----
	t0 = time.Now()
	matched := 0
	for _, acc := range demoAccounts {
		var hash string
		if err := a.db.QueryRow(`SELECT pwd_hash FROM users WHERE username = ?`, acc.Username).Scan(&hash); err != nil {
			continue
		}
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(acc.Password)) == nil {
			matched++
		}
	}
	if matched > 0 {
		add("auth.default_password", "权限与审计", "默认口令检测", "warn",
			fmt.Sprintf("%d 个账号仍使用初始口令", matched),
			"首次登录后立即修改口令，或在配置中关闭演示账号", time.Since(t0))
	} else {
		add("auth.default_password", "权限与审计", "默认口令检测", "pass", "未检测到初始口令", "", time.Since(t0))
	}

	t0 = time.Now()
	var roleCount int
	a.db.QueryRow(`SELECT COUNT(DISTINCT role) FROM users`).Scan(&roleCount)
	if roleCount >= 3 {
		add("auth.rbac", "权限与审计", "角色配置", "pass",
			fmt.Sprintf("已配置 %d 种角色（admin/operator/viewer）", roleCount), "", time.Since(t0))
	} else if roleCount >= 1 {
		add("auth.rbac", "权限与审计", "角色配置", "warn",
			fmt.Sprintf("当前仅配置 %d 种角色，尚未拆分读写权限", roleCount),
			"按需在「账号与角色」中补充 operator / viewer 账号", time.Since(t0))
	} else {
		add("auth.rbac", "权限与审计", "角色配置", "fail",
			"未配置任何角色，读写权限无法隔离",
			"创建 admin/operator/viewer 三类账号", time.Since(t0))
	}

	t0 = time.Now()
	probeRes, errA := a.db.Exec(`INSERT INTO audit_logs(actor, role, action, target, ip, ua, detail, created_at)
		VALUES('selfcheck','system','audit.probe','-','127.0.0.1','-','-',?)`, fmtT(nowT()))
	var auditCount int
	errC := a.db.QueryRow(`SELECT COUNT(*) FROM audit_logs`).Scan(&auditCount)
	if errA == nil {
		if id, err := probeRes.LastInsertId(); err == nil {
			a.db.Exec(`DELETE FROM audit_logs WHERE id = ?`, id)
		}
	}
	if errA != nil || errC != nil || auditCount == 0 {
		add("audit.enabled", "权限与审计", "审计日志可用性", "fail",
			fmt.Sprintf("审计表不可写或为空：%v", firstErr(errA, errC)),
			"检查审计表结构与数据目录写权限", time.Since(t0))
	} else {
		add("audit.enabled", "权限与审计", "审计日志可用性", "pass",
			fmt.Sprintf("审计表可写，共 %d 条", auditCount), "", time.Since(t0))
	}

	// ---- 汇总 ----
	run := selfcheckRun{
		Demo:        a.demoMode(),
		StartedAt:   fmtT(start),
		FinishedAt:  fmtT(nowT()),
		DurationMs:  time.Since(begin).Milliseconds(),
		TriggeredBy: triggeredBy,
		Checks:      checks,
	}
	worst := "pass"
	for _, c := range checks {
		switch c.Status {
		case "pass":
			run.Passed++
		case "warn":
			run.Warnings++
			if worst == "pass" {
				worst = "warn"
			}
		case "fail":
			run.Failed++
			worst = "fail"
		}
	}
	run.Status = worst
	run.RunID = "sc-" + start.Format("20060102-150405")
	run.DurationMs = time.Since(begin).Milliseconds()

	raw, _ := json.Marshal(checks)
	if _, err := a.db.Exec(`INSERT INTO selfcheck_runs(run_id, started_at, finished_at, duration_ms, status,
		triggered_by, passed, warnings, failed, checks) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		run.RunID, run.StartedAt, run.FinishedAt, run.DurationMs, run.Status,
		run.TriggeredBy, run.Passed, run.Warnings, run.Failed, string(raw)); err != nil {
		return run, err
	}
	a.audit(nil, "selfcheck.run", run.RunID,
		fmt.Sprintf("自检完成：%s（%d 通过 / %d 告警 / %d 失败）", run.Status, run.Passed, run.Warnings, run.Failed))
	return run, nil
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

func syncLagHours(db *sql.DB, source string) float64 {
	lag, _, _ := syncCursorInfo(db, source)
	return lag
}

// syncCursorInfo 读取同步游标的时间、状态与错误，供自检判断
func syncCursorInfo(db *sql.DB, source string) (float64, string, string) {
	var last, status, errMsg string
	if err := db.QueryRow(`SELECT last_run_at, status, error FROM sync_cursors WHERE source = ?`, source).
		Scan(&last, &status, &errMsg); err != nil {
		return 9999, "never", ""
	}
	return hoursSince(last), status, errMsg
}

func (a *App) handleSelfcheckRun(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "operator")
	if !ok {
		return
	}
	run, err := a.runSelfcheck(u.Name)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "执行自检失败")
		return
	}
	if run.Status == "fail" {
		a.dispatch("selfcheck.failed", map[string]any{
			"runId":    run.RunID,
			"failed":   run.Failed,
			"warnings": run.Warnings,
			"actor":    u.Name,
		})
	}
	writeJSON(w, http.StatusOK, run)
}

// loadSelfcheckRun 读取最近一次自检记录
func (a *App) loadSelfcheckRun() (*selfcheckRun, error) {
	var run selfcheckRun
	var raw string
	err := a.db.QueryRow(`SELECT run_id, started_at, finished_at, duration_ms, status, triggered_by,
		passed, warnings, failed, checks FROM selfcheck_runs ORDER BY finished_at DESC, id DESC LIMIT 1`).
		Scan(&run.RunID, &run.StartedAt, &run.FinishedAt, &run.DurationMs, &run.Status, &run.TriggeredBy,
			&run.Passed, &run.Warnings, &run.Failed, &raw)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	run.Demo = a.demoMode()
	run.Checks = make([]selfcheckCheck, 0)
	_ = json.Unmarshal([]byte(raw), &run.Checks)
	return &run, nil
}

func (a *App) handleSelfcheckLatest(w http.ResponseWriter, r *http.Request) {
	run, err := a.loadSelfcheckRun()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取自检结果失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"demo": a.demoMode(), "run": run})
}

type selfcheckHistoryItem struct {
	RunID       string `json:"runId"`
	FinishedAt  string `json:"finishedAt"`
	Status      string `json:"status"`
	Passed      int    `json:"passed"`
	Warnings    int    `json:"warnings"`
	Failed      int    `json:"failed"`
	Skipped     int    `json:"skipped"`
	DurationMs  int64  `json:"durationMs"`
	TriggeredBy string `json:"triggeredBy"`
}

func (a *App) handleSelfcheckHistory(w http.ResponseWriter, r *http.Request) {
	rows, err := a.db.Query(`SELECT run_id, finished_at, status, passed, warnings, failed, duration_ms, triggered_by, checks
		FROM selfcheck_runs ORDER BY finished_at DESC, id DESC LIMIT 10`)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取自检历史失败")
		return
	}
	defer rows.Close()
	items := make([]selfcheckHistoryItem, 0, 10)
	for rows.Next() {
		var it selfcheckHistoryItem
		var checksRaw string
		if err := rows.Scan(&it.RunID, &it.FinishedAt, &it.Status, &it.Passed, &it.Warnings, &it.Failed,
			&it.DurationMs, &it.TriggeredBy, &checksRaw); err != nil {
			continue
		}
		var checks []selfcheckCheck
		if json.Unmarshal([]byte(checksRaw), &checks) == nil {
			for _, check := range checks {
				if check.Status == "skip" {
					it.Skipped++
				}
			}
		}
		items = append(items, it)
	}
	writeJSON(w, http.StatusOK, map[string]any{"demo": a.demoMode(), "items": items})
}

// seedSelfcheckHistory 仅演示模式预置两条历史，生产模式不伪造历史
func (a *App) seedSelfcheckHistory() {
	if !a.demoMode() {
		return
	}
	var n int
	if err := a.db.QueryRow(`SELECT COUNT(*) FROM selfcheck_runs`).Scan(&n); err != nil || n > 0 {
		return
	}
	first, err := a.runSelfcheck("系统")
	if err != nil {
		return
	}
	a.backdateRun(first.RunID, nowT().Add(-26*time.Hour))
	second, err := a.runSelfcheck("系统")
	if err != nil {
		return
	}
	a.backdateRun(second.RunID, nowT().Add(-3*time.Hour))
}

func (a *App) backdateRun(runID string, finished time.Time) {
	newID := "sc-" + finished.Format("20060102-150405")
	a.db.Exec(`UPDATE selfcheck_runs SET run_id = ?, started_at = ?, finished_at = ? WHERE run_id = ?`,
		newID, fmtT(finished.Add(-900*time.Millisecond)), fmtT(finished), runID)
}
