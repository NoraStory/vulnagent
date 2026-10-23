package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"strings"
	"time"

	"vulnagent/server/internal/application/ports"
)

// ---------- 概览 ----------

type overviewCounts struct {
	P0           int `json:"p0"`
	P1           int `json:"p1"`
	P2           int `json:"p2"`
	P3           int `json:"p3"`
	Total        int `json:"total"`
	Open         int `json:"open"`
	Fixing       int `json:"fixing"`
	Fixed        int `json:"fixed"`
	Verified     int `json:"verified"`
	RiskAccepted int `json:"riskAccepted"`
}

type trendPoint struct {
	Date  string `json:"date"`
	P0    int    `json:"p0"`
	P1    int    `json:"p1"`
	P2    int    `json:"p2"`
	P3    int    `json:"p3"`
	Total int    `json:"total"`
}

type topComponent struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Ecosystem  string `json:"ecosystem"`
	CveCount   int    `json:"cveCount"`
	MaxRisk    int    `json:"maxRisk"`
	Priority   string `json:"priority"`
	AssetCount int    `json:"assetCount"`
}

type syncItem struct {
	Source    string `json:"source"`
	LastRunAt string `json:"lastRunAt"`
	Status    string `json:"status"`
	Count     int    `json:"count"`
	LagHours  int    `json:"lagHours"`
	Error     string `json:"error"`
}

type agentSummary struct {
	Total   int `json:"total"`
	Online  int `json:"online"`
	Offline int `json:"offline"`
	Stale   int `json:"stale"`
}

type selfcheckSummary struct {
	RunID     string `json:"runId"`
	Status    string `json:"status"`
	CheckedAt string `json:"checkedAt"`
	Passed    int    `json:"passed"`
	Warnings  int    `json:"warnings"`
	Failed    int    `json:"failed"`
}

type overviewEvent struct {
	ID     int64  `json:"id"`
	Time   string `json:"time"`
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Target string `json:"target"`
	Detail string `json:"detail"`
}

type overviewResp struct {
	Demo          bool             `json:"demo"`
	GeneratedAt   string           `json:"generatedAt"`
	Counts        overviewCounts   `json:"counts"`
	Trend         []trendPoint     `json:"trend"`
	TopComponents []topComponent   `json:"topComponents"`
	Sync          []syncItem       `json:"sync"`
	Agents        agentSummary     `json:"agents"`
	Selfcheck     selfcheckSummary `json:"selfcheck"`
	RecentEvents  []overviewEvent  `json:"recentEvents"`
}

func (a *App) handleOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var counts overviewCounts
	prio, err := a.statsRepo().FindingsByPriority(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "统计漏洞分布失败")
		return
	}
	for _, item := range prio {
		switch item.Priority {
		case "P0":
			counts.P0 = item.Count
		case "P1":
			counts.P1 = item.Count
		case "P2":
			counts.P2 = item.Count
		case "P3":
			counts.P3 = item.Count
		}
		counts.Total += item.Count
	}

	statuses, err := a.statsRepo().FindingsByStatus(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "统计漏洞状态失败")
		return
	}
	for _, item := range statuses {
		switch item.Status {
		case "open":
			counts.Open = item.Count
		case "fixing":
			counts.Fixing = item.Count
		case "fixed":
			counts.Fixed = item.Count
		case "verified":
			counts.Verified = item.Count
		case "risk_accepted":
			counts.RiskAccepted = item.Count
		}
	}

	// 近 14 天趋势：按 first_seen 累加当前优先级
	now := nowT()
	trend := make([]trendPoint, 0, 14)
	for i := 13; i >= 0; i-- {
		day := timeAtMidnight(now.AddDate(0, 0, -i))
		end := day.AddDate(0, 0, 1)
		p := trendPoint{Date: day.Format("2006-01-02")}
		buckets, err := a.statsRepo().PriorityBefore(ctx, fmtT(end))
		if err != nil {
			continue
		}
		for _, item := range buckets {
			switch item.Priority {
			case "P0":
				p.P0 = item.Count
			case "P1":
				p.P1 = item.Count
			case "P2":
				p.P2 = item.Count
			case "P3":
				p.P3 = item.Count
			}
			p.Total += item.Count
		}
		trend = append(trend, p)
	}

	topRows, err := a.statsRepo().TopComponents(ctx, 6)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "统计高风险组件失败")
		return
	}
	tops := make([]topComponent, 0, 6)
	for _, item := range topRows {
		tops = append(tops, topComponent{
			Name:       item.Name,
			Version:    item.Version,
			Ecosystem:  item.Eco,
			CveCount:   item.CVECount,
			MaxRisk:    item.MaxRisk,
			Priority:   item.Priority,
			AssetCount: item.AssetCount,
		})
	}

	syncs := a.loadSync()
	agents := a.loadAgents()
	sc := a.latestSelfcheckSummary()

	events := make([]overviewEvent, 0)
	evs, err := a.statsRepo().RecentFindingEvents(ctx, 8)
	if err == nil {
		for _, item := range evs {
			e := overviewEvent{ID: item.ID, Time: item.Time, Actor: item.Actor, Detail: item.Detail}
			e.Action = "finding.event"
			switch {
			case strings.HasPrefix(item.Event, "status:"):
				e.Action = "finding.status"
			case strings.HasPrefix(item.Event, "ticket:"):
				e.Action = "finding.ticket"
			case strings.HasPrefix(item.Event, "rescan:"):
				e.Action = "finding.rescan"
			case strings.HasPrefix(item.Event, "assignee:"):
				e.Action = "finding.assign"
			}
			e.Target = item.CVEID + " @ " + item.Hostname
			events = append(events, e)
		}
	}

	writeJSON(w, http.StatusOK, overviewResp{
		Demo:          a.demoMode(),
		GeneratedAt:   fmtT(now),
		Counts:        counts,
		Trend:         trend,
		TopComponents: tops,
		Sync:          syncs,
		Agents:        agents,
		Selfcheck:     sc,
		RecentEvents:  events,
	})
}

func timeAtMidnight(t time.Time) time.Time {
	t = t.In(cst)
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, cst)
}

func (a *App) loadSync() []syncItem {
	cursors, err := a.syncRepo().Cursors(context.Background())
	if err != nil {
		return []syncItem{}
	}
	items := make([]syncItem, 0, len(cursors))
	for _, it := range cursors {
		items = append(items, syncItem{
			Source:    it.Source,
			LastRunAt: it.LastRunAt,
			Status:    it.Status,
			Count:     it.Count,
			LagHours:  int(math.Round(hoursSince(it.LastRunAt))),
			Error:     it.Error,
		})
	}
	return items
}

func (a *App) loadAgents() agentSummary {
	s, err := a.statsRepo().AgentSummary(context.Background())
	if err != nil {
		return agentSummary{}
	}
	return agentSummary{Total: s.Total, Online: s.Online, Offline: s.Offline, Stale: s.Stale}
}

func (a *App) latestSelfcheckSummary() selfcheckSummary {
	var s selfcheckSummary
	err := a.db.QueryRow(`SELECT run_id, status, finished_at, passed, warnings, failed
		FROM selfcheck_runs ORDER BY finished_at DESC, id DESC LIMIT 1`).
		Scan(&s.RunID, &s.Status, &s.CheckedAt, &s.Passed, &s.Warnings, &s.Failed)
	if err != nil {
		return selfcheckSummary{Status: "never"}
	}
	return s
}

// ---------- 设置 ----------

type settingsUser struct {
	Username  string `json:"username"`
	Name      string `json:"name"`
	Role      string `json:"role"`
	LastLogin string `json:"lastLogin"`
	Disabled  bool   `json:"disabled"`
}

type buildInfo struct {
	Version    string `json:"version"`
	Commit     string `json:"commit"`
	BuiltAt    string `json:"builtAt"`
	SbomDigest string `json:"sbomDigest"`
}

func (a *App) handleSettings(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "admin"); !ok {
		return
	}
	policy := loadPolicy(a.db)
	accounts, err := a.identityRepo().ListAccounts(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "查询账号失败")
		return
	}
	users := make([]settingsUser, 0, len(accounts))
	for _, acc := range accounts {
		users = append(users, settingsUser{
			Username:  acc.Username,
			Name:      acc.Name,
			Role:      acc.Role,
			LastLogin: acc.LastLogin,
			Disabled:  acc.Disabled,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"demo":       a.demoMode(),
		"riskPolicy": policy,
		"users":      users,
		"build": buildInfo{
			Version:    appVersion,
			Commit:     buildCommit,
			BuiltAt:    buildTime,
			SbomDigest: a.selfDigest,
		},
	})
}

func (a *App) handleRiskPolicy(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "admin"); !ok {
		return
	}
	var req RiskPolicy
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	sum := req.Weights.Cvss + req.Weights.Epss + req.Weights.Exploit + req.Weights.Asset
	if math.Abs(sum-1.0) > 0.001 {
		writeErr(w, http.StatusBadRequest, "bad_request", "四项权重之和必须为 1.0")
		return
	}
	for _, v := range []float64{req.Weights.Cvss, req.Weights.Epss, req.Weights.Exploit, req.Weights.Asset} {
		if v < 0 || v > 1 {
			writeErr(w, http.StatusBadRequest, "bad_request", "权重必须位于 0 到 1 之间")
			return
		}
	}
	if !(req.Thresholds.P0 > req.Thresholds.P1 && req.Thresholds.P1 > req.Thresholds.P2 &&
		req.Thresholds.P2 >= 0 && req.Thresholds.P0 <= 100) {
		writeErr(w, http.StatusBadRequest, "bad_request", "阈值需满足 p0 > p1 > p2 且位于 0–100")
		return
	}

	wJSON, _ := json.Marshal(req.Weights)
	tJSON, _ := json.Marshal(req.Thresholds)
	if err := a.policyRepo().SaveRiskPolicy(r.Context(), string(wJSON), string(tJSON), fmtT(nowT())); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "保存策略失败")
		return
	}
	recomputed, err := a.recomputeFindings(req)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "重算风险分失败")
		return
	}
	a.audit(r, "policy.update", "risk-policy",
		fmt.Sprintf("权重 cvss=%.2f epss=%.2f exploit=%.2f asset=%.2f，重算 %d 条",
			req.Weights.Cvss, req.Weights.Epss, req.Weights.Exploit, req.Weights.Asset, recomputed))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "riskPolicy": req, "recomputed": recomputed})
}

func (a *App) recomputeFindings(p RiskPolicy) (int, error) {
	ctx := context.Background()
	list, err := a.findingRepo().ListForRecompute(ctx)
	if err != nil {
		return 0, err
	}
	updates := make([]ports.ScoreUpdate, 0, len(list))
	for _, it := range list {
		risk, prio, bd := p.Score(it.CVSS, it.EPSS, it.Exploit, it.Exposure, it.Tier)
		updates = append(updates, ports.ScoreUpdate{
			ID:          it.ID,
			Risk:        risk,
			Priority:    prio,
			Breakdown:   marshalBreakdown(bd),
			AssetWeight: assetWeight(it.Exposure, it.Tier),
		})
	}
	if err := a.findingRepo().BulkUpdateScores(ctx, updates); err != nil {
		return 0, err
	}
	return len(updates), nil
}

// ---------- 审计 ----------

type auditItem struct {
	ID     int64  `json:"id"`
	Time   string `json:"time"`
	Actor  string `json:"actor"`
	Role   string `json:"role"`
	Action string `json:"action"`
	Target string `json:"target"`
	IP     string `json:"ip"`
	Detail string `json:"detail"`
}

func (a *App) handleAuditLogs(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "admin"); !ok {
		return
	}
	page, size, offset := pageParams(r)
	filter := ports.AuditFilter{
		Action: strings.TrimSpace(r.URL.Query().Get("action")),
		Actor:  strings.TrimSpace(r.URL.Query().Get("actor")),
		Limit:  size,
		Offset: offset,
	}

	total, err := a.auditRepo().Count(r.Context(), filter)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "查询审计日志失败")
		return
	}
	entries, err := a.auditRepo().List(r.Context(), filter)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "查询审计日志失败")
		return
	}
	items := make([]auditItem, 0, len(entries))
	for _, e := range entries {
		items = append(items, auditItem{
			ID:     e.ID,
			Time:   e.CreatedAt,
			Actor:  e.Actor,
			Role:   e.Role,
			Action: e.Action,
			Target: e.Target,
			IP:     e.IP,
			Detail: e.Detail,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"demo":     a.demoMode(),
		"total":    total,
		"page":     page,
		"pageSize": size,
		"items":    items,
	})
}

// ---------- 情报同步 ----------

func (a *App) handleSyncStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"demo": a.demoMode(), "sources": a.loadSync()})
}

// handleOSVSync 对全部或指定资产做 OSV 在线版本匹配
func (a *App) handleOSVSync(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "admin"); !ok {
		return
	}
	var req struct {
		AssetIDs []int64 `json:"assetIds"`
		All      bool    `json:"all"`
	}
	if r.ContentLength > 0 {
		_ = readJSON(r, &req)
	}
	if !req.All && len(req.AssetIDs) == 0 {
		req.All = true
	}
	res, err := a.osvScanAssets(req.AssetIDs, req.All)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "osv_scan_failed", err.Error())
		return
	}
	a.audit(r, "sync.osv", "osv",
		fmt.Sprintf("资产 %d 台，组件 %d 个，命中 %d 条，新增 %d 条，更新 %d 条",
			res.Assets, res.Components, res.Vulns, res.Created, res.Updated))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"assets":     res.Assets,
		"components": res.Components,
		"queried":    res.Queried,
		"vulns":      res.Vulns,
		"created":    res.Created,
		"updated":    res.Updated,
		"errors":     res.Errors,
	})
}

func (a *App) handleSyncTrigger(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "admin"); !ok {
		return
	}
	source := r.PathValue("source")
	if source != "cve" && source != "poc" {
		writeErr(w, http.StatusBadRequest, "bad_request", "未知的情报源")
		return
	}
	apiKey := strings.TrimSpace(os.Getenv("VULNAGENT_CVE_API_KEY"))
	client := newCVEClient(intelBaseURLFromEnv(), apiKey)
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	var res syncResult
	var err error
	if source == "cve" {
		res, err = syncCVEFromAPI(ctx, a.db, client, 20)
	} else {
		res, err = syncPOCFromAPI(ctx, a.db, client, 10)
	}
	if err != nil {
		a.audit(r, "sync."+source, source, "同步失败："+err.Error())
		a.dispatch("sync.failed", map[string]any{"source": source, "error": err.Error()})
		writeErr(w, http.StatusBadGateway, "sync_failed", err.Error())
		return
	}
	a.audit(r, "sync."+source, source,
		fmt.Sprintf("同步完成：新增 %d 条，更新 %d 条", res.Inserted, res.Updated))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"mode":      res.Mode,
		"fetched":   res.Fetched,
		"inserted":  res.Inserted,
		"updated":   res.Updated,
		"startedAt": fmtT(nowT()),
	})
}
