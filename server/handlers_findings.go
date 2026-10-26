package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"vulnagent/server/internal/application/ports"
	"vulnagent/server/internal/domain/vuln"
)

type assetRef struct {
	ID       int64  `json:"id"`
	Hostname string `json:"hostname"`
	Env      string `json:"env"`
	Exposure string `json:"exposure"`
	Tier     string `json:"tier"`
}

type componentRef struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Ecosystem    string `json:"ecosystem"`
	Purl         string `json:"purl"`
	FixedVersion string `json:"fixedVersion"`
}

// findingItem 列表中单条漏洞结论
type findingItem struct {
	ID        int64        `json:"id"`
	CveID     string       `json:"cveId"`
	Title     string       `json:"title"`
	Priority  string       `json:"priority"`
	Risk      int          `json:"risk"`
	Cvss      float64      `json:"cvss"`
	Epss      float64      `json:"epss"`
	Exploit   string       `json:"exploit"`
	Status    string       `json:"status"`
	Assignee  string       `json:"assignee"`
	Inferred  bool         `json:"inferred"`
	FirstSeen string       `json:"firstSeen"`
	Asset     assetRef     `json:"asset"`
	Component componentRef `json:"component"`
}

type cweRef struct {
	ID int    `json:"id"`
	CN string `json:"cn"`
}

type pocItem struct {
	Link       string `json:"link"`
	InsertedAt string `json:"insertedAt"`
}

type advice struct {
	FixedVersion string `json:"fixedVersion"`
	UpgradePath  string `json:"upgradePath"`
	Command      string `json:"command"`
	Note         string `json:"note"`
}

type eventItem struct {
	Time   string `json:"time"`
	Event  string `json:"event"`
	Actor  string `json:"actor"`
	Detail string `json:"detail"`
}

type findingDetail struct {
	findingItem
	Demo           bool          `json:"demo"`
	Description    string        `json:"description"`
	Cwe            cweRef        `json:"cwe"`
	PublishedAt    string        `json:"publishedAt"`
	ScoreBreakdown []ScoreFactor `json:"scoreBreakdown"`
	Poc            []pocItem     `json:"poc"`
	Advice         advice        `json:"advice"`
	Events         []eventItem   `json:"events"`
	Ticket         *ports.Ticket `json:"ticket,omitempty"`
}

// toFindingItem 把仓储模型转换为接口 DTO
func toFindingItem(it ports.FindingListItem) findingItem {
	return findingItem{
		ID:        it.ID,
		CveID:     it.CVEID,
		Title:     it.Title,
		Priority:  it.Priority,
		Risk:      it.Risk,
		Cvss:      it.CVSS,
		Epss:      it.EPSS,
		Exploit:   it.Exploit,
		Status:    it.Status,
		Assignee:  it.Assignee,
		Inferred:  it.Inferred,
		FirstSeen: it.FirstSeen,
		Asset: assetRef{
			ID:       it.AssetID,
			Hostname: it.AssetHostname,
			Env:      it.AssetEnv,
			Exposure: it.AssetExposure,
			Tier:     it.AssetTier,
		},
		Component: componentRef{
			Name:         it.ComponentName,
			Version:      it.ComponentVersion,
			Ecosystem:    it.ComponentEco,
			Purl:         it.PURL,
			FixedVersion: it.FixedVersion,
		},
	}
}

func (a *App) handleFindings(w http.ResponseWriter, r *http.Request) {
	page, size, offset := pageParams(r)
	list, total, err := a.findingRepo().List(r.Context(), ports.FindingFilter{
		Priority: r.URL.Query().Get("priority"),
		Status:   r.URL.Query().Get("status"),
		Query:    strings.TrimSpace(r.URL.Query().Get("q")),
		Limit:    size,
		Offset:   offset,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "查询漏洞列表失败")
		return
	}
	items := make([]findingItem, 0, len(list))
	for _, it := range list {
		items = append(items, toFindingItem(it))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"demo":     a.demoMode(),
		"total":    total,
		"page":     page,
		"pageSize": size,
		"items":    items,
	})
}

func (a *App) getFinding(id int64) (findingItem, error) {
	it, err := a.findingRepo().Get(context.Background(), id)
	if err != nil {
		return findingItem{}, err
	}
	return toFindingItem(it), nil
}

func (a *App) handleFindingDetail(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "无效的漏洞 ID")
		return
	}
	it, err := a.getFinding(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "漏洞记录不存在")
		return
	}

	extra, err := a.findingRepo().Extra(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "查询漏洞详情失败")
		return
	}

	breakdown := make([]ScoreFactor, 0)
	_ = json.Unmarshal([]byte(extra.Breakdown), &breakdown)

	pocLinks, err := a.findingRepo().POCs(r.Context(), it.CveID)
	if err != nil {
		pocLinks = nil
	}
	pocs := make([]pocItem, 0, len(pocLinks))
	for _, p := range pocLinks {
		pocs = append(pocs, pocItem{Link: p.Link, InsertedAt: p.InsertedAt})
	}

	eventRows, err := a.findingRepo().Events(r.Context(), id)
	if err != nil {
		eventRows = nil
	}
	events := make([]eventItem, 0, len(eventRows))
	for _, e := range eventRows {
		events = append(events, eventItem{Time: e.Time, Event: e.Event, Actor: e.Actor, Detail: e.Detail})
	}

	out := findingDetail{
		findingItem:    it,
		Demo:           a.demoMode(),
		Description:    extra.Description,
		Cwe:            cweRef{ID: extra.CWEID, CN: extra.CWECN},
		PublishedAt:    extra.PublishedAt,
		ScoreBreakdown: breakdown,
		Poc:            pocs,
		Advice:         buildAdvice(it),
		Events:         events,
	}
	if ticket, found, err := a.ticketRepo().ByFinding(r.Context(), id); err == nil && found {
		out.Ticket = &ticket
	}
	writeJSON(w, http.StatusOK, out)
}

// buildAdvice 按生态生成升级建议
func buildAdvice(it findingItem) advice {
	cur := it.Component.Version
	fixed := it.Component.FixedVersion
	if fixed == "" {
		return advice{
			FixedVersion: "",
			UpgradePath:  cur + " → 暂无官方修复版本",
			Command:      "",
			Note:         "无可用补丁，建议下线该组件或通过访问控制、WAF 规则做临时缓解",
		}
	}
	cmd := ""
	switch it.Component.Ecosystem {
	case "deb":
		cmd = fmt.Sprintf("apt-get install --only-upgrade %s=%s", it.Component.Name, fixed)
	case "rpm":
		cmd = fmt.Sprintf("dnf update %s-%s", it.Component.Name, fixed)
	case "maven":
		group := mavenGroup(it.Component.Purl)
		cmd = fmt.Sprintf("mvn versions:use-dep-version -Dincludes=%s:%s -DdepVersion=%s", group, it.Component.Name, fixed)
	case "npm":
		cmd = fmt.Sprintf("npm i %s@%s", it.Component.Name, fixed)
	case "golang":
		cmd = fmt.Sprintf("go get %s@%s", it.Component.Name, fixed)
	case "pypi":
		cmd = fmt.Sprintf("pip install -U %s==%s", it.Component.Name, fixed)
	case "nuget":
		cmd = fmt.Sprintf("dotnet add package %s --version %s", it.Component.Name, fixed)
	case "oci":
		cmd = fmt.Sprintf("docker pull %s:%s", it.Component.Name, fixed)
	default:
		cmd = fmt.Sprintf("升级 %s 至 %s", it.Component.Name, fixed)
	}
	note := "按常规变更窗口升级，升级后触发复扫验证"
	switch it.Priority {
	case "P0":
		note = "存在在野利用或公网暴露，建议 24 小时内完成变更并复扫验证"
	case "P1":
		note = "建议 7 天内完成修复，升级后务必复扫确认"
	}
	return advice{
		FixedVersion: fixed,
		UpgradePath:  cur + " → " + fixed,
		Command:      cmd,
		Note:         note,
	}
}

func mavenGroup(purl string) string {
	s := strings.TrimPrefix(purl, "pkg:maven/")
	if i := strings.Index(s, "/"); i > 0 {
		return s[:i]
	}
	return ""
}

// validStatuses 状态字典来自领域层，避免与复扫/报表各写一套
func isValidStatus(s string) bool { return vuln.Status(s).Valid() }

func (a *App) handleFindingPatch(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "operator")
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "无效的漏洞 ID")
		return
	}
	var req struct {
		Status   *string `json:"status"`
		Assignee *string `json:"assignee"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	if req.Status == nil && req.Assignee == nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "仅支持修改 status 与 assignee")
		return
	}
	if req.Status != nil && !isValidStatus(*req.Status) {
		writeErr(w, http.StatusBadRequest, "bad_request", "status 取值不在允许范围内")
		return
	}

	cur, err := a.getFinding(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "漏洞记录不存在")
		return
	}
	newStatus := cur.Status
	if req.Status != nil {
		newStatus = *req.Status
	}
	newAssignee := cur.Assignee
	if req.Assignee != nil {
		newAssignee = strings.TrimSpace(*req.Assignee)
	}
	if err := a.findingRepo().UpdateStatusAssignee(r.Context(), id, newStatus, newAssignee); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "更新漏洞失败")
		return
	}

	now := fmtT(nowT())
	if newStatus != cur.Status {
		event := fmt.Sprintf("status: %s → %s", cur.Status, newStatus)
		_ = a.findingRepo().AddEvent(r.Context(), id, event, u.Name, "控制台手动更新", now)
		a.audit(r, "finding.status", cur.CveID+" @ "+cur.Asset.Hostname, cur.Status+" → "+newStatus)
	}
	if newAssignee != cur.Assignee {
		event := fmt.Sprintf("assignee: %s → %s", firstNonEmpty(cur.Assignee, "未指派"), firstNonEmpty(newAssignee, "未指派"))
		_ = a.findingRepo().AddEvent(r.Context(), id, event, u.Name, "控制台重新指派", now)
		a.audit(r, "finding.assign", cur.CveID+" @ "+cur.Asset.Hostname, event)
	}
	// 工单与漏洞状态保持一致
	if ticket, found, err := a.ticketRepo().ByFinding(r.Context(), id); err == nil && found {
		_ = a.ticketRepo().UpdateStatus(r.Context(), ticket.ID, newStatus, newAssignee, now)
	}

	updated, err := a.getFinding(id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取更新结果失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "finding": updated})
}

func (a *App) handleFindingTicket(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "operator")
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "无效的漏洞 ID")
		return
	}
	cur, err := a.getFinding(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "漏洞记录不存在")
		return
	}

	ticket, created, err := a.ensureTicket(cur, u.Name)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "创建工单失败")
		return
	}

	now := fmtT(nowT())
	if created {
		detail := "本地工单已创建，状态保持 " + ticket.Status
		if cur.Status != ticket.Status {
			detail = "本地工单已创建，漏洞状态由 " + cur.Status + " 流转为 " + ticket.Status
		}
		_ = a.findingRepo().AddEvent(r.Context(), id, "ticket: "+ticket.ID+" 已创建", u.Name, detail, now)
		a.audit(r, "finding.ticket", cur.CveID+" @ "+cur.Asset.Hostname, "创建工单 "+ticket.ID)
		a.dispatch("ticket.created", map[string]any{
			"ticketId": ticket.ID,
			"cveId":    cur.CveID,
			"hostname": cur.Asset.Hostname,
			"priority": cur.Priority,
			"risk":     cur.Risk,
			"status":   ticket.Status,
			"assignee": ticket.Assignee,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "ticketId": ticket.ID, "status": ticket.Status, "ticket": ticket, "created": created,
	})
}

func (a *App) handleFindingRescan(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "operator")
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "无效的漏洞 ID")
		return
	}
	cur, err := a.getFinding(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "漏洞记录不存在")
		return
	}

	scanID := "scan-" + nowT().Format("20060102-1504")
	now := fmtT(nowT())

	// 真正的复扫：重新匹配 + 状态收敛，同一资产受防抖窗口保护
	outcome, err := a.rescanAsset(cur.Asset.ID, u.Name)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "复扫失败")
		return
	}
	if outcome.Skipped {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"skipped": true,
			"scanId":  scanID,
			"assetId": cur.Asset.ID,
			"status":  cur.Status,
		})
		return
	}

	detail := fmt.Sprintf("新增 %d 条 · 更新 %d 条 · 验证 %d 条 · 关闭 %d 条",
		outcome.Created, outcome.Updated, outcome.Verified, outcome.Closed)
	if outcome.Reopened > 0 {
		detail += fmt.Sprintf(" · 重新打开 %d 条", outcome.Reopened)
	}
	if err := a.findingRepo().AddEvent(r.Context(), id, "rescan: 已执行复扫 "+scanID, u.Name, detail, now); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "写入处理记录失败")
		return
	}
	a.audit(r, "findings.rescan", cur.CveID+" @ "+cur.Asset.Hostname, "触发复扫 "+scanID+"："+detail)

	status := cur.Status
	if latest, err := a.getFinding(id); err == nil {
		status = latest.Status
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"skipped":  false,
		"scanId":   scanID,
		"assetId":  cur.Asset.ID,
		"created":  outcome.Created,
		"updated":  outcome.Updated,
		"verified": outcome.Verified,
		"closed":   outcome.Closed,
		"reopened": outcome.Reopened,
		"status":   status,
	})
}
