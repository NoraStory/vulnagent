package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
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
}

const findingSelect = `SELECT f.id, f.cve_id, c.title, f.priority, f.risk, f.cvss, f.epss, f.exploit,
	f.status, f.assignee, f.inferred, f.first_seen,
	a.id, a.hostname, a.env, a.exposure, a.tier,
	f.component_name, f.component_version, f.eco, f.purl, f.fixed_version
	FROM findings f
	JOIN assets a ON a.id = f.asset_id
	JOIN cves c ON c.cve_id = f.cve_id`

func scanFinding(sc interface{ Scan(...any) error }) (findingItem, error) {
	var it findingItem
	err := sc.Scan(&it.ID, &it.CveID, &it.Title, &it.Priority, &it.Risk, &it.Cvss, &it.Epss, &it.Exploit,
		&it.Status, &it.Assignee, &it.Inferred, &it.FirstSeen,
		&it.Asset.ID, &it.Asset.Hostname, &it.Asset.Env, &it.Asset.Exposure, &it.Asset.Tier,
		&it.Component.Name, &it.Component.Version, &it.Component.Ecosystem, &it.Component.Purl, &it.Component.FixedVersion)
	return it, err
}

func (a *App) handleFindings(w http.ResponseWriter, r *http.Request) {
	page, size, offset := pageParams(r)
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	priority := r.URL.Query().Get("priority")
	status := r.URL.Query().Get("status")

	where := []string{"1=1"}
	args := []any{}
	if priority != "" {
		where = append(where, "f.priority = ?")
		args = append(args, priority)
	}
	if status != "" {
		where = append(where, "f.status = ?")
		args = append(args, status)
	}
	if q != "" {
		like := "%" + q + "%"
		where = append(where, "(a.hostname LIKE ? OR f.cve_id LIKE ? OR f.component_name LIKE ?)")
		args = append(args, like, like, like)
	}
	whereSQL := strings.Join(where, " AND ")

	var total int
	if err := a.db.QueryRow(`SELECT COUNT(*) FROM findings f JOIN assets a ON a.id = f.asset_id WHERE `+whereSQL, args...).Scan(&total); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "查询漏洞列表失败")
		return
	}
	rows, err := a.db.Query(findingSelect+" WHERE "+whereSQL+" ORDER BY f.risk DESC, f.id ASC LIMIT ? OFFSET ?",
		append(args, size, offset)...)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "查询漏洞列表失败")
		return
	}
	defer rows.Close()

	items := make([]findingItem, 0, size)
	for rows.Next() {
		it, err := scanFinding(rows)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal_error", "解析漏洞数据失败")
			return
		}
		items = append(items, it)
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
	row := a.db.QueryRow(findingSelect+" WHERE f.id = ?", id)
	return scanFinding(row)
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

	var desc, cweCN, published, breakdownRaw string
	var cweID int
	err = a.db.QueryRow(`SELECT c.description, c.cwe_id, c.cwe_cn, c.published_at, f.score_breakdown
		FROM findings f JOIN cves c ON c.cve_id = f.cve_id WHERE f.id = ?`, id).
		Scan(&desc, &cweID, &cweCN, &published, &breakdownRaw)
	if err != nil && err != sql.ErrNoRows {
		writeErr(w, http.StatusInternalServerError, "internal_error", "查询漏洞详情失败")
		return
	}

	breakdown := make([]ScoreFactor, 0)
	_ = json.Unmarshal([]byte(breakdownRaw), &breakdown)

	pocRows, err := a.db.Query(`SELECT link, inserted_at FROM cve_poc WHERE cve_id = ? ORDER BY inserted_at DESC`, it.CveID)
	if err == nil {
		defer pocRows.Close()
	}
	pocs := make([]pocItem, 0)
	if pocRows != nil {
		for pocRows.Next() {
			var p pocItem
			if err := pocRows.Scan(&p.Link, &p.InsertedAt); err == nil {
				pocs = append(pocs, p)
			}
		}
	}

	eventRows, err := a.db.Query(`SELECT created_at, event, actor, detail FROM finding_events
		WHERE finding_id = ? ORDER BY created_at ASC, id ASC`, id)
	if err == nil {
		defer eventRows.Close()
	}
	events := make([]eventItem, 0)
	if eventRows != nil {
		for eventRows.Next() {
			var e eventItem
			if err := eventRows.Scan(&e.Time, &e.Event, &e.Actor, &e.Detail); err == nil {
				events = append(events, e)
			}
		}
	}

	out := findingDetail{
		findingItem:    it,
		Demo:           a.demoMode(),
		Description:    desc,
		Cwe:            cweRef{ID: cweID, CN: cweCN},
		PublishedAt:    published,
		ScoreBreakdown: breakdown,
		Poc:            pocs,
		Advice:         buildAdvice(it),
		Events:         events,
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

var validStatuses = map[string]bool{
	"open": true, "triaged": true, "fixing": true, "fixed": true, "verified": true,
	"closed": true, "risk_accepted": true, "false_positive": true,
}

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
	if req.Status != nil && !validStatuses[*req.Status] {
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
	if _, err := a.db.Exec(`UPDATE findings SET status = ?, assignee = ? WHERE id = ?`, newStatus, newAssignee, id); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "更新漏洞失败")
		return
	}

	now := fmtT(nowT())
	if newStatus != cur.Status {
		event := fmt.Sprintf("status: %s → %s", cur.Status, newStatus)
		a.db.Exec(`INSERT INTO finding_events(finding_id, event, actor, detail, created_at) VALUES(?,?,?,?,?)`,
			id, event, u.Name, "控制台手动更新", now)
		a.audit(r, "finding.status", cur.CveID+" @ "+cur.Asset.Hostname, cur.Status+" → "+newStatus)
	}
	if newAssignee != cur.Assignee {
		event := fmt.Sprintf("assignee: %s → %s", firstNonEmpty(cur.Assignee, "未指派"), firstNonEmpty(newAssignee, "未指派"))
		a.db.Exec(`INSERT INTO finding_events(finding_id, event, actor, detail, created_at) VALUES(?,?,?,?,?)`,
			id, event, u.Name, "控制台重新指派", now)
		a.audit(r, "finding.assign", cur.CveID+" @ "+cur.Asset.Hostname, event)
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

	var maxSeq int
	_ = a.db.QueryRow(`SELECT COALESCE(MAX(CAST(substr(ticket_id, 9) AS INTEGER)), 0)
		FROM findings WHERE ticket_id LIKE 'VA-2026-%'`).Scan(&maxSeq)
	ticketID := fmt.Sprintf("VA-2026-%04d", maxSeq+1)
	status := cur.Status
	assignee := cur.Assignee
	if assignee == "" {
		assignee = u.Name
	}
	if status == "open" || status == "triaged" {
		status = "fixing"
	}
	if _, err := a.db.Exec(`UPDATE findings SET ticket_id = ?, status = ?, assignee = ? WHERE id = ?`,
		ticketID, status, assignee, id); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "创建工单失败")
		return
	}

	now := fmtT(nowT())
	detail := "工单已同步至变更平台"
	if cur.Status != status {
		detail = "工单已创建，状态由 " + cur.Status + " 流转为 " + status
	}
	a.db.Exec(`INSERT INTO finding_events(finding_id, event, actor, detail, created_at) VALUES(?,?,?,?,?)`,
		id, "ticket: "+ticketID+" 已创建", u.Name, detail, now)
	a.audit(r, "finding.ticket", cur.CveID+" @ "+cur.Asset.Hostname, "创建工单 "+ticketID)
	a.dispatch("ticket.created", map[string]any{
		"ticketId": ticketID,
		"cveId":    cur.CveID,
		"hostname": cur.Asset.Hostname,
		"priority": cur.Priority,
		"risk":     cur.Risk,
		"status":   status,
		"assignee": assignee,
	})

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "ticketId": ticketID, "status": status})
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
	if _, err := a.db.Exec(`INSERT INTO finding_events(finding_id, event, actor, detail, created_at)
		VALUES(?,?,?,?,?)`, id, "rescan: 已执行复扫 "+scanID, u.Name, detail, now); err != nil {
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
