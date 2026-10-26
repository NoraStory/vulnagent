package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"vulnagent/server/internal/application/ports"
)

// newTicketTestApp 构造一个带资产与 CVE 的临时控制面，供工单用例复用。
func newTicketTestApp(t *testing.T) (*App, *sql.DB, int64) {
	t.Helper()
	db, err := openDB(filepath.Join(t.TempDir(), "tickets.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败：%v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	mustExec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.Exec(query, args...); err != nil {
			t.Fatalf("执行 SQL 失败：%v", err)
		}
	}
	mustExec(`INSERT INTO assets(hostname, exposure, tier, source) VALUES('ticket-host','internal','normal','agent')`)
	var assetID int64
	if err := db.QueryRow(`SELECT id FROM assets WHERE hostname = 'ticket-host'`).Scan(&assetID); err != nil {
		t.Fatalf("读取资产失败：%v", err)
	}
	mustExec(`INSERT INTO cves(cve_id, title, description, cvss_score, epss, exploit_state, cwe_id, cwe_cn,
		published_at, fixed_version) VALUES('CVE-TEST-0001','测试漏洞','用于工单单元测试',9.8,0.9,'kev',79,'测试',
		'2026-01-01T00:00:00+08:00','2.17.1')`)

	return &App{db: db}, db, assetID
}

// seedTicketFinding 插入一条漏洞结论并返回 ID；suffix 用于保证 purl 唯一。
func seedTicketFinding(t *testing.T, db *sql.DB, assetID int64, suffix, status, assignee string) int64 {
	t.Helper()
	purl := fmt.Sprintf("pkg:npm/ticket-test-%s@1.0.0", suffix)
	res, err := db.Exec(`INSERT INTO findings(asset_id, purl, component_name, component_version, eco, cve_id,
		cvss, epss, exploit, asset_weight, risk, priority, status, assignee, fixed_version, first_seen, last_seen)
		VALUES(?,?,?,?,?,?,9.8,0.9,'kev',0.8,90,'P1',?,?,'2.17.1','2026-01-01T00:00:00+08:00','2026-01-01T00:00:00+08:00')`,
		assetID, purl, "ticket-test-"+suffix, "1.0.0", "npm", "CVE-TEST-0001", status, assignee)
	if err != nil {
		t.Fatalf("写入漏洞结论失败：%v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("读取漏洞 ID 失败：%v", err)
	}
	return id
}

func TestEnsureTicketIdempotentAndStatusFlow(t *testing.T) {
	app, db, assetID := newTicketTestApp(t)

	openID := seedTicketFinding(t, db, assetID, "open", "open", "")
	cur, err := app.getFinding(openID)
	if err != nil {
		t.Fatalf("读取漏洞失败：%v", err)
	}

	wantID := fmt.Sprintf("VA-%d-0001", nowT().Year())
	first, created, err := app.ensureTicket(cur, "李维")
	if err != nil {
		t.Fatalf("首次建单失败：%v", err)
	}
	if !created {
		t.Fatal("首次建单应返回 created=true")
	}
	if first.ID != wantID {
		t.Fatalf("工单号应为 %s，实际 %s", wantID, first.ID)
	}
	if first.Status != "fixing" {
		t.Fatalf("open 状态应流转为 fixing，实际 %s", first.Status)
	}
	if first.Assignee != "李维" || first.CreatedBy != "李维" {
		t.Fatalf("责任人应回落到操作人：%+v", first)
	}
	if first.CVEID != "CVE-TEST-0001" || first.AssetID != assetID || first.Priority != "P1" {
		t.Fatalf("工单关联字段不完整：%+v", first)
	}
	if first.CreatedAt == "" || first.UpdatedAt == "" {
		t.Fatalf("工单时间戳不能为空：%+v", first)
	}

	var findingTicket, findingStatus, findingAssignee string
	if err := db.QueryRow(`SELECT ticket_id, status, assignee FROM findings WHERE id = ?`, openID).
		Scan(&findingTicket, &findingStatus, &findingAssignee); err != nil {
		t.Fatalf("读取漏洞状态失败：%v", err)
	}
	if findingTicket != wantID || findingStatus != "fixing" || findingAssignee != "李维" {
		t.Fatalf("漏洞未同步建单结果：ticket=%s status=%s assignee=%s", findingTicket, findingStatus, findingAssignee)
	}

	second, created, err := app.ensureTicket(cur, "王倩")
	if err != nil {
		t.Fatalf("重复建单失败：%v", err)
	}
	if created || second.ID != wantID {
		t.Fatalf("重复建单应幂等：created=%v id=%s", created, second.ID)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM tickets WHERE finding_id = ?`, openID).Scan(&count); err != nil {
		t.Fatalf("统计工单失败：%v", err)
	}
	if count != 1 {
		t.Fatalf("同一漏洞只应有一张工单，实际 %d", count)
	}

	// 已处置的漏洞建单时保留原状态与责任人，序号继续递增
	fixedID := seedTicketFinding(t, db, assetID, "fixed", "fixed", "王倩")
	fixedCur, err := app.getFinding(fixedID)
	if err != nil {
		t.Fatalf("读取已修复漏洞失败：%v", err)
	}
	fixedTicket, created, err := app.ensureTicket(fixedCur, "李维")
	if err != nil || !created {
		t.Fatalf("为已修复漏洞建单失败：created=%v err=%v", created, err)
	}
	if fixedTicket.ID != fmt.Sprintf("VA-%d-0002", nowT().Year()) {
		t.Fatalf("工单序号应递增，实际 %s", fixedTicket.ID)
	}
	if fixedTicket.Status != "fixed" || fixedTicket.Assignee != "王倩" {
		t.Fatalf("已处置状态不应被覆盖：%+v", fixedTicket)
	}
}

func TestFindingPatchSyncsTicket(t *testing.T) {
	app, db, assetID := newTicketTestApp(t)
	findingID := seedTicketFinding(t, db, assetID, "patch", "open", "")

	cur, err := app.getFinding(findingID)
	if err != nil {
		t.Fatalf("读取漏洞失败：%v", err)
	}
	ticket, _, err := app.ensureTicket(cur, "李维")
	if err != nil {
		t.Fatalf("建单失败：%v", err)
	}
	// 把时间戳调到过去，确保 PATCH 后能观察到刷新（同秒内两次写入无法区分）
	const oldTime = "2000-01-01T00:00:00+08:00"
	if _, err := db.Exec(`UPDATE tickets SET updated_at = ? WHERE id = ?`, oldTime, ticket.ID); err != nil {
		t.Fatalf("重置工单时间戳失败：%v", err)
	}

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/findings/"+strconv.FormatInt(findingID, 10),
		strings.NewReader(`{"status":"fixed","assignee":"王倩"}`))
	req.SetPathValue("id", strconv.FormatInt(findingID, 10))
	req = req.WithContext(context.WithValue(req.Context(), ctxKeyUser{}, User{
		Username: "ops", Name: "李维", Role: "operator",
	}))
	rec := httptest.NewRecorder()
	app.handleFindingPatch(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("更新漏洞状态失败：%d %s", rec.Code, rec.Body.String())
	}

	got, found, err := app.ticketRepo().ByFinding(context.Background(), findingID)
	if err != nil || !found {
		t.Fatalf("读取工单失败：found=%v err=%v", found, err)
	}
	if got.ID != ticket.ID {
		t.Fatalf("工单号被改变：%s → %s", ticket.ID, got.ID)
	}
	if got.Status != "fixed" || got.Assignee != "王倩" {
		t.Fatalf("工单未同步漏洞处置：%+v", got)
	}
	if got.UpdatedAt == oldTime || got.UpdatedAt == "" {
		t.Fatalf("同步后 updated_at 应刷新，实际 %q", got.UpdatedAt)
	}

	var findingStatus, findingAssignee string
	if err := db.QueryRow(`SELECT status, assignee FROM findings WHERE id = ?`, findingID).
		Scan(&findingStatus, &findingAssignee); err != nil {
		t.Fatalf("读取漏洞失败：%v", err)
	}
	if findingStatus != "fixed" || findingAssignee != "王倩" {
		t.Fatalf("漏洞状态未更新：status=%s assignee=%s", findingStatus, findingAssignee)
	}
}

func TestHandleTicketsFilterLimitAndRole(t *testing.T) {
	app, db, assetID := newTicketTestApp(t)

	for _, item := range []struct {
		suffix, status string
	}{
		{"ticket-fixing", "open"},
		{"ticket-fixed", "fixed"},
		{"ticket-verified", "verified"},
	} {
		id := seedTicketFinding(t, db, assetID, item.suffix, item.status, "李维")
		cur, err := app.getFinding(id)
		if err != nil {
			t.Fatalf("读取漏洞失败：%v", err)
		}
		if _, _, err := app.ensureTicket(cur, "李维"); err != nil {
			t.Fatalf("建单失败：%v", err)
		}
	}

	call := func(query, role string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tickets"+query, nil)
		req = req.WithContext(context.WithValue(req.Context(), ctxKeyUser{}, User{
			Username: "u", Name: "李维", Role: role,
		}))
		rec := httptest.NewRecorder()
		app.handleTickets(rec, req)
		return rec
	}

	rec := call("?status=fixed", "operator")
	if rec.Code != http.StatusOK {
		t.Fatalf("查询工单失败：%d %s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Items []ports.Ticket `json:"items"`
		Total int            `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("解析工单响应失败：%v", err)
	}
	if payload.Total != 1 || len(payload.Items) != 1 || payload.Items[0].Status != "fixed" {
		t.Fatalf("按状态过滤异常：%+v", payload)
	}

	rec = call("?limit=1", "operator")
	if rec.Code != http.StatusOK {
		t.Fatalf("查询工单失败：%d", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("解析工单响应失败：%v", err)
	}
	if payload.Total != 1 || len(payload.Items) != 1 {
		t.Fatalf("limit 未生效：%+v", payload)
	}

	if rec := call("", "viewer"); rec.Code != http.StatusForbidden {
		t.Fatalf("只读账号应被拒绝，实际 %d", rec.Code)
	}
}

func TestFindingDetailIncludesTicket(t *testing.T) {
	app, db, assetID := newTicketTestApp(t)
	findingID := seedTicketFinding(t, db, assetID, "detail", "open", "")

	cur, err := app.getFinding(findingID)
	if err != nil {
		t.Fatalf("读取漏洞失败：%v", err)
	}
	ticket, _, err := app.ensureTicket(cur, "李维")
	if err != nil {
		t.Fatalf("建单失败：%v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings/"+strconv.FormatInt(findingID, 10), nil)
	req.SetPathValue("id", strconv.FormatInt(findingID, 10))
	req = req.WithContext(context.WithValue(req.Context(), ctxKeyUser{}, User{
		Username: "u", Name: "李维", Role: "operator",
	}))
	rec := httptest.NewRecorder()
	app.handleFindingDetail(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("读取详情失败：%d %s", rec.Code, rec.Body.String())
	}

	var detail struct {
		ID     int64         `json:"id"`
		Ticket *ports.Ticket `json:"ticket"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil {
		t.Fatalf("解析详情失败：%v", err)
	}
	if detail.ID != findingID {
		t.Fatalf("详情 ID 不匹配：%d", detail.ID)
	}
	if detail.Ticket == nil || detail.Ticket.ID != ticket.ID || detail.Ticket.Status != "fixing" {
		t.Fatalf("详情未返回工单：%+v", detail.Ticket)
	}
}
