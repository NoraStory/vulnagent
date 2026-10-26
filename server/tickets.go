package main

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"vulnagent/server/internal/application/ports"
)

// ensureTicket 幂等地为漏洞创建本地工单：已存在则直接返回既有工单。
// 控制面自建工单，不依赖外部 ITSM；状态与漏洞处置状态保持同步。
func (a *App) ensureTicket(cur findingItem, actor string) (ports.Ticket, bool, error) {
	ctx := context.Background()
	if existing, found, err := a.ticketRepo().ByFinding(ctx, cur.ID); err != nil {
		return ports.Ticket{}, false, err
	} else if found {
		return existing, false, nil
	}

	maxSeq, _ := a.findingRepo().NextTicketSeq(ctx)
	ticketID := fmt.Sprintf("VA-%d-%04d", nowT().Year(), maxSeq+1)
	status := cur.Status
	assignee := cur.Assignee
	if assignee == "" {
		assignee = actor
	}
	if status == "open" || status == "triaged" {
		status = "fixing"
	}
	if err := a.findingRepo().CreateTicket(ctx, cur.ID, ticketID, status, assignee); err != nil {
		return ports.Ticket{}, false, err
	}

	now := fmtT(nowT())
	ticket := ports.Ticket{
		ID:        ticketID,
		FindingID: cur.ID,
		CVEID:     cur.CveID,
		AssetID:   cur.Asset.ID,
		Priority:  cur.Priority,
		Status:    status,
		Assignee:  assignee,
		CreatedBy: actor,
		Note:      "控制面本地工单，需在变更窗口内完成修复并复扫验证",
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := a.ticketRepo().Create(ctx, ticket); err != nil {
		return ports.Ticket{}, false, err
	}
	return ticket, true, nil
}

// handleTickets 列出本地工单，可按状态过滤
func (a *App) handleTickets(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	items, err := a.ticketRepo().List(r.Context(), r.URL.Query().Get("status"), limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "查询工单失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}
