package main

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"vulnagent/server/internal/application/ports"
)

// 治理待办默认时间窗：失联 7 天、暴露面变化 30 天
const (
	governanceStaleDays  = 7
	governanceChangeDays = 30
)

func governanceCutoffs(r *http.Request) (string, string) {
	staleDays := governanceStaleDays
	changeDays := governanceChangeDays
	if v, err := strconv.Atoi(r.URL.Query().Get("days")); err == nil && v >= 1 && v <= 365 {
		staleDays = v
	}
	if v, err := strconv.Atoi(r.URL.Query().Get("changeDays")); err == nil && v >= 1 && v <= 365 {
		changeDays = v
	}
	stale := fmtT(nowT().Add(-time.Duration(staleDays) * 24 * time.Hour))
	change := fmtT(nowT().Add(-time.Duration(changeDays) * 24 * time.Hour))
	return stale, change
}

// handleGovernanceSummary 返回四类治理待办数量
func (a *App) handleGovernanceSummary(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "viewer"); !ok {
		return
	}
	staleCutoff, changeCutoff := governanceCutoffs(r)
	summary, err := a.governanceRepo().Summary(r.Context(), staleCutoff, changeCutoff)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "统计治理待办失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"summary": summary, "staleCutoff": staleCutoff, "changeCutoff": changeCutoff,
	})
}

// handleGovernanceTodos 按类型分页返回治理待办
func (a *App) handleGovernanceTodos(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "viewer"); !ok {
		return
	}
	typ := strings.TrimSpace(r.URL.Query().Get("type"))
	switch typ {
	case "owner_missing", "stale", "duplicate", "exposure_changed":
	default:
		writeErr(w, http.StatusBadRequest, "bad_request", "type 仅支持 owner_missing / stale / duplicate / exposure_changed")
		return
	}
	page, size, offset := pageParams(r)
	staleCutoff, changeCutoff := governanceCutoffs(r)
	items, total, err := a.governanceRepo().List(r.Context(), typ, staleCutoff, changeCutoff, size, offset)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "查询治理待办失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"type": typ, "total": total, "page": page, "pageSize": size, "items": items,
	})
}

// assetBatchRequest 批量更新资产档案（治理页使用）
type assetBatchRequest struct {
	IDs   []int64 `json:"ids"`
	Patch struct {
		Owner          *string `json:"owner"`
		OwnerEmail     *string `json:"ownerEmail"`
		Department     *string `json:"department"`
		BusinessSystem *string `json:"businessSystem"`
		Status         *string `json:"status"`
		Tier           *string `json:"tier"`
		Env            *string `json:"env"`
	} `json:"patch"`
}

// handleAssetBatch 批量分配责任人 / 归档资产（operator+）
func (a *App) handleAssetBatch(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "operator")
	if !ok {
		return
	}
	var req assetBatchRequest
	if err := readJSON(r, &req); err != nil || len(req.IDs) == 0 {
		writeErr(w, http.StatusBadRequest, "bad_request", "请提供需要更新的资产 ID 列表")
		return
	}
	if len(req.IDs) > 200 {
		writeErr(w, http.StatusBadRequest, "bad_request", "单次最多批量更新 200 台资产")
		return
	}
	updates := map[string]string{}
	add := func(key string, value *string) {
		if value != nil {
			updates[key] = strings.TrimSpace(*value)
		}
	}
	add("owner", req.Patch.Owner)
	add("ownerEmail", req.Patch.OwnerEmail)
	add("department", req.Patch.Department)
	add("businessSystem", req.Patch.BusinessSystem)
	add("status", req.Patch.Status)
	add("tier", req.Patch.Tier)
	add("env", req.Patch.Env)
	if len(updates) == 0 {
		writeErr(w, http.StatusBadRequest, "bad_request", "请至少提供一个要更新的字段")
		return
	}
	if status, exists := updates["status"]; exists {
		switch status {
		case "active", "maintenance", "retired":
		default:
			writeErr(w, http.StatusBadRequest, "bad_request", "状态仅支持 active / maintenance / retired")
			return
		}
	}
	if tier, exists := updates["tier"]; exists {
		switch tier {
		case "core", "important", "normal":
		default:
			writeErr(w, http.StatusBadRequest, "bad_request", "业务等级仅支持 core / important / normal")
			return
		}
	}
	if business, exists := updates["businessSystem"]; exists && business != "" {
		if tier, err := a.businessRepo().GetTier(r.Context(), business); err == nil {
			_ = a.businessRepo().Upsert(r.Context(), ports.BusinessSystem{Name: business, Tier: tier}, fmtT(nowT()))
		}
	}

	updated := 0
	unchanged := 0
	failed := make([]map[string]any, 0)
	for _, id := range req.IDs {
		changes, err := a.assetRepo().UpdateFields(r.Context(), id, updates, u.Name, "governance")
		if err != nil {
			failed = append(failed, map[string]any{"id": id, "error": err.Error()})
			continue
		}
		if len(changes) == 0 {
			unchanged++
		} else {
			updated++
		}
	}
	a.audit(r, "asset.batch_update", "assets",
		fmt.Sprintf("更新 %d 台，未变化 %d，失败 %d，字段 %s", updated, unchanged, len(failed), changeSummaryFromMap(updates)))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "updated": updated, "unchanged": unchanged, "failed": failed,
	})
}

func changeSummaryFromMap(updates map[string]string) string {
	keys := make([]string, 0, len(updates))
	for key := range updates {
		keys = append(keys, key)
	}
	return strings.Join(keys, ",")
}
