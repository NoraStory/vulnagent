package main

import (
	"fmt"
	"net/http"
	"strings"

	"vulnagent/server/internal/application/ports"
)

// handleBusinessSystems 返回业务系统列表及资产数量
func (a *App) handleBusinessSystems(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "viewer"); !ok {
		return
	}
	items, err := a.businessRepo().List(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "查询业务系统失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// handleBusinessSystemUpsert 更新业务系统重要性并重算风险分（仅管理员）
func (a *App) handleBusinessSystemUpsert(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "admin"); !ok {
		return
	}
	name := strings.TrimSpace(r.PathValue("name"))
	if name == "" || len([]rune(name)) > 128 {
		writeErr(w, http.StatusBadRequest, "bad_request", "业务系统名称不能为空且不超过 128 字")
		return
	}
	var req struct {
		Tier        string `json:"tier"`
		Owner       string `json:"owner"`
		Description string `json:"description"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	tier := strings.ToLower(strings.TrimSpace(req.Tier))
	switch tier {
	case "core", "important", "normal":
	default:
		writeErr(w, http.StatusBadRequest, "bad_request", "业务系统重要性仅支持 core / important / normal")
		return
	}
	item := ports.BusinessSystem{
		Name:        name,
		Tier:        tier,
		Owner:       strings.TrimSpace(req.Owner),
		Description: strings.TrimSpace(req.Description),
	}
	if err := a.businessRepo().Upsert(r.Context(), item, fmtT(nowT())); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "保存业务系统失败")
		return
	}
	recomputed, err := a.recomputeFindings(loadPolicy(a.db))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "业务系统已保存，但重算风险分失败")
		return
	}
	a.audit(r, "business.update", "business:"+name,
		fmt.Sprintf("重要性 %s，重算 %d 条漏洞", tier, recomputed))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "businessSystem": item, "recomputed": recomputed})
}

// handleBusinessSystemDelete 删除业务系统登记并重算
func (a *App) handleBusinessSystemDelete(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "admin"); !ok {
		return
	}
	name := strings.TrimSpace(r.PathValue("name"))
	if err := a.businessRepo().Delete(r.Context(), name); err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "业务系统不存在")
		return
	}
	recomputed, _ := a.recomputeFindings(loadPolicy(a.db))
	a.audit(r, "business.delete", "business:"+name, fmt.Sprintf("重算 %d 条漏洞", recomputed))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "recomputed": recomputed})
}
