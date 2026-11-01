package main

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// 允许的资产关系类型
var allowedRelations = map[string]bool{
	"depends_on":  true,
	"runs_on":     true,
	"member_of":   true,
	"manages":     true,
	"connects_to": true,
}

// handleAssetRelations 返回资产的全部关系
func (a *App) handleAssetRelations(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "viewer"); !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "无效的资产 ID")
		return
	}
	if exists, err := a.assetRepo().HasAsset(r.Context(), id); err != nil || !exists {
		writeErr(w, http.StatusNotFound, "not_found", "资产不存在")
		return
	}
	items, err := a.assetRepo().Relations(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "查询资产关系失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// handleAssetRelationCreate 创建资产关系（operator+）
func (a *App) handleAssetRelationCreate(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
		return
	}
	fromID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "无效的资产 ID")
		return
	}
	var req struct {
		ToAssetID int64  `json:"toAssetId"`
		Relation  string `json:"relation"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	relation := strings.ToLower(strings.TrimSpace(req.Relation))
	if !allowedRelations[relation] {
		writeErr(w, http.StatusBadRequest, "bad_request",
			"关系类型仅支持 depends_on / runs_on / member_of / manages / connects_to")
		return
	}
	if req.ToAssetID <= 0 || req.ToAssetID == fromID {
		writeErr(w, http.StatusBadRequest, "bad_request", "请选择其他资产作为关系目标")
		return
	}
	if exists, err := a.assetRepo().HasAsset(r.Context(), fromID); err != nil || !exists {
		writeErr(w, http.StatusNotFound, "not_found", "源资产不存在")
		return
	}
	if exists, err := a.assetRepo().HasAsset(r.Context(), req.ToAssetID); err != nil || !exists {
		writeErr(w, http.StatusNotFound, "not_found", "目标资产不存在")
		return
	}
	relationID, err := a.assetRepo().CreateRelation(r.Context(), fromID, req.ToAssetID, relation, fmtT(nowT()))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "创建资产关系失败")
		return
	}
	a.audit(r, "asset.relation.create", fmt.Sprintf("asset:%d→%d", fromID, req.ToAssetID), relation)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": relationID})
}

// handleAssetRelationDelete 删除资产关系（operator+）
func (a *App) handleAssetRelationDelete(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "无效的关系 ID")
		return
	}
	if err := a.assetRepo().DeleteRelation(r.Context(), id); err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "关系不存在")
		return
	}
	a.audit(r, "asset.relation.delete", fmt.Sprintf("relation:%d", id), "删除资产关系")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
