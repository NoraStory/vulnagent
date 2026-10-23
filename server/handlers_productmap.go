package main

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"vulnagent/server/internal/application/ports"
)

// handleProductMapList 列出产品映射，支持按名称/产品/生态过滤
func (a *App) handleProductMapList(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "admin"); !ok {
		return
	}
	rows, err := a.intelRepo().ProductMapList(r.Context(), strings.TrimSpace(r.URL.Query().Get("q")), 500)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "查询产品映射失败")
		return
	}
	items := make([]productMapping, 0, len(rows))
	for _, m := range rows {
		items = append(items, productMapping{
			Eco:        m.Eco,
			Name:       m.Name,
			Product:    m.Product,
			Confidence: m.Confidence,
			Source:     m.Source,
			UpdatedAt:  m.UpdatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"demo": a.demoMode(), "total": len(items), "items": items})
}

// handleProductMapUpsert 新增或更新映射，保存后立即重新匹配全部资产
func (a *App) handleProductMapUpsert(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "admin"); !ok {
		return
	}
	var req struct {
		Eco        string  `json:"eco"`
		Name       string  `json:"name"`
		Product    string  `json:"product"`
		Confidence float64 `json:"confidence"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	req.Eco = strings.ToLower(strings.TrimSpace(req.Eco))
	req.Name = strings.ToLower(strings.TrimSpace(req.Name))
	req.Product = strings.ToLower(strings.TrimSpace(req.Product))
	if req.Eco == "" || req.Name == "" || req.Product == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "生态、组件名与映射产品不能为空")
		return
	}
	if req.Confidence == 0 {
		req.Confidence = 1.0
	}
	if req.Confidence < 0 || req.Confidence > 1 {
		writeErr(w, http.StatusBadRequest, "bad_request", "置信度需在 0 与 1 之间")
		return
	}

	now := fmtT(nowT())
	if err := a.intelRepo().UpsertProductMapping(r.Context(), ports.ProductMapping{
		Eco:        req.Eco,
		Name:       req.Name,
		Product:    req.Product,
		Confidence: req.Confidence,
		Source:     "manual",
		UpdatedAt:  now,
	}, now); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "保存映射失败")
		return
	}
	rematched, err := a.rematchAllAssets()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "重新匹配失败")
		return
	}
	a.audit(r, "productmap.upsert", req.Eco+"/"+req.Name,
		"映射到 "+req.Product+"，重匹配 "+strconv.Itoa(rematched)+" 台资产")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"mapping": productMapping{Eco: req.Eco, Name: req.Name, Product: req.Product,
			Confidence: req.Confidence, Source: "manual", UpdatedAt: now},
		"rematched": rematched,
	})
}

// handleProductMapDelete 删除映射并重新匹配
func (a *App) handleProductMapDelete(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "admin"); !ok {
		return
	}
	eco := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("eco")))
	name := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("name")))
	if eco == "" || name == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "缺少 eco 或 name")
		return
	}
	if err := a.intelRepo().DeleteProductMapping(r.Context(), eco, name); err != nil {
		if errors.Is(err, ports.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "not_found", "映射不存在")
			return
		}
		writeErr(w, http.StatusInternalServerError, "internal_error", "删除映射失败")
		return
	}
	rematched, err := a.rematchAllAssets()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "重新匹配失败")
		return
	}
	a.audit(r, "productmap.delete", eco+"/"+name, "删除映射，重匹配 "+strconv.Itoa(rematched)+" 台资产")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "rematched": rematched})
}
