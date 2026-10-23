package main

import (
	"net/http"
	"strconv"
	"strings"
)

// handleProductMapList 列出产品映射，支持按名称/产品/生态过滤
func (a *App) handleProductMapList(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "admin"); !ok {
		return
	}
	where := "1=1"
	args := []any{}
	if q := strings.TrimSpace(r.URL.Query().Get("q")); q != "" {
		like := "%" + strings.ToLower(q) + "%"
		where = "(lower(name) LIKE ? OR lower(product) LIKE ? OR lower(eco) LIKE ?)"
		args = append(args, like, like, like)
	}
	rows, err := a.db.Query(`SELECT eco, name, product, confidence, source, updated_at
		FROM product_map WHERE `+where+` ORDER BY eco, name LIMIT 500`, args...)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "查询产品映射失败")
		return
	}
	defer rows.Close()
	items := make([]productMapping, 0, 32)
	for rows.Next() {
		var m productMapping
		if err := rows.Scan(&m.Eco, &m.Name, &m.Product, &m.Confidence, &m.Source, &m.UpdatedAt); err != nil {
			continue
		}
		items = append(items, m)
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
	if _, err := a.db.Exec(`INSERT INTO product_map(eco, name, product, confidence, source, updated_at)
		VALUES(?,?,?,?, 'manual', ?)
		ON CONFLICT(eco, name) DO UPDATE SET product = excluded.product,
		confidence = excluded.confidence, source = 'manual', updated_at = excluded.updated_at`,
		req.Eco, req.Name, req.Product, req.Confidence, now); err != nil {
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
	res, err := a.db.Exec(`DELETE FROM product_map WHERE eco = ? AND name = ?`, eco, name)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "删除映射失败")
		return
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		writeErr(w, http.StatusNotFound, "not_found", "映射不存在")
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
