package main

import (
	"fmt"
	"net/http"
)

// handleScanBatch 批量复扫（operator+），同一资产受防抖窗口保护
func (a *App) handleScanBatch(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "operator")
	if !ok {
		return
	}
	var req struct {
		AssetIDs []int64 `json:"assetIds"`
		All      bool    `json:"all"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	if !req.All && len(req.AssetIDs) == 0 {
		writeErr(w, http.StatusBadRequest, "bad_request", "需要提供 assetIds 或 all=true")
		return
	}
	if len(req.AssetIDs) > 500 {
		writeErr(w, http.StatusBadRequest, "too_many_assets", "单次最多复扫 500 台资产")
		return
	}

	outcomes, err := a.rescanAssets(req.AssetIDs, req.All, u.Name)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "批量复扫失败")
		return
	}
	scanned, skipped := 0, 0
	created, updated, verified, closed, reopened := 0, 0, 0, 0, 0
	for _, item := range outcomes {
		if item.Skipped {
			skipped++
			continue
		}
		scanned++
		created += item.Created
		updated += item.Updated
		verified += item.Verified
		closed += item.Closed
		reopened += item.Reopened
	}

	target := "全部资产"
	if !req.All {
		target = fmt.Sprintf("%d 台指定资产", len(req.AssetIDs))
	}
	a.audit(r, "scan.batch", target,
		fmt.Sprintf("扫描 %d 台，验证 %d 条，关闭 %d 条，跳过 %d 台", scanned, verified, closed, skipped))

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"scanned":  scanned,
		"skipped":  skipped,
		"created":  created,
		"updated":  updated,
		"verified": verified,
		"closed":   closed,
		"reopened": reopened,
		"items":    outcomes,
	})
}
