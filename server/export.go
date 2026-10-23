package main

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

const exportRowLimit = 5000

// handleFindingsCSV 按当前筛选导出 CSV（UTF-8 BOM，便于 Excel 直接打开）
func (a *App) handleFindingsCSV(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
		return
	}
	filter := reportFilterFromQuery(r)
	items, err := a.loadReportFindings(filter, exportRowLimit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "导出失败")
		return
	}

	name := "vulnagent-findings-" + nowT().Format("20060102-1504") + ".csv"
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte{0xEF, 0xBB, 0xBF})

	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"优先级", "CVE", "标题", "组件", "当前版本", "修复版本", "资产", "CVSS", "EPSS", "风险分", "状态"})
	for _, it := range items {
		_ = cw.Write([]string{
			it.Priority, it.CveID, it.Title, it.Component, it.Version, it.Fixed, it.Hostname,
			strconv.FormatFloat(it.Cvss, 'f', 1, 64),
			strconv.FormatFloat(it.Epss, 'f', 2, 64),
			strconv.Itoa(it.Risk),
			statusLabel(it.Status),
		})
	}
	cw.Flush()

	a.audit(r, "report.export_csv", "findings.csv",
		fmt.Sprintf("导出 %d 条（上限 %d），%s", len(items), exportRowLimit,
			orDefault(strings.Join(filter.labels, " · "), "全部范围")))
}

// handleFindingsJSON 按当前筛选导出 JSON（便于自动化对接）
func (a *App) handleFindingsJSON(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
		return
	}
	filter := reportFilterFromQuery(r)
	items, err := a.loadReportFindings(filter, exportRowLimit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "导出失败")
		return
	}
	total, assets, byPriority, err := a.reportStats(filter)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "导出失败")
		return
	}
	a.audit(r, "report.export_json", "findings.json",
		fmt.Sprintf("导出 %d 条（上限 %d），%s", len(items), exportRowLimit,
			orDefault(strings.Join(filter.labels, " · "), "全部范围")))
	writeJSON(w, http.StatusOK, map[string]any{
		"demo":       a.demoMode(),
		"total":      total,
		"assets":     assets,
		"byPriority": byPriority,
		"limit":      exportRowLimit,
		"items":      items,
	})
}
