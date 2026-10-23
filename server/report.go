package main

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"

	"vulnagent/server/internal/application/ports"
	"vulnagent/server/internal/domain/vuln"
)

// cjkFont 报告使用思源黑体（SIL OFL 1.1），随二进制内嵌，部署无外部字体依赖
//
//go:embed assets/fonts/NotoSansSC-VF.ttf
var cjkFont []byte

const reportRowLimit = 300

var priorityRGB = map[string][3]int{
	"P0": {196, 23, 14},
	"P1": {181, 71, 8},
	"P2": {0, 100, 214},
	"P3": {90, 100, 115},
}

type reportFinding struct {
	Priority  string  `json:"priority"`
	CveID     string  `json:"cveId"`
	Title     string  `json:"title"`
	Component string  `json:"component"`
	Version   string  `json:"version"`
	Fixed     string  `json:"fixedVersion"`
	Hostname  string  `json:"hostname"`
	Status    string  `json:"status"`
	Cvss      float64 `json:"cvss"`
	Epss      float64 `json:"epss"`
	Risk      int     `json:"risk"`
}

// reportFilter 报告筛选条件；priority 单独拆出，用于统计不受优先级筛选影响的分布
type reportFilter struct {
	query  ports.ReportFilter
	labels []string
}

func reportFilterFromQuery(r *http.Request) reportFilter {
	query := r.URL.Query()
	priority := query.Get("priority")
	status := query.Get("status")
	keyword := strings.TrimSpace(query.Get("q"))

	labels := make([]string, 0, 3)
	if status != "" {
		labels = append(labels, "状态："+statusLabel(status))
	}
	if keyword != "" {
		labels = append(labels, "关键词："+keyword)
	}
	if priority != "" {
		labels = append([]string{"优先级：" + priority}, labels...)
	}

	return reportFilter{
		query:  ports.ReportFilter{Priority: priority, Status: status, Query: keyword},
		labels: labels,
	}
}

func statusLabel(status string) string { return vuln.StatusLabel(status) }

func (a *App) loadReportFindings(f reportFilter, limit int) ([]reportFinding, error) {
	rows, err := a.findingRepo().ReportRows(context.Background(), f.query, limit)
	if err != nil {
		return nil, err
	}
	items := make([]reportFinding, 0, len(rows))
	for _, it := range rows {
		items = append(items, reportFinding{
			Priority:  it.Priority,
			CveID:     it.CVEID,
			Title:     it.Title,
			Component: it.Component,
			Version:   it.Version,
			Fixed:     it.FixedVersion,
			Hostname:  it.Hostname,
			Status:    it.Status,
			Cvss:      it.CVSS,
			Epss:      it.EPSS,
			Risk:      it.Risk,
		})
	}
	return items, nil
}

// reportStats 返回筛选范围内的总数、涉及资产数与各优先级数量
func (a *App) reportStats(f reportFilter) (int, int, map[string]int, error) {
	total, assets, err := a.findingRepo().ReportTotals(context.Background(), f.query)
	if err != nil {
		return 0, 0, nil, err
	}
	byPriority, err := a.findingRepo().ReportByPriority(context.Background(), f.query)
	if err != nil {
		return 0, 0, nil, err
	}
	return total, assets, byPriority, nil
}

func (a *App) handleFindingReportPDF(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "operator")
	if !ok {
		return
	}
	filter := reportFilterFromQuery(r)
	items, err := a.loadReportFindings(filter, reportRowLimit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "生成报告失败")
		return
	}
	total, assets, byPriority, err := a.reportStats(filter)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "生成报告失败")
		return
	}

	data, err := buildFindingReportPDF(reportMeta{
		GeneratedBy: u.Name,
		GeneratedAt: nowT(),
		FilterText:  strings.Join(filter.labels, " · "),
		Total:       total,
		Assets:      assets,
		ByPriority:  byPriority,
	}, items)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "生成报告失败")
		return
	}

	name := "vulnagent-findings-" + nowT().Format("20060102-1504") + ".pdf"
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
	a.audit(r, "report.export", "findings.pdf", fmt.Sprintf("共 %d 条，展示 %d 条，%s", total, len(items), orDefault(strings.Join(filter.labels, " · "), "全部范围")))
}

func orDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

type reportMeta struct {
	GeneratedBy string
	GeneratedAt time.Time
	FilterText  string
	Total       int
	Assets      int
	ByPriority  map[string]int
}

func buildFindingReportPDF(meta reportMeta, items []reportFinding) ([]byte, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(10, 12, 10)
	pdf.SetAutoPageBreak(true, 16)
	pdf.AddUTF8FontFromBytes("cjk", "", cjkFont)
	pdf.SetFont("cjk", "", 9)
	pdf.SetFooterFunc(func() {
		pdf.SetY(-12)
		pdf.SetFont("cjk", "", 8)
		pdf.SetTextColor(130, 136, 148)
		pdf.CellFormat(0, 6, fmt.Sprintf("VulnAgent · 安全漏洞运维报告 · 第 %d 页", pdf.PageNo()), "", 0, "C", false, 0, "")
	})
	pdf.AddPage()

	// 页头色带
	pdf.SetFillColor(0, 100, 214)
	pdf.Rect(0, 0, 210, 26, "F")
	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont("cjk", "", 17)
	pdf.SetXY(10, 6)
	pdf.CellFormat(0, 8, "安全漏洞运维报告", "", 1, "L", false, 0, "")
	pdf.SetFont("cjk", "", 8.5)
	pdf.SetXY(10, 15.5)
	pdf.CellFormat(0, 5, fmt.Sprintf("生成时间 %s · 生成人 %s", meta.GeneratedAt.Format("2006-01-02 15:04"), meta.GeneratedBy), "", 1, "L", false, 0, "")

	// 概览卡片
	pdf.SetTextColor(30, 33, 38)
	stats := []struct {
		label string
		value string
		rgb   [3]int
	}{
		{"匹配漏洞", fmt.Sprintf("%d", meta.Total), [3]int{30, 33, 38}},
		{"P0 严重", fmt.Sprintf("%d", meta.ByPriority["P0"]), priorityRGB["P0"]},
		{"P1 高危", fmt.Sprintf("%d", meta.ByPriority["P1"]), priorityRGB["P1"]},
		{"P2 中危", fmt.Sprintf("%d", meta.ByPriority["P2"]), priorityRGB["P2"]},
		{"P3 低危", fmt.Sprintf("%d", meta.ByPriority["P3"]), priorityRGB["P3"]},
	}
	y := 31.0
	for i, s := range stats {
		x := 10 + float64(i)*36.5
		pdf.SetFillColor(246, 247, 250)
		pdf.Rect(x, y, 34, 19, "F")
		pdf.SetFont("cjk", "", 8)
		pdf.SetTextColor(110, 118, 130)
		pdf.SetXY(x+3, y+2.5)
		pdf.CellFormat(28, 4.5, s.label, "", 2, "L", false, 0, "")
		pdf.SetFont("cjk", "", 16)
		pdf.SetTextColor(s.rgb[0], s.rgb[1], s.rgb[2])
		pdf.SetXY(x+3, y+7.5)
		pdf.CellFormat(28, 8, s.value, "", 0, "L", false, 0, "")
	}

	// 筛选与范围说明
	pdf.SetDrawColor(229, 229, 234)
	pdf.Line(10, y+22, 200, y+22)
	pdf.SetFont("cjk", "", 8.5)
	pdf.SetTextColor(90, 96, 108)
	pdf.SetXY(10, y+24)
	scope := "筛选：" + orDefault(meta.FilterText, "全部漏洞") + fmt.Sprintf(" · 涉及资产 %d 台", meta.Assets)
	if meta.Total > len(items) {
		scope += fmt.Sprintf(" · 明细仅展示风险分最高的 %d 条", len(items))
	}
	pdf.CellFormat(190, 5, clipToWidth(pdf, scope, 188), "", 1, "L", false, 0, "")

	// 明细表
	pdf.SetY(y + 32)
	drawReportTableHeader(pdf)
	for _, it := range items {
		if pdf.GetY() > 262 {
			pdf.AddPage()
			drawReportTableHeader(pdf)
		}
		drawReportRow(pdf, it)
	}
	if len(items) == 0 {
		pdf.SetFont("cjk", "", 10)
		pdf.SetTextColor(130, 136, 148)
		pdf.SetXY(10, pdf.GetY()+8)
		pdf.CellFormat(190, 8, "当前筛选条件下没有漏洞记录。", "", 1, "C", false, 0, "")
	}

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func drawReportTableHeader(pdf *fpdf.Fpdf) {
	pdf.SetFillColor(242, 242, 247)
	pdf.SetTextColor(70, 76, 88)
	pdf.SetFont("cjk", "", 8)
	pdf.SetX(10)
	pdf.CellFormat(14, 7, "优先级", "", 0, "L", true, 0, "")
	pdf.CellFormat(28, 7, "漏洞编号", "", 0, "L", true, 0, "")
	pdf.CellFormat(110, 7, "漏洞标题", "", 0, "L", true, 0, "")
	pdf.CellFormat(18, 7, "风险分", "", 0, "R", true, 0, "")
	pdf.CellFormat(20, 7, "状态", "", 1, "R", true, 0, "")
}

func drawReportRow(pdf *fpdf.Fpdf, it reportFinding) {
	rgb, ok := priorityRGB[it.Priority]
	if !ok {
		rgb = [3]int{90, 100, 115}
	}

	pdf.SetX(10)
	pdf.SetFont("cjk", "", 8.5)
	pdf.SetTextColor(rgb[0], rgb[1], rgb[2])
	pdf.CellFormat(14, 5.6, it.Priority, "", 0, "L", false, 0, "")

	pdf.SetFont("cjk", "", 8)
	pdf.SetTextColor(110, 118, 130)
	pdf.CellFormat(28, 5.6, it.CveID, "", 0, "L", false, 0, "")

	pdf.SetFont("cjk", "", 9)
	pdf.SetTextColor(30, 33, 38)
	pdf.CellFormat(110, 5.6, clipToWidth(pdf, it.Title, 108), "", 0, "L", false, 0, "")

	pdf.SetFont("cjk", "", 10)
	pdf.SetTextColor(rgb[0], rgb[1], rgb[2])
	pdf.CellFormat(18, 5.6, fmt.Sprintf("%d", it.Risk), "", 0, "R", false, 0, "")

	pdf.SetFont("cjk", "", 8)
	pdf.SetTextColor(110, 118, 130)
	pdf.CellFormat(20, 5.6, statusLabel(it.Status), "", 1, "R", false, 0, "")

	pdf.SetX(24)
	component := strings.TrimSpace(it.Component + " " + it.Version)
	if it.Fixed != "" {
		component += " → " + it.Fixed
	}
	line := fmt.Sprintf("%s · %s · CVSS %.1f · EPSS %.2f", component, it.Hostname, it.Cvss, it.Epss)
	pdf.CellFormat(0, 4.4, clipToWidth(pdf, line, 174), "", 1, "L", false, 0, "")

	pdf.SetDrawColor(238, 238, 243)
	top := pdf.GetY() + 1
	pdf.Line(10, top, 200, top)
	pdf.SetY(top + 1.8)
}

// clipToWidth 按实际渲染宽度截断，超出以省略号结尾
func clipToWidth(pdf *fpdf.Fpdf, s string, maxWidth float64) string {
	s = strings.TrimSpace(s)
	if pdf.GetStringWidth(s) <= maxWidth {
		return s
	}
	runes := []rune(s)
	for len(runes) > 0 {
		runes = runes[:len(runes)-1]
		candidate := string(runes) + "…"
		if pdf.GetStringWidth(candidate) <= maxWidth {
			return candidate
		}
	}
	return ""
}
