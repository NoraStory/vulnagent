package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/go-pdf/fpdf"
)

func TestBuildFindingReportPDF(t *testing.T) {
	meta := reportMeta{
		GeneratedBy: "张启明",
		GeneratedAt: nowT(),
		FilterText:  "优先级：P0 · 状态：待处理",
		Total:       2,
		Assets:      1,
		ByPriority:  map[string]int{"P0": 2},
	}
	items := []reportFinding{
		{Priority: "P0", CveID: "CVE-2021-44228", Title: "Apache Log4j2 JNDI 远程代码执行（Log4Shell）",
			Component: "log4j-core", Version: "2.14.1", Fixed: "2.17.1", Hostname: "web-01",
			Status: "open", Cvss: 10, Epss: 0.94, Risk: 99},
		{Priority: "P0", CveID: "CVE-2023-4863", Title: "libwebp 堆缓冲区溢出",
			Component: "libwebp7", Version: "1.2.4", Fixed: "1.3.2", Hostname: "web-02",
			Status: "fixing", Cvss: 8.8, Epss: 0.72, Risk: 90},
	}
	data, err := buildFindingReportPDF(meta, items)
	if err != nil {
		t.Fatalf("生成 PDF 失败: %v", err)
	}
	if !bytes.HasPrefix(data, []byte("%PDF-")) {
		t.Fatalf("不是合法 PDF，前 8 字节: %q", data[:8])
	}
	if len(data) < 4000 {
		t.Fatalf("PDF 过小，可能未写入内容: %d 字节", len(data))
	}
}

func TestClipToWidth(t *testing.T) {
	pdf := newCJKPDF()
	pdf.AddPage()
	pdf.SetFont("cjk", "", 9)

	short := "libwebp 堆缓冲区溢出"
	if got := clipToWidth(pdf, short, 110); got != short {
		t.Fatalf("未超宽不应截断，got %q", got)
	}
	long := "Apache Log4j2 JNDI 远程代码执行（Log4Shell）漏洞的完整描述文本"
	got := clipToWidth(pdf, long, 60)
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("超宽应截断并加省略号，got %q", got)
	}
	if pdf.GetStringWidth(got) > 60 {
		t.Fatalf("截断后仍超出宽度: %.1fmm", pdf.GetStringWidth(got))
	}
}

// newCJKPDF 创建带内嵌中文字体的文档，供测试与报告共用构造参数
func newCJKPDF() *fpdf.Fpdf {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(10, 12, 10)
	pdf.AddUTF8FontFromBytes("cjk", "", cjkFont)
	pdf.SetFont("cjk", "", 9)
	return pdf
}
