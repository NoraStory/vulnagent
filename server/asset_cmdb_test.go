package main

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func newAssetCMDBTestApp(t *testing.T) (*App, func(query string, args ...any) int64) {
	t.Helper()
	db, err := openDB(filepath.Join(t.TempDir(), "asset-cmdb.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败：%v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	scalar := func(query string, args ...any) int64 {
		t.Helper()
		var value int64
		if err := db.QueryRow(query, args...).Scan(&value); err != nil {
			t.Fatalf("执行查询失败：%v", err)
		}
		return value
	}
	return &App{db: db}, scalar
}

func newAssetImportRequest(t *testing.T, csvBody, strategy string, dryRun bool) (*http.Request, *httptest.ResponseRecorder) {
	t.Helper()
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", "assets.csv")
	if err != nil {
		t.Fatalf("构造上传失败：%v", err)
	}
	if _, err := part.Write([]byte(csvBody)); err != nil {
		t.Fatalf("写入 CSV 失败：%v", err)
	}
	_ = writer.WriteField("strategy", strategy)
	if dryRun {
		_ = writer.WriteField("dryRun", "true")
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("关闭表单失败：%v", err)
	}

	req := httptest.NewRequest("POST", "/api/v1/assets/import", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req = req.WithContext(context.WithValue(req.Context(), ctxKeyUser{}, User{Username: "admin", Name: "管理员", Role: "admin"}))
	return req, httptest.NewRecorder()
}

func decodeAssetImportReport(t *testing.T, rec *httptest.ResponseRecorder) assetImportReport {
	t.Helper()
	if rec.Code != 200 {
		t.Fatalf("导入返回 %d：%s", rec.Code, rec.Body.String())
	}
	var report assetImportReport
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatalf("解析导入结果失败：%v", err)
	}
	return report
}

func TestAssetImportDryRunDoesNotWrite(t *testing.T) {
	app, scalar := newAssetCMDBTestApp(t)
	csvBody := "\uFEFF主机名,IP,业务系统,标签,序列号\nweb-01,10.0.0.11,交易系统,prod|核心,SN-001\n"

	req, rec := newAssetImportRequest(t, csvBody, "update", true)
	app.handleAssetImport(rec, req)
	report := decodeAssetImportReport(t, rec)

	if !report.DryRun || report.Created != 1 || report.Total != 1 {
		t.Fatalf("预览结果异常：%+v", report)
	}
	if total := scalar(`SELECT COUNT(*) FROM assets`); total != 0 {
		t.Fatalf("预览模式不应写入资产，实际 %d", total)
	}
}

func TestAssetImportCreateThenUpdate(t *testing.T) {
	app, scalar := newAssetCMDBTestApp(t)
	csvBody := "\uFEFF主机名,IP,业务系统,标签,序列号\nweb-01,10.0.0.11,交易系统,prod|核心,SN-001\n"

	req, rec := newAssetImportRequest(t, csvBody, "update", false)
	app.handleAssetImport(rec, req)
	report := decodeAssetImportReport(t, rec)
	if report.Created != 1 || report.Errors != 0 {
		t.Fatalf("首次导入结果异常：%+v", report)
	}
	assetID := report.Items[0].AssetID
	if assetID == 0 {
		t.Fatal("首次导入应返回资产 ID")
	}
	if total := scalar(`SELECT COUNT(*) FROM assets`); total != 1 {
		t.Fatalf("应新增 1 台资产，实际 %d", total)
	}
	if tags := scalar(`SELECT COUNT(*) FROM asset_tags WHERE asset_id = ?`, assetID); tags != 2 {
		t.Fatalf("标签应写入 2 个，实际 %d", tags)
	}

	// 第二次导入：更新业务系统并补充标签
	csvBody2 := "\uFEFF主机名,IP,业务系统,标签\nweb-01,10.0.0.12,支付系统,核心|重要\n"
	req2, rec2 := newAssetImportRequest(t, csvBody2, "update", false)
	app.handleAssetImport(rec2, req2)
	report2 := decodeAssetImportReport(t, rec2)
	if report2.Updated != 1 {
		t.Fatalf("第二次导入应更新 1 行：%+v", report2)
	}
	if total := scalar(`SELECT COUNT(*) FROM assets`); total != 1 {
		t.Fatalf("更新不应新增资产，实际 %d", total)
	}

	detail, err := app.assetRepo().Detail(context.Background(), assetID)
	if err != nil {
		t.Fatalf("读取资产失败：%v", err)
	}
	if detail.BusinessSystem != "支付系统" || detail.IP != "10.0.0.12" {
		t.Fatalf("资产字段未更新：%+v", detail)
	}
	if len(detail.Tags) != 3 {
		t.Fatalf("标签应合并为 3 个，实际 %v", detail.Tags)
	}
}

func TestAssetImportSkipStrategy(t *testing.T) {
	app, _ := newAssetCMDBTestApp(t)
	csvBody := "主机名,IP\nweb-01,10.0.0.11\n"

	req, rec := newAssetImportRequest(t, csvBody, "update", false)
	app.handleAssetImport(rec, req)
	if report := decodeAssetImportReport(t, rec); report.Created != 1 {
		t.Fatalf("首次导入失败：%+v", report)
	}

	req2, rec2 := newAssetImportRequest(t, "主机名,IP\nweb-01,10.0.0.99\n", "skip", false)
	app.handleAssetImport(rec2, req2)
	report := decodeAssetImportReport(t, rec2)
	if report.Skipped != 1 || report.Updated != 0 {
		t.Fatalf("跳过策略结果异常：%+v", report)
	}

	detail, err := app.assetRepo().Detail(context.Background(), report.Items[0].AssetID)
	if err != nil {
		t.Fatalf("读取资产失败：%v", err)
	}
	if detail.IP != "10.0.0.11" {
		t.Fatalf("跳过策略不应修改资产，实际 IP=%s", detail.IP)
	}
}

func TestAssetImportRejectsUnknownHeader(t *testing.T) {
	app, _ := newAssetCMDBTestApp(t)
	req, rec := newAssetImportRequest(t, "未知列A,未知列B\n1,2\n", "update", true)
	app.handleAssetImport(rec, req)
	if rec.Code != 400 {
		t.Fatalf("未识别表头应返回 400，实际 %d：%s", rec.Code, rec.Body.String())
	}
}

func TestAssetCSVHeaderAliases(t *testing.T) {
	cases := map[string]string{
		"主机名":       "hostname",
		"Host_Name": "hostname",
		"IP 地址":     "ip",
		"业务系统":      "businessSystem",
		"业务":        "businessSystem",
		"实例ID":      "instanceId",
		"标签":        "tags",
	}
	for header, want := range cases {
		got, ok := assetCSVHeaderIndex[normalizeAssetHeader(header)]
		if !ok || got != want {
			t.Fatalf("表头 %q 期望 %s，实际 %s（ok=%v）", header, want, got, ok)
		}
	}
}

func TestSplitAssetTags(t *testing.T) {
	got := splitAssetTags("prod|核心, 重要、测试 ; ")
	want := []string{"prod", "核心", "重要", "测试"}
	if len(got) != len(want) {
		t.Fatalf("标签解析异常：%v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("标签第 %d 项期望 %s，实际 %s", i, want[i], got[i])
		}
	}
}
