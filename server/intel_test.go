package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestSyncCVEFromAPI(t *testing.T) {
	db, err := openDB(filepath.Join(t.TempDir(), "intel.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败：%v", err)
	}
	defer db.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "test-key" {
			http.Error(w, `{"success":false}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("page") != "1" {
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "data": []any{}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"data": []map[string]any{
				{
					"cve_id":       "CVE-2022-26134",
					"title":        "Atlassian Confluence OGNL 注入",
					"description":  "演示数据：Confluence 服务器存在 OGNL 注入。",
					"cvss_vector":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					"cwe_id":       917,
					"cwe_cn":       "表达式语言注入",
					"published_at": "Thu, 02 Jun 2022 10:00:00 GMT",
					"updated_at":   "Mon, 02 Jun 2025 10:00:00 GMT",
					"pocs":         []string{"https://example.com/poc/26134"},
				},
				{
					"cve_id":       "CVE-2024-3400",
					"title":        "PAN-OS 命令注入",
					"description":  "演示数据：GlobalProtect 存在命令注入。",
					"cvss_vector":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
					"cwe_id":       77,
					"cwe_cn":       "命令注入",
					"published_at": "Mon, 01 Apr 2024 08:00:00 GMT",
					"updated_at":   "Mon, 02 Jun 2025 11:00:00 GMT",
					"pocs":         []string{},
				},
			},
		})
	}))
	defer srv.Close()

	client := newCVEClient(srv.URL, "test-key")
	res, err := syncCVEFromAPI(context.Background(), db, client, 3)
	if err != nil {
		t.Fatalf("同步失败：%v", err)
	}
	if res.Inserted != 2 || res.Updated != 0 {
		t.Fatalf("首次同步应新增 2 条，实际 %+v", res)
	}

	var score float64
	var severity string
	if err := db.QueryRow(`SELECT cvss_score, severity FROM cves WHERE cve_id = 'CVE-2022-26134'`).
		Scan(&score, &severity); err != nil {
		t.Fatalf("读取 CVE 失败：%v", err)
	}
	if score != 9.8 || severity != "critical" {
		t.Fatalf("CVSS 计算结果不符：score=%.1f severity=%s", score, severity)
	}
	var s2 float64
	if err := db.QueryRow(`SELECT cvss_score FROM cves WHERE cve_id = 'CVE-2024-3400'`).Scan(&s2); err != nil {
		t.Fatalf("读取 CVE 失败：%v", err)
	}
	if s2 != 10.0 {
		t.Fatalf("S:C 向量应得 10.0，实际 %.1f", s2)
	}

	var pocCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM cve_poc WHERE cve_id = 'CVE-2022-26134'`).Scan(&pocCount); err != nil {
		t.Fatalf("读取 POC 失败：%v", err)
	}
	if pocCount != 1 {
		t.Fatalf("应写入 1 条 POC，实际 %d", pocCount)
	}

	// 游标生效：再次同步不会重复写入
	res2, err := syncCVEFromAPI(context.Background(), db, client, 3)
	if err != nil {
		t.Fatalf("二次同步失败：%v", err)
	}
	if res2.Inserted != 0 || res2.Updated != 0 {
		t.Fatalf("游标未生效，二次同步写入 %+v", res2)
	}

	var status string
	if err := db.QueryRow(`SELECT status FROM sync_cursors WHERE source = 'cve'`).Scan(&status); err != nil {
		t.Fatalf("读取同步状态失败：%v", err)
	}
	if status != "ok" {
		t.Fatalf("同步状态应为 ok，实际 %s", status)
	}
}

func TestImportBundle(t *testing.T) {
	db, err := openDB(filepath.Join(t.TempDir(), "bundle.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败：%v", err)
	}
	defer db.Close()

	bundle := map[string]any{
		"version": 1,
		"source":  "cve",
		"items": []map[string]any{
			{
				"cve_id":       "CVE-2023-34362",
				"title":        "MOVEit Transfer SQL 注入",
				"description":  "演示数据：MOVEit Transfer 存在 SQL 注入。",
				"cvss_vector":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				"cwe_id":       89,
				"cwe_cn":       "SQL 注入",
				"published_at": "Thu, 01 Jun 2023 00:00:00 GMT",
				"updated_at":   "Tue, 02 Jul 2024 00:00:00 GMT",
				"pocs":         []string{"https://example.com/poc/34362"},
			},
		},
	}
	raw, _ := json.Marshal(bundle)
	path := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("写入情报包失败：%v", err)
	}

	res, err := importBundle(db, path)
	if err != nil {
		t.Fatalf("导入失败：%v", err)
	}
	if res.Inserted != 1 {
		t.Fatalf("应导入 1 条，实际 %+v", res)
	}
	var score float64
	if err := db.QueryRow(`SELECT cvss_score FROM cves WHERE cve_id = 'CVE-2023-34362'`).Scan(&score); err != nil {
		t.Fatalf("读取导入结果失败：%v", err)
	}
	if score != 9.8 {
		t.Fatalf("导入后分值应为 9.8，实际 %.1f", score)
	}
}
