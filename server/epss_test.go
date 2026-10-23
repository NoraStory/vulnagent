package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestImportEPSS(t *testing.T) {
	db, err := openDB(filepath.Join(t.TempDir(), "epss.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败：%v", err)
	}
	defer db.Close()

	mustExec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.Exec(query, args...); err != nil {
			t.Fatalf("执行 SQL 失败：%v", err)
		}
	}

	mustExec(`INSERT INTO assets(hostname, exposure, tier, source) VALUES('demo-01','public','core','agent')`)
	mustExec(`INSERT INTO cves(cve_id, title, cvss_score, epss, exploit_state, fixed_version)
		VALUES('CVE-TEST-0001','测试漏洞',9.8,0.1,'kev','2.0.0')`)
	mustExec(`INSERT INTO cves(cve_id, title, cvss_score, epss, exploit_state, fixed_version)
		VALUES('CVE-TEST-0002','不受影响的漏洞',5.0,0.0,'none','')`)
	mustExec(`INSERT INTO findings(asset_id, purl, component_name, component_version, eco, cve_id, cvss, epss,
		exploit, asset_weight, risk, priority, status, fixed_version, first_seen, last_seen)
		VALUES(1,'pkg:deb/debian/demo@1.0','demo','1.0','deb','CVE-TEST-0001',9.8,0.1,'kev',0.6,0,'P3','open','2.0.0','','')`)

	var before int
	if err := db.QueryRow(`SELECT risk FROM findings WHERE cve_id = 'CVE-TEST-0001'`).Scan(&before); err != nil {
		t.Fatalf("读取初始风险分失败：%v", err)
	}

	csv := strings.NewReader(`cve,epss,percentile
CVE-TEST-0001,0.9,0.99
CVE-NOT-EXIST,0.5,0.5
CVE-TEST-0002,not-a-number,0.1
`)
	app := &App{db: db}
	res, err := app.importEPSS(csv)
	if err != nil {
		t.Fatalf("导入失败：%v", err)
	}
	if res.Rows != 3 || res.Matched != 1 || res.Unmatched != 1 || res.Invalid != 1 {
		t.Fatalf("导入统计不符：%+v", res)
	}
	if res.Recomputed != 1 {
		t.Fatalf("应重算 1 条漏洞，实际 %d", res.Recomputed)
	}

	var epss float64
	if err := db.QueryRow(`SELECT epss FROM cves WHERE cve_id = 'CVE-TEST-0001'`).Scan(&epss); err != nil {
		t.Fatalf("读取 EPSS 失败：%v", err)
	}
	if epss != 0.9 {
		t.Fatalf("EPSS 应更新为 0.9，实际 %.2f", epss)
	}

	var findingEpss float64
	var after int
	if err := db.QueryRow(`SELECT epss, risk FROM findings WHERE cve_id = 'CVE-TEST-0001'`).Scan(&findingEpss, &after); err != nil {
		t.Fatalf("读取漏洞失败：%v", err)
	}
	if findingEpss != 0.9 {
		t.Fatalf("漏洞快照 EPSS 应同步为 0.9，实际 %.2f", findingEpss)
	}
	if after <= before {
		t.Fatalf("EPSS 升高后风险分应上升，before=%d after=%d", before, after)
	}

	var status string
	var count int
	if err := db.QueryRow(`SELECT status, count FROM sync_cursors WHERE source = 'epss'`).Scan(&status, &count); err != nil {
		t.Fatalf("读取同步状态失败：%v", err)
	}
	if status != "ok" || count != 1 {
		t.Fatalf("同步状态不符：status=%s count=%d", status, count)
	}
}

func TestSyncEPSSFromRemoteGzip(t *testing.T) {
	db, err := openDB(filepath.Join(t.TempDir(), "epss-remote.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败：%v", err)
	}
	defer db.Close()

	if _, err := db.Exec(`INSERT INTO cves(cve_id, title, cvss_score, epss, exploit_state)
		VALUES('CVE-REMOTE-1','远程 EPSS 测试',7.5,0,'none')`); err != nil {
		t.Fatalf("插入 CVE 失败：%v", err)
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write([]byte("cve,epss,percentile\nCVE-REMOTE-1,0.42,0.97\n"))
	_ = gz.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(buf.Bytes())
	}))
	defer srv.Close()

	t.Setenv("VA_EPSS_URL", srv.URL+"/epss_scores-current.csv.gz")
	app := &App{db: db}
	res, err := app.syncEPSSFromRemote(context.Background())
	if err != nil {
		t.Fatalf("在线刷新失败：%v", err)
	}
	if res.Mode != "epss-remote" || res.Matched != 1 {
		t.Fatalf("刷新结果不符：%+v", res)
	}
	var epss float64
	if err := db.QueryRow(`SELECT epss FROM cves WHERE cve_id = 'CVE-REMOTE-1'`).Scan(&epss); err != nil {
		t.Fatalf("读取 EPSS 失败：%v", err)
	}
	if epss != 0.42 {
		t.Fatalf("EPSS 应更新为 0.42，实际 %.2f", epss)
	}
}
