package main

import (
	"path/filepath"
	"testing"
	"time"
)

func TestRescanAssetDebounce(t *testing.T) {
	db, err := openDB(filepath.Join(t.TempDir(), "scan.db"))
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

	mustExec(`INSERT INTO assets(hostname, exposure, tier, source) VALUES('scan-01','public','core','agent')`)
	var assetID int64
	if err := db.QueryRow(`SELECT id FROM assets WHERE hostname='scan-01'`).Scan(&assetID); err != nil {
		t.Fatalf("读取资产失败：%v", err)
	}
	mustExec(`INSERT INTO cves(cve_id, title, cvss_score, epss, exploit_state, fixed_version)
		VALUES('CVE-TEST-SCAN','扫描测试漏洞',9.8,0.9,'kev','2.0.0')`)
	mustExec(`INSERT INTO cve_affected(cve_id, product, version_start_incl, version_end_excl, fixed_version)
		VALUES('CVE-TEST-SCAN','demo-lib','1.0.0','2.0.0','2.0.0')`)
	mustExec(`INSERT INTO components(asset_id, purl, eco, name, version, product)
		VALUES(?,'pkg:deb/debian/demo-lib@1.5.0','deb','demo-lib','1.5.0','demo-lib')`, assetID)

	app := &App{db: db, lastScan: map[int64]time.Time{}, scanDebounce: time.Hour}

	first, err := app.rescanAsset(assetID, "测试")
	if err != nil {
		t.Fatalf("首次复扫失败：%v", err)
	}
	if first.Skipped || first.Created != 1 {
		t.Fatalf("首次复扫应新建 1 条，实际 %+v", first)
	}

	second, err := app.rescanAsset(assetID, "测试")
	if err != nil {
		t.Fatalf("二次复扫失败：%v", err)
	}
	if !second.Skipped {
		t.Fatalf("防抖窗口内应跳过，实际 %+v", second)
	}

	// 关闭防抖后可再次执行
	app.scanDebounce = 0
	third, err := app.rescanAsset(assetID, "测试")
	if err != nil {
		t.Fatalf("关闭防抖后复扫失败：%v", err)
	}
	if third.Skipped || third.Updated != 1 {
		t.Fatalf("关闭防抖后应更新 1 条，实际 %+v", third)
	}

	outcomes, err := app.rescanAssets(nil, true, "测试")
	if err != nil {
		t.Fatalf("批量复扫失败：%v", err)
	}
	if len(outcomes) != 1 || outcomes[0].AssetID != assetID {
		t.Fatalf("批量复扫结果不符：%+v", outcomes)
	}
}
