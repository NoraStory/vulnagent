package main

import (
	"path/filepath"
	"testing"
)

func TestReconcileFindingStates(t *testing.T) {
	db, err := openDB(filepath.Join(t.TempDir(), "reconcile.db"))
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

	mustExec(`INSERT INTO assets(hostname, exposure, tier, source) VALUES('demo-01','internal','normal','agent')`)
	var assetID int64
	if err := db.QueryRow(`SELECT id FROM assets WHERE hostname = 'demo-01'`).Scan(&assetID); err != nil {
		t.Fatalf("读取资产失败：%v", err)
	}

	mustExec(`INSERT INTO cves(cve_id, title, cvss_score, epss, exploit_state, fixed_version)
		VALUES('CVE-TEST-0001','测试用漏洞',9.8,0.9,'kev','2.17.1')`)
	mustExec(`INSERT INTO cve_affected(cve_id, product, version_start_incl, version_end_excl, fixed_version)
		VALUES('CVE-TEST-0001','log4j-core','2.0.0','2.15.0','2.17.1')`)

	const purl = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
	mustExec(`INSERT INTO components(asset_id, purl, eco, name, version, product)
		VALUES(?,?,?,?,?,?)`, assetID, purl, "maven", "log4j-core", "2.14.1", "log4j-core")
	mustExec(`INSERT INTO findings(asset_id, purl, component_name, component_version, eco, cve_id, cvss, epss,
		exploit, asset_weight, risk, priority, status, fixed_version, first_seen, last_seen)
		VALUES(?,?,?,?,?,?,9.8,0.9,'kev',0.6,99,'P0','fixing','2.17.1','','')`,
		assetID, purl, "log4j-core", "2.14.1", "maven", "CVE-TEST-0001")

	// 1. 旧版本仍受影响：保持 fixing
	app := &App{db: db}
	res, err := app.reconcileFindingStates(assetID, "测试")
	if err != nil {
		t.Fatalf("首次复扫失败：%v", err)
	}
	if res.Kept != 1 || res.Verified != 0 {
		t.Fatalf("旧版本应收敛为 1 条仍受影响，实际 %+v", res)
	}

	// 2. 组件升级到修复版本：自动 verified
	mustExec(`UPDATE components SET version = '2.17.1', purl = ? WHERE asset_id = ?`,
		"pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1", assetID)
	res, err = app.reconcileFindingStates(assetID, "测试")
	if err != nil {
		t.Fatalf("升级后复扫失败：%v", err)
	}
	if res.Verified != 1 {
		t.Fatalf("升级后应验证 1 条，实际 %+v", res)
	}
	var status string
	if err := db.QueryRow(`SELECT status FROM findings WHERE asset_id = ?`, assetID).Scan(&status); err != nil {
		t.Fatalf("读取状态失败：%v", err)
	}
	if status != "verified" {
		t.Fatalf("状态应为 verified，实际 %s", status)
	}

	// 3. 版本回退：重新打开
	mustExec(`UPDATE components SET version = '2.14.1' WHERE asset_id = ? AND name = 'log4j-core'`, assetID)
	res, err = app.reconcileFindingStates(assetID, "测试")
	if err != nil {
		t.Fatalf("回退后复扫失败：%v", err)
	}
	if res.Reopened != 1 {
		t.Fatalf("版本回退后应重新打开 1 条，实际 %+v", res)
	}
	if err := db.QueryRow(`SELECT status FROM findings WHERE asset_id = ? AND cve_id = 'CVE-TEST-0001'`, assetID).
		Scan(&status); err != nil {
		t.Fatalf("读取状态失败：%v", err)
	}
	if status != "open" {
		t.Fatalf("回退后状态应为 open，实际 %s", status)
	}

	// 4. 组件被移除：自动 closed
	mustExec(`INSERT INTO components(asset_id, purl, eco, name, version, product)
		VALUES(?,?,?,?,?,?)`, assetID, "pkg:npm/lodash@4.17.20", "npm", "lodash", "4.17.20", "lodash")
	mustExec(`INSERT INTO findings(asset_id, purl, component_name, component_version, eco, cve_id, cvss, epss,
		exploit, asset_weight, risk, priority, status, fixed_version, first_seen, last_seen)
		VALUES(?,?,?,?,?,?,9.1,0.2,'poc',0.6,80,'P1','open','4.17.21','','')`,
		assetID, "pkg:npm/lodash@4.17.20", "lodash", "4.17.20", "npm", "CVE-TEST-0002")
	mustExec(`DELETE FROM components WHERE asset_id = ? AND name = 'lodash'`, assetID)

	res, err = app.reconcileFindingStates(assetID, "测试")
	if err != nil {
		t.Fatalf("移除组件后复扫失败：%v", err)
	}
	if res.Closed != 1 {
		t.Fatalf("组件移除后应关闭 1 条，实际 %+v", res)
	}
}
