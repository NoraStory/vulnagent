package main

import (
	"path/filepath"
	"testing"
)

func TestProductMappingEnablesMatch(t *testing.T) {
	db, err := openDB(filepath.Join(t.TempDir(), "pmap.db"))
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
	if err := db.QueryRow(`SELECT id FROM assets WHERE hostname='demo-01'`).Scan(&assetID); err != nil {
		t.Fatalf("读取资产失败：%v", err)
	}

	mustExec(`INSERT INTO cves(cve_id, title, cvss_score, epss, exploit_state, fixed_version)
		VALUES('CVE-TEST-REQ','requests 代理凭据泄露',6.1,0.09,'none','2.31.0')`)
	mustExec(`INSERT INTO cve_affected(cve_id, product, version_start_incl, version_end_excl, fixed_version)
		VALUES('CVE-TEST-REQ','requests','2.3.0','2.31.0','2.31.0')`)
	mustExec(`INSERT INTO components(asset_id, purl, eco, name, version, vendor, product)
		VALUES(?,'pkg:deb/debian/python3-requests@2.25.1','deb','python3-requests','2.25.1','debian','python3-requests')`,
		assetID)

	app := &App{db: db}

	// 没有映射时：包名与产品名不一致，匹配不到
	if created, _, err := app.matchAssetFindings(defaultPolicy(), assetID); err != nil {
		t.Fatalf("首次匹配失败：%v", err)
	} else if created != 0 {
		t.Fatalf("无映射时不应命中，实际新增 %d 条", created)
	}

	// 加入映射后应命中，并标记为映射推断
	mustExec(`INSERT INTO product_map(eco, name, product, confidence, source, updated_at)
		VALUES('deb','python3-requests','requests',1.0,'manual','')`)
	created, _, err := app.matchAssetFindings(defaultPolicy(), assetID)
	if err != nil {
		t.Fatalf("映射后匹配失败：%v", err)
	}
	if created != 1 {
		t.Fatalf("映射后应新增 1 条，实际 %d", created)
	}
	var inferred int
	if err := db.QueryRow(`SELECT inferred FROM findings WHERE asset_id = ? AND cve_id = 'CVE-TEST-REQ'`, assetID).
		Scan(&inferred); err != nil {
		t.Fatalf("读取结论失败：%v", err)
	}
	if inferred != 1 {
		t.Fatalf("映射命中的结论应标记 inferred=1，实际 %d", inferred)
	}
}

func TestEnsureProductMap(t *testing.T) {
	db, err := openDB(filepath.Join(t.TempDir(), "pmap-seed.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败：%v", err)
	}
	defer db.Close()

	inserted, err := ensureProductMap(db)
	if err != nil {
		t.Fatalf("写入内置映射失败：%v", err)
	}
	if inserted != len(builtinMappings) {
		t.Fatalf("应写入 %d 条内置映射，实际 %d", len(builtinMappings), inserted)
	}
	again, err := ensureProductMap(db)
	if err != nil {
		t.Fatalf("二次写入失败：%v", err)
	}
	if again != 0 {
		t.Fatalf("重复执行不应再次写入，实际 %d", again)
	}
}
