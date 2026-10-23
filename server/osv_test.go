package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestOSVScanAssetCreatesFindings(t *testing.T) {
	db, err := openDB(filepath.Join(t.TempDir(), "osv.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败：%v", err)
	}
	defer db.Close()

	if _, err := db.Exec(`INSERT INTO assets(hostname, exposure, tier, source) VALUES('osv-host','internal','normal','agent')`); err != nil {
		t.Fatalf("插入资产失败：%v", err)
	}
	var assetID int64
	if err := db.QueryRow(`SELECT id FROM assets WHERE hostname='osv-host'`).Scan(&assetID); err != nil {
		t.Fatalf("读取资产失败：%v", err)
	}
	if _, err := db.Exec(`INSERT INTO components(asset_id, purl, eco, name, version, vendor, product)
		VALUES(?, 'pkg:golang/golang.org/x/crypto@v0.1.0', 'golang', 'golang.org/x/crypto', 'v0.1.0', 'golang', 'golang.org/x/crypto')`, assetID); err != nil {
		t.Fatalf("插入组件失败：%v", err)
	}

	var gotQuery osvQueryRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotQuery)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"vulns": []map[string]any{
				{
					"id":        "GO-2024-0001",
					"summary":   "crypto 测试漏洞",
					"details":   "测试详情",
					"aliases":   []string{"CVE-2024-9999"},
					"published": "2024-01-02T03:04:05Z",
					"modified":  "2024-02-02T03:04:05Z",
					"severity": []map[string]string{
						{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
					},
					"affected": []map[string]any{
						{
							"package": map[string]string{"ecosystem": "Go", "name": "golang.org/x/crypto"},
							"ranges": []map[string]any{
								{"type": "SEMVER", "events": []map[string]string{
									{"introduced": "0"}, {"fixed": "v0.2.0"},
								}},
							},
						},
					},
				},
			},
		})
	}))
	defer srv.Close()
	t.Setenv("VA_OSV_URL", srv.URL)

	app := &App{db: db}
	res, err := app.osvScanAsset(assetID, "test")
	if err != nil {
		t.Fatalf("OSV 匹配失败：%v", err)
	}
	if res.Created != 1 || res.Vulns != 1 {
		t.Fatalf("结果不符：%+v", res)
	}
	if gotQuery.Package.Ecosystem != "Go" || gotQuery.Package.Name != "golang.org/x/crypto" || gotQuery.Version != "0.1.0" {
		t.Fatalf("查询参数不符：%+v", gotQuery)
	}

	var fixed string
	var cvss float64
	if err := db.QueryRow(`SELECT fixed_version, cvss FROM findings WHERE asset_id = ? AND cve_id = 'CVE-2024-9999'`,
		assetID).Scan(&fixed, &cvss); err != nil {
		t.Fatalf("读取结论失败：%v", err)
	}
	if fixed != "v0.2.0" || cvss < 9 {
		t.Fatalf("结论字段不符：fixed=%s cvss=%.1f", fixed, cvss)
	}
	var product string
	if err := db.QueryRow(`SELECT product FROM cve_affected WHERE cve_id = 'CVE-2024-9999'`).Scan(&product); err != nil {
		t.Fatalf("读取受影响区间失败：%v", err)
	}
	if product != "golang.org/x/crypto" {
		t.Fatalf("受影响产品不符：%s", product)
	}
}
