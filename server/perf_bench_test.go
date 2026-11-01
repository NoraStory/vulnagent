package main

// 性能基准与压测夹具：
//   - go test -bench . -run '^$' ./server        → 微基准（匹配/复扫/批量写入/列表/接口）
//   - $env:VA_LOAD=1; go test -run TestLoadProfile -v ./server → HTTP 并发压测
//
// 数据全部写入真实的 SQLite 临时库，走真实仓储与评分链路，不使用演示数据。

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"vulnagent/server/internal/application/ports"
	"vulnagent/server/internal/application/scan"
	"vulnagent/server/internal/domain/asset"
)

type perfFixture struct {
	app      *App
	db       *sql.DB
	dir      string
	assetIDs []int64
	assets   int
	compsPer int
	vulnLibs int
	findings int
	cves     int
	ranges   int
	mappings int
	seedTime time.Duration
	dbBytes  int64
}

var (
	perfOnce sync.Once
	perfFix  *perfFixture
	perfErr  error
)

// TestMain 统一回收压测库，避免临时目录残留。
func TestMain(m *testing.M) {
	code := m.Run()
	if perfFix != nil && perfFix.dir != "" {
		_ = perfFix.db.Close()
		_ = os.RemoveAll(perfFix.dir)
	}
	os.Exit(code)
}

func perfScale(key string, def int) int {
	if raw := os.Getenv(key); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			return v
		}
	}
	return def
}

func sharedPerfFixture(tb testing.TB) *perfFixture {
	tb.Helper()
	perfOnce.Do(func() {
		perfFix, perfErr = newPerfFixture()
	})
	if perfErr != nil {
		tb.Fatalf("构建压测数据失败：%v", perfErr)
	}
	return perfFix
}

func newPerfFixture() (*perfFixture, error) {
	// 匹配过程会逐资产打印 INFO 日志，压测时降到 WARN 避免干扰计时
	slog.SetLogLoggerLevel(slog.LevelWarn)

	dir, err := os.MkdirTemp("", "vulnagent-perf-*")
	if err != nil {
		return nil, err
	}
	dbPath := filepath.Join(dir, "perf.db")
	db, err := openDB(dbPath)
	if err != nil {
		return nil, err
	}
	f := &perfFixture{
		app:      &App{db: db},
		db:       db,
		dir:      dir,
		assets:   perfScale("VA_BENCH_ASSETS", 800),
		compsPer: perfScale("VA_BENCH_COMPS", 120),
		vulnLibs: perfScale("VA_BENCH_VULN_LIBS", 40),
		cves:     perfScale("VA_BENCH_CVES", 20000),
		ranges:   perfScale("VA_BENCH_RANGES", 8000),
		mappings: perfScale("VA_BENCH_MAPPINGS", 2000),
	}
	if f.vulnLibs > f.compsPer {
		return nil, fmt.Errorf("vulnLibs(%d) 不能超过 compsPer(%d)", f.vulnLibs, f.compsPer)
	}
	started := time.Now()
	if err := f.seedIntel(); err != nil {
		return nil, err
	}
	if err := f.seedAssets(); err != nil {
		return nil, err
	}
	f.seedTime = time.Since(started)
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM findings`).Scan(&f.findings); err != nil {
		return nil, err
	}
	if info, err := os.Stat(dbPath); err == nil {
		f.dbBytes = info.Size()
	}
	return f, nil
}

// seedIntel 写入 CVE、受影响区间与产品映射（静态字典，批量事务）
func (f *perfFixture) seedIntel() error {
	tx, err := f.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	cveStmt, err := tx.Prepare(`INSERT OR IGNORE INTO cves(cve_id, title, cvss_score, epss, exploit_state, fixed_version)
		VALUES(?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer cveStmt.Close()
	for i := 0; i < f.vulnLibs; i++ {
		score := 4.0 + float64(i%50)/10
		if _, err := cveStmt.Exec(fmt.Sprintf("CVE-BENCH-%04d", i), "压测漏洞样本",
			score, float64(i%90)/100, "none", "9.0.0"); err != nil {
			return err
		}
	}
	for i := 0; i < f.cves; i++ {
		if _, err := cveStmt.Exec(fmt.Sprintf("CVE-SEED-%05d", i), "背景情报样本",
			3.0+float64(i%70)/10, 0.01, "none", "2.0.0"); err != nil {
			return err
		}
	}

	rangeStmt, err := tx.Prepare(`INSERT OR IGNORE INTO cve_affected(cve_id, product, version_start_incl, version_end_excl, fixed_version)
		VALUES(?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer rangeStmt.Close()
	for i := 0; i < f.vulnLibs; i++ {
		if _, err := rangeStmt.Exec(fmt.Sprintf("CVE-BENCH-%04d", i), fmt.Sprintf("lib-%03d", i),
			"1.0.0", "9.0.0", "9.0.0"); err != nil {
			return err
		}
	}
	for i := 0; i < f.ranges; i++ {
		if _, err := rangeStmt.Exec(fmt.Sprintf("CVE-SEED-%05d", i%f.cves), fmt.Sprintf("extra-lib-%04d", i),
			"0.1.0", "2.0.0", "2.0.0"); err != nil {
			return err
		}
	}

	mapStmt, err := tx.Prepare(`INSERT OR IGNORE INTO product_map(eco, name, product, confidence, source, updated_at)
		VALUES(?,?,?,1.0,'seed','')`)
	if err != nil {
		return err
	}
	defer mapStmt.Close()
	for i := 0; i < f.mappings; i++ {
		if _, err := mapStmt.Exec("deb", fmt.Sprintf("pkg-%04d", i), fmt.Sprintf("lib-%03d", i%f.vulnLibs)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// seedAssets 写入资产与组件，并通过真实匹配链路生成漏洞结论
func (f *perfFixture) seedAssets() error {
	ctx := context.Background()
	repo := f.app.assetRepo()
	seenAt := fmtT(nowT())
	for i := 0; i < f.assets; i++ {
		id, err := repo.UpsertReported(ctx, fmt.Sprintf("perf-%04d", i),
			fmt.Sprintf("10.%d.%d.%d", i/65536%256, i/256%256, i%256),
			"linux", "Ubuntu 22.04", "agent", "online", seenAt)
		if err != nil {
			return err
		}
		comps := make([]asset.Component, 0, f.compsPer)
		for j := 0; j < f.compsPer; j++ {
			name := fmt.Sprintf("lib-%03d", j)
			comps = append(comps, asset.Component{
				PURL:    fmt.Sprintf("pkg:npm/%s@1.5.0", name),
				Eco:     "npm",
				Name:    name,
				Version: "1.5.0",
				Product: name,
			})
		}
		if err := repo.ReplaceComponents(ctx, id, comps); err != nil {
			return err
		}
		f.assetIDs = append(f.assetIDs, id)
	}

	svc := f.app.scanService(defaultPolicy())
	for _, id := range f.assetIDs {
		if _, err := svc.MatchAsset(id); err != nil {
			return err
		}
	}
	return nil
}

func (f *perfFixture) info(tb testing.TB) {
	tb.Helper()
	tb.Logf("DATA assets=%d components=%d findings=%d cves=%d ranges=%d mappings=%d db=%.1fMB seed=%s",
		f.assets, f.assets*f.compsPer, f.findings, f.cves+f.vulnLibs, f.ranges+f.vulnLibs,
		f.mappings, float64(f.dbBytes)/(1024*1024), f.seedTime.Round(time.Millisecond))
}

// ---------- 微基准 ----------

// BenchmarkMatchAsset 对比情报快照缓存与逐次查库的匹配开销
func BenchmarkMatchAsset(b *testing.B) {
	f := sharedPerfFixture(b)
	f.info(b)
	policy := defaultPolicy()
	assetID := f.assetIDs[0]
	cached := f.app.scanService(policy)
	direct := &scan.Service{
		Assets:   f.app.assetRepo(),
		Intel:    f.app.intelRepo(),
		Findings: f.app.findingRepo(),
		Policy:   policy,
	}
	b.Run("snapshot_cache", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := cached.MatchAsset(assetID); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("direct_db", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := direct.MatchAsset(assetID); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkReconcile 对比复扫时逐条查区间与内存快照的差异
func BenchmarkReconcile(b *testing.B) {
	f := sharedPerfFixture(b)
	policy := defaultPolicy()
	assetID := f.assetIDs[0]
	cached := f.app.scanService(policy)
	direct := &scan.Service{
		Assets:   f.app.assetRepo(),
		Intel:    f.app.intelRepo(),
		Findings: f.app.findingRepo(),
		Policy:   policy,
	}
	b.Run("snapshot_cache", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := cached.Reconcile(assetID, "压测"); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("direct_db", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := direct.Reconcile(assetID, "压测"); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkUpsertMatches 对比单事务批量写入与逐条写入
func BenchmarkUpsertMatches(b *testing.B) {
	f := sharedPerfFixture(b)
	repo := f.app.findingRepo()
	ctx := context.Background()
	const rows = 200
	inputs := make([]ports.MatchInput, 0, rows)
	now := fmtT(nowT())
	for i := 0; i < rows; i++ {
		inputs = append(inputs, ports.MatchInput{
			AssetID: f.assetIDs[1],
			Component: asset.Component{
				PURL: fmt.Sprintf("pkg:npm/bench-%03d@1.0.0", i), Eco: "npm",
				Name: fmt.Sprintf("bench-%03d", i), Version: "1.0.0",
			},
			CVEID: fmt.Sprintf("CVE-SEED-%05d", i), CVSS: 7.5, EPSS: 0.2, Exploit: "none",
			AssetWeight: 0.8, Risk: 72, Priority: "P1", Breakdown: "[]", Now: now,
		})
	}
	b.Run("batch_tx", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := repo.UpsertMatches(ctx, inputs); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("single_row", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			for _, in := range inputs {
				if _, err := repo.UpsertMatch(ctx, in); err != nil {
					b.Fatal(err)
				}
			}
		}
	})
}

// BenchmarkOverviewTrend 对比每天一次分组查询与一次读取后内存聚合
func BenchmarkOverviewTrend(b *testing.B) {
	f := sharedPerfFixture(b)
	repo := f.app.statsRepo()
	now := nowT()
	b.Run("query_per_day", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			for d := 0; d < 14; d++ {
				before := fmtT(now.AddDate(0, 0, -d))
				if _, err := repo.PriorityBefore(context.Background(), before); err != nil {
					b.Fatal(err)
				}
			}
		}
	})
	b.Run("single_scan", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			seens, err := repo.FindingFirstSeen(context.Background())
			if err != nil {
				b.Fatal(err)
			}
			_ = buildPriorityTrend(seens, now)
		}
	})
}

// BenchmarkHTTPHandlers 测量主要读接口的处理器开销（含 JSON 序列化）
func BenchmarkHTTPHandlers(b *testing.B) {
	f := sharedPerfFixture(b)
	mux := http.NewServeMux()
	f.app.routes(mux)
	assetID := f.assetIDs[len(f.assetIDs)/2]
	cases := []struct{ name, target string }{
		{"overview", "/api/v1/overview"},
		{"findings_default", "/api/v1/findings"},
		{"findings_status", "/api/v1/findings?status=open"},
		{"findings_query", "/api/v1/findings?q=lib-010"},
		{"assets_list", "/api/v1/assets"},
		{"asset_detail", fmt.Sprintf("/api/v1/assets/%d", assetID)},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				req := httptest.NewRequest(http.MethodGet, c.target, nil)
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, req)
				if rec.Code != http.StatusOK {
					b.Fatalf("状态码 %d", rec.Code)
				}
			}
		})
	}
}

// ---------- HTTP 并发压测 ----------

type loadResult struct {
	name     string
	workers  int
	requests int
	qps      float64
	p50      time.Duration
	p95      time.Duration
	p99      time.Duration
	avgBody  int
	errors   int
}

func runLoad(name string, h http.Handler, target string, workers int, dur time.Duration) loadResult {
	deadline := time.Now().Add(dur)
	var mu sync.Mutex
	lat := make([]time.Duration, 0, 4096)
	var errs, bodyBytes int64
	var wg sync.WaitGroup
	start := time.Now()
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := make([]time.Duration, 0, 512)
			var lerrs, lbytes int64
			for time.Now().Before(deadline) {
				req := httptest.NewRequest(http.MethodGet, target, nil)
				rec := httptest.NewRecorder()
				t0 := time.Now()
				h.ServeHTTP(rec, req)
				local = append(local, time.Since(t0))
				if rec.Code != http.StatusOK {
					lerrs++
				}
				lbytes += int64(rec.Body.Len())
			}
			mu.Lock()
			lat = append(lat, local...)
			errs += lerrs
			bodyBytes += lbytes
			mu.Unlock()
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	res := loadResult{name: name, workers: workers, errors: int(errs), requests: len(lat)}
	if len(lat) == 0 {
		return res
	}
	res.qps = float64(len(lat)) / elapsed.Seconds()
	res.p50 = percentile(lat, 0.50)
	res.p95 = percentile(lat, 0.95)
	res.p99 = percentile(lat, 0.99)
	res.avgBody = int(bodyBytes / int64(len(lat)))
	return res
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	idx := int(float64(len(sorted)-1) * p)
	if idx < 0 {
		idx = 0
	}
	return sorted[idx]
}

// TestLoadProfile 多并发档位的读接口压测；默认跳过，VA_LOAD=1 时执行。
func TestLoadProfile(t *testing.T) {
	if os.Getenv("VA_LOAD") != "1" {
		t.Skip("设置 VA_LOAD=1 后执行 HTTP 压测")
	}
	f := sharedPerfFixture(t)
	f.info(t)
	dur := time.Duration(perfScale("VA_LOAD_SECS", 3)) * time.Second

	mux := http.NewServeMux()
	f.app.routes(mux)

	// 情报快照常驻内存占用：同库新建 App，关闭 GC 后统计加载期分配量
	fresh := &App{db: f.db}
	oldGC := debug.SetGCPercent(-1)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if _, err := fresh.cachedIntelRepo().CVEMeta(context.Background()); err != nil {
		t.Fatalf("加载情报快照失败：%v", err)
	}
	if _, err := fresh.cachedIntelRepo().AffectedByProduct(context.Background()); err != nil {
		t.Fatalf("加载区间快照失败：%v", err)
	}
	if _, err := fresh.cachedIntelRepo().ProductMappings(context.Background()); err != nil {
		t.Fatalf("加载映射快照失败：%v", err)
	}
	runtime.ReadMemStats(&after)
	debug.SetGCPercent(oldGC)
	t.Logf("SNAPSHOT alloc=%.1fMB (cves=%d ranges=%d mappings=%d)",
		float64(after.TotalAlloc-before.TotalAlloc)/(1024*1024),
		f.cves+f.vulnLibs, f.ranges+f.vulnLibs, f.mappings)

	assetID := f.assetIDs[len(f.assetIDs)/2]
	cases := []struct{ name, target string }{
		{"overview", "/api/v1/overview"},
		{"findings_default", "/api/v1/findings"},
		{"findings_status", "/api/v1/findings?status=open"},
		{"findings_query", "/api/v1/findings?q=lib-010"},
		{"assets_list", "/api/v1/assets"},
		{"asset_detail", fmt.Sprintf("/api/v1/assets/%d", assetID)},
	}
	for _, workers := range []int{1, 8, 32} {
		for _, c := range cases {
			res := runLoad(c.name, mux, c.target, workers, dur)
			t.Logf("LOAD %-16s workers=%2d qps=%8.1f p50=%6s p95=%6s p99=%6s body=%5dB errors=%d",
				res.name, res.workers, res.qps,
				res.p50.Round(time.Microsecond), res.p95.Round(time.Microsecond),
				res.p99.Round(time.Microsecond), res.avgBody, res.errors)
		}
	}

	// gzip 收益：同一接口原始与压缩后的响应体大小
	raw := httptest.NewRecorder()
	mux.ServeHTTP(raw, httptest.NewRequest(http.MethodGet, "/api/v1/overview", nil))
	gz := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/overview", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	withCompression(mux).ServeHTTP(gz, req)
	t.Logf("GZIP overview raw=%dB gzip=%dB encoding=%s", raw.Body.Len(), gz.Body.Len(),
		gz.Header().Get("Content-Encoding"))
}
