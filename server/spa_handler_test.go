package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 未匹配的 /api 路径必须返回 JSON 404，不能回退到 index.html
func TestSPAHandlerAPIFallback(t *testing.T) {
	dir := t.TempDir()
	index := "<!doctype html><html><body>app</body></html>"
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte(index), 0o644); err != nil {
		t.Fatalf("写入 index.html 失败：%v", err)
	}
	handler := spaHandler(dir)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/not-exist?x=1", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("未知接口应返回 404，实际 %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("未知接口应返回 JSON，实际 Content-Type=%q", ct)
	}
	if !strings.Contains(rec.Body.String(), "not_found") {
		t.Fatalf("错误体缺少 code：%s", rec.Body.String())
	}

	// 前端路由仍回退到 index.html
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/findings/42", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "app") {
		t.Fatalf("前端路由应回退到 index.html：status=%d body=%q", rec.Code, rec.Body.String())
	}
	if cache := rec.Header().Get("Cache-Control"); !strings.Contains(cache, "no-store") {
		t.Fatalf("index.html 不应缓存，实际 %q", cache)
	}

	// 静态资源正常命中
	if err := os.MkdirAll(filepath.Join(dir, "assets"), 0o755); err != nil {
		t.Fatalf("创建 assets 失败：%v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "assets", "app.js"), []byte("console.log(1)"), 0o644); err != nil {
		t.Fatalf("写入静态资源失败：%v", err)
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/assets/app.js", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "console.log") {
		t.Fatalf("静态资源应直接返回：status=%d body=%q", rec.Code, rec.Body.String())
	}
	if cache := rec.Header().Get("Cache-Control"); !strings.Contains(cache, "immutable") {
		t.Fatalf("/assets 应长期缓存，实际 %q", cache)
	}
}
