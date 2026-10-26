package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSPAHandlerCacheHeaders(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("<html>app</html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "assets", "app-123.js"), []byte("console.log(1)"), 0o644); err != nil {
		t.Fatal(err)
	}
	handler := spaHandler(root)

	cases := []struct {
		path      string
		wantCache string
	}{
		{"/", "no-store, must-revalidate"},
		{"/index.html", "no-store, must-revalidate"},
		{"/assets/app-123.js", "public, max-age=31536000, immutable"},
		{"/assets/fallback/route", "no-store, must-revalidate"},
	}
	for _, item := range cases {
		req := httptest.NewRequest(http.MethodGet, item.path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s 状态码异常：%d headers=%v body=%q", item.path, rec.Code, rec.Header(), rec.Body.String())
		}
		if got := rec.Header().Get("Cache-Control"); got != item.wantCache {
			t.Fatalf("%s 缓存头应为 %q，实际 %q", item.path, item.wantCache, got)
		}
		if item.path == "/assets/app-123.js" && !strings.Contains(rec.Body.String(), "console.log") {
			t.Fatalf("静态资源内容异常：%s", rec.Body.String())
		}
	}
}
