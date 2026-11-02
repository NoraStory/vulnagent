package main

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCompressionJSON(t *testing.T) {
	handler := withCompression(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"hello": "world"})
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("JSON 响应应压缩，实际 %q", got)
	}
	if got := rec.Header().Get("Vary"); got != "Accept-Encoding" {
		t.Fatalf("缺少 Vary 头：%q", got)
	}
	reader, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatalf("解压失败：%v", err)
	}
	defer reader.Close()
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("读取解压内容失败：%v", err)
	}
	var payload map[string]string
	if err := json.Unmarshal(body, &payload); err != nil || payload["hello"] != "world" {
		t.Fatalf("解压内容异常：%s err=%v", body, err)
	}
}

func TestCompressionRespectsGzipQuality(t *testing.T) {
	handler := withCompression(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"hello": "world"})
	}))
	cases := []struct {
		header     string
		compressed bool
	}{
		{"gzip;q=0", false},
		{"br, gzip;q=0", false},
		{"br, gzip;q=0.5", true},
		{"identity", false},
		{"*", true},
	}
	for _, item := range cases {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
		req.Header.Set("Accept-Encoding", item.header)
		handler.ServeHTTP(rec, req)
		got := rec.Header().Get("Content-Encoding") == "gzip"
		if got != item.compressed {
			t.Fatalf("Accept-Encoding=%q 期望压缩=%v，实际 %v", item.header, item.compressed, got)
		}
	}
}

func TestCompressionSkipsSSEAndBinary(t *testing.T) {
	cases := []struct {
		name        string
		contentType string
		body        string
	}{
		{"SSE", "text/event-stream", "data: hello\n\n"},
		{"PDF", "application/pdf", "%PDF-1.4"},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			handler := withCompression(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", item.contentType)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(item.body))
				if flusher, ok := w.(http.Flusher); ok {
					flusher.Flush()
				}
			}))
			req := httptest.NewRequest(http.MethodGet, "/api/v1/stream", nil)
			req.Header.Set("Accept-Encoding", "gzip")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if got := rec.Header().Get("Content-Encoding"); got != "" {
				t.Fatalf("%s 不应压缩，实际 %q", item.name, got)
			}
			if rec.Body.String() != item.body {
				t.Fatalf("%s 内容被改写：%q", item.name, rec.Body.String())
			}
		})
	}
}

func TestCompressionStaticAssetsAndStatus(t *testing.T) {
	// JS 静态资源应压缩
	handler := withCompression(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte("console.log('hello world')"))
	}))
	req := httptest.NewRequest(http.MethodGet, "/assets/index.js", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("JS 资源应压缩，实际 %q", rec.Header().Get("Content-Encoding"))
	}

	// 304 不应带压缩头
	handler = withCompression(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	}))
	req = httptest.NewRequest(http.MethodGet, "/assets/index.js", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Header().Get("Content-Encoding") != "" {
		t.Fatalf("304 不应压缩，实际 %q", rec.Header().Get("Content-Encoding"))
	}

	// Range 请求跳过压缩
	handler = withCompression(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte("0123456789"))
	}))
	req = httptest.NewRequest(http.MethodGet, "/assets/index.js", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("Range", "bytes=0-1")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Header().Get("Content-Encoding") != "" || rec.Body.String() != "0123456789" {
		t.Fatalf("Range 请求不应压缩：%q %q", rec.Header().Get("Content-Encoding"), rec.Body.String())
	}
}

func TestCompressionSkipsWhenNotAcceptedOrUpgrade(t *testing.T) {
	handler := withCompression(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}))
	for _, item := range []struct {
		name    string
		headers map[string]string
	}{
		{"未声明 gzip", map[string]string{}},
		{"WebSocket 升级", map[string]string{"Accept-Encoding": "gzip", "Upgrade": "websocket"}},
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
		for key, value := range item.headers {
			req.Header.Set(key, value)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if got := rec.Header().Get("Content-Encoding"); got != "" {
			t.Fatalf("%s 不应压缩，实际 %q", item.name, got)
		}
	}
}
