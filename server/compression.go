package main

import (
	"compress/gzip"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// gzipPool 复用压缩器，降低高频接口的分配开销
var gzipPool = sync.Pool{
	New: func() any {
		writer, _ := gzip.NewWriterLevel(io.Discard, gzip.BestSpeed)
		return writer
	},
}

// gzipResponseWriter 在首次写响应头时根据 Content-Type 决定是否压缩。
type gzipResponseWriter struct {
	http.ResponseWriter
	writer   *gzip.Writer
	compress bool
	decided  bool
}

func (w *gzipResponseWriter) decide(code int) {
	if w.decided {
		return
	}
	w.decided = true
	if code < 200 || code == http.StatusNoContent || code == http.StatusNotModified {
		return
	}
	header := w.Header()
	if header.Get("Content-Encoding") != "" {
		return
	}
	contentType := header.Get("Content-Type")
	w.compress = compressibleContentType(contentType)
	if w.compress {
		header.Del("Content-Length")
		header.Set("Content-Encoding", "gzip")
		header.Add("Vary", "Accept-Encoding")
		w.writer = gzipPool.Get().(*gzip.Writer)
		w.writer.Reset(w.ResponseWriter)
	}
}

// compressibleContentType 只压缩文本类响应；SSE、字体、图片、PDF 等保持原样。
func compressibleContentType(contentType string) bool {
	if strings.HasPrefix(contentType, "text/event-stream") {
		return false
	}
	for _, prefix := range []string{
		"application/json",
		"application/javascript",
		"application/xml",
		"application/manifest+json",
		"text/",
		"image/svg+xml",
	} {
		if strings.HasPrefix(contentType, prefix) {
			return true
		}
	}
	return false
}

func (w *gzipResponseWriter) WriteHeader(code int) {
	w.decide(code)
	w.ResponseWriter.WriteHeader(code)
}

func (w *gzipResponseWriter) Write(data []byte) (int, error) {
	if !w.decided {
		w.WriteHeader(http.StatusOK)
	}
	if w.compress && w.writer != nil {
		return w.writer.Write(data)
	}
	return w.ResponseWriter.Write(data)
}

func (w *gzipResponseWriter) Flush() {
	if !w.decided {
		w.WriteHeader(http.StatusOK)
	}
	if w.writer != nil {
		_ = w.writer.Flush()
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Unwrap 让 http.ResponseController 能访问底层连接（SSE/WebSocket）
func (w *gzipResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *gzipResponseWriter) close() {
	if w.writer == nil {
		return
	}
	_ = w.writer.Close()
	w.writer.Reset(io.Discard)
	gzipPool.Put(w.writer)
	w.writer = nil
}

// acceptsGzip 解析 Accept-Encoding；gzip;q=0 表示客户端明确拒绝压缩
func acceptsGzip(header string) bool {
	for _, part := range strings.Split(header, ",") {
		fields := strings.Split(strings.TrimSpace(part), ";")
		coding := strings.ToLower(strings.TrimSpace(fields[0]))
		if coding != "gzip" && coding != "*" {
			continue
		}
		quality := 1.0
		for _, param := range fields[1:] {
			kv := strings.SplitN(strings.TrimSpace(param), "=", 2)
			if len(kv) == 2 && strings.EqualFold(strings.TrimSpace(kv[0]), "q") {
				if v, err := strconv.ParseFloat(strings.TrimSpace(kv[1]), 64); err == nil {
					quality = v
				}
			}
		}
		if quality > 0 {
			return true
		}
	}
	return false
}

// withCompression 压缩 API 与静态资源中的文本响应；SSE、WebSocket、Range 与二进制下载自动跳过。
func withCompression(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead ||
			r.Header.Get("Upgrade") != "" ||
			r.Header.Get("Range") != "" ||
			!acceptsGzip(r.Header.Get("Accept-Encoding")) {
			next.ServeHTTP(w, r)
			return
		}
		writer := &gzipResponseWriter{ResponseWriter: w}
		defer writer.close()
		next.ServeHTTP(writer, r)
	})
}
