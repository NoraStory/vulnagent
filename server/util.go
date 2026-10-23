package main

import (
	"encoding/json"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
	"time"

	"vulnagent/server/internal/platform/clock"
)

// 时间与时区统一由 platform/clock 提供，这里保留包内别名以减少改动。
var cst = clock.Zone()

func nowT() time.Time { return clock.Now() }

func fmtT(t time.Time) string { return clock.Format(t) }

func parseT(s string) (time.Time, error) { return clock.Parse(s) }

// hoursSince 返回某时间字符串距今的小时数，解析失败返回 0
func hoursSince(s string) float64 { return clock.HoursSince(s) }

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

type errBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type apiError struct {
	Error errBody `json:"error"`
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, apiError{Error: errBody{Code: code, Message: msg}})
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	return dec.Decode(v)
}

// pageParams 解析分页参数，page 默认 1、pageSize 默认 20 且上限 100
func pageParams(r *http.Request) (page, size, offset int) {
	page, _ = strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	size, _ = strconv.Atoi(r.URL.Query().Get("pageSize"))
	if size < 1 {
		size = 20
	}
	if size > 100 {
		size = 100
	}
	return page, size, (page - 1) * size
}

func round1(f float64) float64 { return math.Round(f*10) / 10 }

func round2(f float64) float64 { return math.Round(f*100) / 100 }

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
