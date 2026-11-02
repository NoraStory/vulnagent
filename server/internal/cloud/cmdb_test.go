package cloud

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// auto 模式跟随 next：游标、相对地址、完整同源地址都能继续拉取
func TestCMDBListAutoFollowsNext(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		switch r.URL.Query().Get("cursor") {
		case "":
			_, _ = w.Write([]byte(`{"items":[{"hostname":"host-a"}],"next":"page-2"}`))
		case "page-2":
			_, _ = w.Write([]byte(`{"items":[{"hostname":"host-b"}],"next":"/cmdb?cursor=page-3"}`))
		case "page-3":
			_, _ = w.Write([]byte(`{"items":[{"hostname":"host-c"}],"next":""}`))
		default:
			t.Errorf("意外游标：%s", r.URL.RawQuery)
		}
	}))
	defer server.Close()

	items, err := cmdbProvider{}.List(context.Background(), Config{URL: server.URL + "/cmdb"})
	if err != nil {
		t.Fatalf("拉取失败：%v", err)
	}
	if len(items) != 3 || items[0].Hostname != "host-a" || items[2].Hostname != "host-c" {
		t.Fatalf("应拉取 3 台实例：%+v", items)
	}
	if requests != 3 {
		t.Fatalf("应请求 3 次，实际 %d", requests)
	}
}

// page 模式按页码 + 页大小翻页，并以 total 提前停止
func TestCMDBListPageMode(t *testing.T) {
	var pages []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pages = append(pages, r.URL.Query().Get("p"))
		switch r.URL.Query().Get("p") {
		case "1":
			_, _ = w.Write([]byte(`{"data":{"items":[{"hostname":"p1-a"},{"hostname":"p1-b"}]},"total":5}`))
		case "2":
			_, _ = w.Write([]byte(`{"data":{"items":[{"hostname":"p2-a"},{"hostname":"p2-b"}]},"total":5}`))
		case "3":
			_, _ = w.Write([]byte(`{"data":{"items":[{"hostname":"p3-a"}]},"total":5}`))
		default:
			t.Errorf("意外页码：%s", r.URL.RawQuery)
		}
	}))
	defer server.Close()

	items, err := cmdbProvider{}.List(context.Background(), Config{
		URL:        server.URL + "/assets?env=prod",
		Pagination: "page",
		PageParam:  "p",
		PageSize:   2,
		ItemsField: "data.items",
	})
	if err != nil {
		t.Fatalf("拉取失败：%v", err)
	}
	if len(items) != 5 {
		t.Fatalf("应拉取 5 台实例，实际 %d", len(items))
	}
	if strings.Join(pages, ",") != "1,2,3" {
		t.Fatalf("页码序列异常：%v", pages)
	}
}

// cursor 模式按自定义参数名携带游标
func TestCMDBListCursorMode(t *testing.T) {
	var cursors []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cursor := r.URL.Query().Get("after")
		cursors = append(cursors, cursor)
		if cursor == "" {
			_, _ = w.Write([]byte(`{"results":[{"hostname":"c1"}],"next":"token-2"}`))
			return
		}
		_, _ = w.Write([]byte(`{"results":[{"hostname":"c2"}],"next":""}`))
	}))
	defer server.Close()

	items, err := cmdbProvider{}.List(context.Background(), Config{
		URL:         server.URL,
		Pagination:  "cursor",
		CursorParam: "after",
	})
	if err != nil {
		t.Fatalf("拉取失败：%v", err)
	}
	if len(items) != 2 {
		t.Fatalf("应拉取 2 台实例，实际 %d", len(items))
	}
	if strings.Join(cursors, ",") != ",token-2" {
		t.Fatalf("游标序列异常：%v", cursors)
	}
}

// 跨域 next 必须拒绝，避免把凭据带到任意主机
func TestCMDBListRejectsCrossOriginNext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"items":[{"hostname":"a"}],"next":"http://evil.example.com/steal"}`))
	}))
	defer server.Close()

	_, err := cmdbProvider{}.List(context.Background(), Config{URL: server.URL})
	if err == nil || !strings.Contains(err.Error(), "同源") {
		t.Fatalf("跨域 next 应被拒绝，实际 %v", err)
	}
}

// none 模式只取单页，即使响应带 next 也不继续
func TestCMDBListNoneModeStopsAfterFirstPage(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		_, _ = w.Write([]byte(`{"items":[{"hostname":"only"}],"next":"page-2"}`))
	}))
	defer server.Close()

	items, err := cmdbProvider{}.List(context.Background(), Config{URL: server.URL, Pagination: "none"})
	if err != nil || len(items) != 1 || requests != 1 {
		t.Fatalf("单页模式异常：items=%d requests=%d err=%v", len(items), requests, err)
	}
}
