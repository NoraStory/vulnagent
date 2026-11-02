package main

import (
	"encoding/json"
	"net"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
)

// 通过测试 SSH 服务端验证性能采样端点：连接 → 执行脚本 → 解析 → JSON 输出
func TestSSHHostMetricsHandler(t *testing.T) {
	addr, fingerprint := startTestSSHServer(t)
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("解析测试地址失败：%v", err)
	}
	port, _ := strconv.Atoi(portText)

	db, err := openDB(filepath.Join(t.TempDir(), "metrics.db"))
	if err != nil {
		t.Fatalf("打开测试库失败：%v", err)
	}
	defer db.Close()
	app := &App{db: db, dataDir: t.TempDir()}
	sealed, err := app.sealSSHSecret("secret")
	if err != nil {
		t.Fatalf("加密凭据失败：%v", err)
	}
	res, err := db.Exec(`INSERT INTO ssh_hosts(name, host, port, username, auth_type, secret, passphrase,
		host_key, note, tags, created_by, created_at, updated_at, last_connected_at)
		VALUES('metrics-host', ?, ?, 'tester', 'password', ?, '', ?, '', '', 'tester', '', '', '')`,
		host, port, sealed, fingerprint)
	if err != nil {
		t.Fatalf("写入测试主机失败：%v", err)
	}
	id, _ := res.LastInsertId()

	rec := httptest.NewRecorder()
	req := withPathValue(newCatalogRequest(t, "GET", "/api/v1/ssh/hosts/x/metrics", nil, "viewer"),
		"id", strconv.FormatInt(id, 10))
	app.handleSSHHostMetrics(rec, req)
	if rec.Code != 200 {
		t.Fatalf("采样接口返回 %d：%s", rec.Code, rec.Body.String())
	}
	var metrics sshHostMetrics
	if err := json.Unmarshal(rec.Body.Bytes(), &metrics); err != nil {
		t.Fatalf("解析响应失败：%v", err)
	}
	if metrics.HostID != id || metrics.HostName != "metrics-host" {
		t.Fatalf("主机信息异常：%+v", metrics)
	}
	if metrics.CPUPercent < 49.9 || metrics.CPUPercent > 50.1 {
		t.Fatalf("CPU 使用率异常：%v", metrics.CPUPercent)
	}
	if metrics.MemPercent != 50 || metrics.Load1 != 0.52 || metrics.CPUCores != 4 {
		t.Fatalf("指标解析异常：%+v", metrics)
	}
	if len(metrics.Disks) != 1 || metrics.Disks[0].Mount != "/" {
		t.Fatalf("磁盘解析异常：%+v", metrics.Disks)
	}
	if len(metrics.Top) != 1 || metrics.Top[0].Command != "nginx" {
		t.Fatalf("进程解析异常：%+v", metrics.Top)
	}
	if metrics.SampledAt == "" || metrics.HostAddr == "" {
		t.Fatalf("缺少采样时间或地址：%+v", metrics)
	}
}
