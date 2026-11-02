package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestHashcatSpeedParsing(t *testing.T) {
	speed, device := hashcatSpeed("Speed.#1.........: 12000.0 MH/s\n  Name...........: NVIDIA GeForce RTX 4090\n")
	if speed != 12e9 || device != "NVIDIA GeForce RTX 4090" {
		t.Fatalf("MH/s 解析异常：%v / %q", speed, device)
	}
	speed, _ = hashcatSpeed("Speed.#1.........: 1500.0 kH/s")
	if speed != 1.5e6 {
		t.Fatalf("kH/s 解析异常：%v", speed)
	}
	if speed, device := hashcatSpeed("No devices found"); speed != 0 || device != "" {
		t.Fatalf("无设备时应返回零值：%v / %q", speed, device)
	}
}

func TestParseHashcatAuditOutput(t *testing.T) {
	requested := map[string]bool{"5f4dcc3b5aa765d61d8327deb882cf99": true}
	cracked, message := parseHashcatAuditOutput(
		"HASHCAT_EXIT|0\n5f4dcc3b5aa765d61d8327deb882cf99:password\nffffffffffffffffffffffffffffffff:other\n", requested)
	if message != "" || len(cracked) != 1 || cracked[0].Plain != "password" {
		t.Fatalf("审计结果解析异常：%+v / %q", cracked, message)
	}

	if _, message := parseHashcatAuditOutput("WORDLIST_MISSING", requested); message != "wordlist_missing" {
		t.Fatalf("字典缺失未识别：%q", message)
	}
	_, message = parseHashcatAuditOutput("HASHCAT_EXIT|2\nHASHCAT_ERROR\nNo devices found", requested)
	if !strings.Contains(message, "No devices found") {
		t.Fatalf("错误信息未提取：%q", message)
	}
}

func TestSSHHostHashcatBenchmarkHandler(t *testing.T) {
	addr, fingerprint := startTestSSHServer(t)
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("解析测试地址失败：%v", err)
	}
	port, _ := strconv.Atoi(portText)

	db, err := openDB(filepath.Join(t.TempDir(), "hashcat.db"))
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
		host_key, note, tags, created_by, created_at, updated_at, last_connected_at, gpu_accel)
		VALUES('hashcat-host', ?, ?, 'tester', 'password', ?, '', ?, '', '', 'tester', '', '', '', 1)`,
		host, port, sealed, fingerprint)
	if err != nil {
		t.Fatalf("写入测试主机失败：%v", err)
	}
	id, _ := res.LastInsertId()

	rec := httptest.NewRecorder()
	req := withPathValue(newCatalogRequest(t, "POST", "/api/v1/ssh/hosts/x/hashcat/benchmark", nil, "operator"),
		"id", strconv.FormatInt(id, 10))
	app.handleSSHHostHashcatBenchmark(rec, req)
	if rec.Code != 200 {
		t.Fatalf("基准接口返回 %d：%s", rec.Code, rec.Body.String())
	}
	var benchmark hashcatBenchmark
	if err := json.Unmarshal(rec.Body.Bytes(), &benchmark); err != nil {
		t.Fatalf("解析基准响应失败：%v", err)
	}
	if !benchmark.Available || benchmark.Version != "v6.2.6" {
		t.Fatalf("hashcat 版本异常：%+v", benchmark)
	}
	if benchmark.GPUSpeedHs != 12e9 || benchmark.CPUSpeedHs != 3e8 {
		t.Fatalf("基准速度异常：%+v", benchmark)
	}
	if benchmark.Speedup <= 0 || benchmark.GPUDevice != "NVIDIA GeForce RTX 4090" {
		t.Fatalf("加速比或设备异常：%+v", benchmark)
	}
}

func TestSSHPoolReusesClient(t *testing.T) {
	addr, fingerprint := startTestSSHServer(t)
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("解析测试地址失败：%v", err)
	}
	port, _ := strconv.Atoi(portText)

	db, err := openDB(filepath.Join(t.TempDir(), "pool.db"))
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
		VALUES('pool-host', ?, ?, 'tester', 'password', ?, '', ?, '', '', 'tester', '', '', '')`,
		host, port, sealed, fingerprint)
	if err != nil {
		t.Fatalf("写入测试主机失败：%v", err)
	}
	id, _ := res.LastInsertId()
	saved, err := app.getSSHHost(context.Background(), id)
	if err != nil {
		t.Fatalf("读取测试主机失败：%v", err)
	}

	client1, fp1, release1, err := app.acquireSSHHost(context.Background(), saved)
	if err != nil {
		t.Fatalf("首次连接失败：%v", err)
	}
	release1()
	client2, fp2, release2, err := app.acquireSSHHost(context.Background(), saved)
	if err != nil {
		t.Fatalf("复用连接失败：%v", err)
	}
	defer release2()
	if client1 != client2 || fp1 != fp2 {
		t.Fatalf("连接未被复用")
	}
	app.closeSSHPool()
}
