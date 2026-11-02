package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	harnessapp "vulnagent/server/internal/application/harness"
	"vulnagent/server/internal/application/ports"
)

type fakeLLM struct {
	model string
	delay time.Duration
	fail  bool
}

func (f *fakeLLM) Chat(ctx context.Context, req ports.LLMRequest) (ports.LLMResponse, error) {
	if f.fail {
		return ports.LLMResponse{}, errors.New("fake failure")
	}
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return ports.LLMResponse{}, ctx.Err()
		}
	}
	return ports.LLMResponse{Content: "ok"}, nil
}

func (f *fakeLLM) Model() string { return f.model }

func TestParseSSHGPUInfo(t *testing.T) {
	info := parseSSHGPUInfo("NVIDIA GeForce RTX 4090, 24564, 550.54.14, 37\nNVIDIA A100-SXM4-80GB, 81920, 550.54.14, 82\n")
	if !info.Available || len(info.Devices) != 2 {
		t.Fatalf("GPU 解析失败：%+v", info)
	}
	if info.Name != "NVIDIA GeForce RTX 4090" || info.MemoryMB != 24564 || info.Driver != "550.54.14" {
		t.Fatalf("首块 GPU 信息异常：%+v", info.Devices[0])
	}
	if info.Utilization != 37 {
		t.Fatalf("利用率解析异常：%v", info.Utilization)
	}

	missing := parseSSHGPUInfo("NOGPU|未检测到 nvidia-smi")
	if missing.Available || missing.Error == "" {
		t.Fatalf("未检测到 GPU 时应返回错误说明：%+v", missing)
	}

	empty := parseSSHGPUInfo("")
	if empty.Available || empty.Error == "" {
		t.Fatalf("空输出应返回不可用：%+v", empty)
	}
}

func TestLLMForHostSelectsGPU(t *testing.T) {
	gpu := &fakeLLM{model: "qwen-gpu"}
	def := &fakeLLM{model: "qwen-default"}
	app := &App{gpuLLM: gpu, harness: &harnessapp.Service{LLM: def}}

	if got := app.llmForHost(sshHost{GPUAccel: true}); got != ports.LLM(gpu) {
		t.Fatalf("开启 GPU 加速时应使用 GPU 端点")
	}
	if got := app.llmForHost(sshHost{}); got != ports.LLM(def) {
		t.Fatalf("未开启 GPU 加速时应使用默认端点")
	}
	if app.hostAccelerated(sshHost{GPUAccel: true}) != true || app.hostAccelerated(sshHost{}) != false {
		t.Fatalf("加速标记判断异常")
	}

	noGPU := &App{harness: &harnessapp.Service{LLM: def}}
	if got := noGPU.llmForHost(sshHost{GPUAccel: true}); got != ports.LLM(def) {
		t.Fatalf("未配置 GPU 端点时应回落到默认端点")
	}
	if got := (&App{}).llmForHost(sshHost{GPUAccel: true}); got != nil {
		t.Fatalf("两个端点都未配置时应返回 nil")
	}
}

func TestBenchmarkLLM(t *testing.T) {
	base := benchmarkLLM(context.Background(), &fakeLLM{model: "slow", delay: 12 * time.Millisecond}, "ping", 2)
	gpu := benchmarkLLM(context.Background(), &fakeLLM{model: "fast", delay: time.Millisecond}, "ping", 2)
	if base.Samples != 2 || gpu.Samples != 2 {
		t.Fatalf("采样次数异常：%+v / %+v", base, gpu)
	}
	if base.AvgMs <= gpu.AvgMs {
		t.Fatalf("慢端点平均耗时应大于快端点：%d vs %d", base.AvgMs, gpu.AvgMs)
	}

	failed := benchmarkLLM(context.Background(), &fakeLLM{model: "broken", fail: true}, "ping", 2)
	if failed.Samples != 0 || failed.Failed != 2 || failed.Error == "" {
		t.Fatalf("失败调用统计异常：%+v", failed)
	}
}

func TestSSHHostGPUHandlers(t *testing.T) {
	addr, fingerprint := startTestSSHServer(t)
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("解析测试地址失败：%v", err)
	}
	port, _ := strconv.Atoi(portText)

	db, err := openDB(filepath.Join(t.TempDir(), "gpu.db"))
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
		VALUES('gpu-host', ?, ?, 'tester', 'password', ?, '', ?, '', '', 'tester', '', '', '', 1)`,
		host, port, sealed, fingerprint)
	if err != nil {
		t.Fatalf("写入测试主机失败：%v", err)
	}
	id, _ := res.LastInsertId()

	// 未配置 GPU 端点时基准对比应直接返回 503
	rec := httptest.NewRecorder()
	req := withPathValue(newCatalogRequest(t, "POST", "/api/v1/ssh/hosts/x/gpu/benchmark", nil, "operator"),
		"id", strconv.FormatInt(id, 10))
	app.handleSSHHostGPUBenchmark(rec, req)
	if rec.Code != 503 {
		t.Fatalf("未配置 GPU 端点应返回 503，实际 %d：%s", rec.Code, rec.Body.String())
	}

	// 探测接口：测试 SSH 服务返回一块 RTX 4090
	rec = httptest.NewRecorder()
	req = withPathValue(newCatalogRequest(t, "GET", "/api/v1/ssh/hosts/x/gpu", nil, "viewer"),
		"id", strconv.FormatInt(id, 10))
	app.handleSSHHostGPU(rec, req)
	if rec.Code != 200 {
		t.Fatalf("GPU 探测接口返回 %d：%s", rec.Code, rec.Body.String())
	}
	var info sshGPUInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatalf("解析探测响应失败：%v", err)
	}
	if !info.Available || info.HostID != id || info.Name != "NVIDIA GeForce RTX 4090" {
		t.Fatalf("探测结果异常：%+v", info)
	}
	if !info.AccelEnabled || info.EndpointReady {
		t.Fatalf("加速开关或端点状态异常：%+v", info)
	}

	// 配置两个端点后做一次基准对比
	app.gpuLLM = &fakeLLM{model: "gpu-model", delay: time.Millisecond}
	app.harness = &harnessapp.Service{LLM: &fakeLLM{model: "default-model", delay: 15 * time.Millisecond}}
	rec = httptest.NewRecorder()
	req = withPathValue(newCatalogRequest(t, "POST", "/api/v1/ssh/hosts/x/gpu/benchmark?rounds=1", nil, "operator"),
		"id", strconv.FormatInt(id, 10))
	app.handleSSHHostGPUBenchmark(rec, req)
	if rec.Code != 200 {
		t.Fatalf("基准对比返回 %d：%s", rec.Code, rec.Body.String())
	}
	var benchmark sshGPUBenchmark
	if err := json.Unmarshal(rec.Body.Bytes(), &benchmark); err != nil {
		t.Fatalf("解析基准响应失败：%v", err)
	}
	if benchmark.Default.Model != "default-model" || benchmark.GPU.Model != "gpu-model" {
		t.Fatalf("基准端点信息异常：%+v", benchmark)
	}
	if benchmark.Default.Samples != 1 || benchmark.GPU.Samples != 1 {
		t.Fatalf("基准采样次数异常：%+v", benchmark)
	}
	if benchmark.SpeedupPercent <= 0 {
		t.Fatalf("GPU 更快时提升比例应为正：%v", benchmark.SpeedupPercent)
	}
}
