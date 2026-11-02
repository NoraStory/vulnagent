package main

import (
	"encoding/json"
	"net"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestParseSSHAccelProfile(t *testing.T) {
	output := strings.Join([]string{
		"NVSMI|1",
		"GPU|NVIDIA GeForce RTX 4090, 24564, 1024, 550.54.14, 37, Enabled, 450.00, 450.00, 2100, 2520",
		"GPU|NVIDIA A100-SXM4-80GB, 81920, 4096, 550.54.14, 82, Disabled, 300.00, 400.00, 1410, 1410",
		"CUDA|12.4",
		"THROTTLE|Not Active",
		"THROTTLE|SW Power Cap",
		"CPU|Intel Xeon Gold 6338",
		"GOV|powersave",
		"CORES|32",
		"MEM|64000000",
		"SWAP|2000000",
	}, "\n")
	profile, err := parseSSHAccelProfile(output)
	if err != nil {
		t.Fatalf("解析加速信息失败：%v", err)
	}
	if !profile.Available || !profile.NvidiaSMI || len(profile.GPUs) != 2 {
		t.Fatalf("GPU 解析异常：%+v", profile)
	}
	if profile.CUDA != "12.4" || profile.CPUModel != "Intel Xeon Gold 6338" || profile.CPUCores != 32 {
		t.Fatalf("系统信息解析异常：%+v", profile)
	}
	first := profile.GPUs[0]
	if first.Name != "NVIDIA GeForce RTX 4090" || first.MemoryMB != 24564 || first.MemoryUsedMB != 1024 ||
		first.PowerLimitW != 450 || first.ClockMHz != 2100 || first.Throttle != "Not Active" {
		t.Fatalf("首块 GPU 解析异常：%+v", first)
	}
	if profile.GPUs[1].Throttle != "SW Power Cap" {
		t.Fatalf("降频原因未按设备回填：%+v", profile.GPUs[1])
	}

	suggestions := buildAccelSuggestions(&profile)
	wantIDs := map[string]bool{"persistence-1": false, "power-1": false, "thermal-1": false, "cpu-governor": false, "swap-enabled": false}
	for _, item := range suggestions {
		if _, ok := wantIDs[item.ID]; ok {
			wantIDs[item.ID] = true
		}
	}
	for id, found := range wantIDs {
		if !found {
			t.Fatalf("缺少建议 %s：%+v", id, suggestions)
		}
	}
	if len(suggestions) != 5 {
		t.Fatalf("建议数量异常：%d %+v", len(suggestions), suggestions)
	}

	if _, err := parseSSHAccelProfile("unexpected output"); err == nil {
		t.Fatalf("无有效行时应返回错误")
	}

	noGPU, err := parseSSHAccelProfile("NVSMI|0\nCPU|Test CPU\nGOV|performance\nCORES|8\nMEM|8000000\nSWAP|0\n")
	if err != nil || noGPU.Available || len(buildAccelSuggestions(&noGPU)) != 1 {
		t.Fatalf("无 GPU 主机处理异常：%+v / %v", noGPU, err)
	}
}

func TestParseSSHAccelProfileExtended(t *testing.T) {
	output := strings.Join([]string{
		"NVSMI|1",
		"GPU|0, GPU-4090-0001, NVIDIA GeForce RTX 4090, 24564, 1024, 12, 37, 550.54.14, Enabled, 450.00, 450.00, 500.00, 120.50, 2100, 2520, 10501, 82, 45, P2, Default, Not Active",
		"CUDA|12.4",
		"DRIVER|550.54.14",
		"MIG|Disabled",
		"PROC|GPU-4090-0001, 1234, python, 512",
		"CPU|Intel Xeon Gold 6338", "GOV|powersave", "CORES|32", "MEM|64000000", "SWAP|0", "HASHCAT|v6.2.6",
	}, "\n")
	profile, err := parseSSHAccelProfile(output)
	if err != nil {
		t.Fatalf("解析扩展加速信息失败：%v", err)
	}
	if profile.Driver != "550.54.14" || len(profile.GPUs) != 1 {
		t.Fatalf("驱动或 GPU 解析异常：%+v", profile)
	}
	gpu := profile.GPUs[0]
	if gpu.UUID != "GPU-4090-0001" || gpu.MemoryUtilization != 12 || gpu.TempC != 82 ||
		gpu.PowerDrawW != 120.5 || gpu.PowerMaxW != 500 || gpu.FanPercent != 45 ||
		gpu.PState != "P2" || gpu.ComputeMode != "Default" || gpu.MigMode != "Disabled" {
		t.Fatalf("扩展 GPU 字段解析异常：%+v", gpu)
	}
	if len(gpu.Processes) != 1 || gpu.Processes[0].PID != 1234 || gpu.Processes[0].MemoryMB != 512 {
		t.Fatalf("GPU 进程解析异常：%+v", gpu.Processes)
	}
	suggestions := buildAccelSuggestions(&profile)
	foundTemp := false
	for _, item := range suggestions {
		if item.ID == "temp-0" {
			foundTemp = true
		}
	}
	if !foundTemp {
		t.Fatalf("高温建议缺失：%+v", suggestions)
	}
}

func TestParseSSHAccelLive(t *testing.T) {
	live := parseSSHAccelLive("GPU|0, GPU-4090-0001, NVIDIA GeForce RTX 4090, 24564, 2048, 45, 30, 120.5, 450.0, 62, 45, P2, Not Active\n")
	if !live.Available || len(live.GPUs) != 1 {
		t.Fatalf("实时指标解析异常：%+v", live)
	}
	gpu := live.GPUs[0]
	if gpu.Utilization != 45 || gpu.MemoryUtilization != 30 || gpu.TempC != 62 || gpu.PowerDrawW != 120.5 ||
		gpu.FanPercent != 45 || gpu.PState != "P2" || gpu.Throttle != "Not Active" {
		t.Fatalf("实时 GPU 字段异常：%+v", gpu)
	}
	noGPU := parseSSHAccelLive("NOGPU|未检测到 nvidia-smi\n")
	if noGPU.Available || noGPU.Error == "" {
		t.Fatalf("无 GPU 实时结果异常：%+v", noGPU)
	}
}

func TestBuildAccelComparison(t *testing.T) {
	before := sshHostAccelProfile{
		HostID: 1, HostName: "gpu-01", Governor: "powersave",
		GPUs: []accelGPU{{Name: "RTX 4090", Persistence: "Disabled", PowerLimitW: 300, ClockMHz: 1500, Utilization: 10}},
	}
	after := sshHostAccelProfile{
		HostID: 1, HostName: "gpu-01", Governor: "performance", Suggestions: []accelSuggestion{},
		GPUs: []accelGPU{{Name: "RTX 4090", Persistence: "Enabled", PowerLimitW: 450, ClockMHz: 2100, Utilization: 80}},
	}
	beforeMetrics := sshHostMetrics{HostID: 1, CPUPercent: 40, MemPercent: 60, Load1: 1.2}
	afterMetrics := sshHostMetrics{HostID: 1, CPUPercent: 20, MemPercent: 55, Load1: 0.6}

	comparison := buildAccelComparison(before, beforeMetrics, after, afterMetrics)
	if len(comparison.Metrics) != 5 {
		t.Fatalf("指标数量异常：%+v", comparison.Metrics)
	}
	if comparison.Metrics[0].Delta != -20 || !comparison.Metrics[0].Improved {
		t.Fatalf("CPU 指标对比异常：%+v", comparison.Metrics[0])
	}
	if !comparison.Metrics[4].Improved || comparison.Metrics[4].Delta != 600 {
		t.Fatalf("GPU 频率对比异常：%+v", comparison.Metrics[4])
	}
	joined := strings.Join(comparison.Changes, "|")
	for _, want := range []string{"持久化模式", "功耗上限", "CPU 调频策略"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("缺少配置变更 %s：%s", want, joined)
		}
	}
}

func TestSSHHostAccelHandlers(t *testing.T) {
	addr, fingerprint := startTestSSHServer(t)
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("解析测试地址失败：%v", err)
	}
	port, _ := strconv.Atoi(portText)

	db, err := openDB(filepath.Join(t.TempDir(), "accel.db"))
	if err != nil {
		t.Fatalf("打开测试库失败：%v", err)
	}
	defer db.Close()
	app := &App{db: db, dataDir: t.TempDir(), gpuLLM: &fakeLLM{model: "gpu-model"}}
	sealed, err := app.sealSSHSecret("secret")
	if err != nil {
		t.Fatalf("加密凭据失败：%v", err)
	}
	res, err := db.Exec(`INSERT INTO ssh_hosts(name, host, port, username, auth_type, secret, passphrase,
		host_key, note, tags, created_by, created_at, updated_at, last_connected_at, gpu_accel)
		VALUES('accel-host', ?, ?, 'tester', 'password', ?, '', ?, '', '', 'tester', '', '', '', 1)`,
		host, port, sealed, fingerprint)
	if err != nil {
		t.Fatalf("写入测试主机失败：%v", err)
	}
	id, _ := res.LastInsertId()
	idText := strconv.FormatInt(id, 10)

	// 未记录基线时对比应返回 404
	rec := httptest.NewRecorder()
	req := withPathValue(newCatalogRequest(t, "POST", "/api/v1/ssh/hosts/x/accel/compare", nil, "operator"), "id", idText)
	app.handleSSHHostAccelCompare(rec, req)
	if rec.Code != 404 {
		t.Fatalf("无基线时应返回 404，实际 %d：%s", rec.Code, rec.Body.String())
	}

	// 能力探测
	rec = httptest.NewRecorder()
	req = withPathValue(newCatalogRequest(t, "GET", "/api/v1/ssh/hosts/x/accel", nil, "viewer"), "id", idText)
	app.handleSSHHostAccel(rec, req)
	if rec.Code != 200 {
		t.Fatalf("加速探测返回 %d：%s", rec.Code, rec.Body.String())
	}
	var profile sshHostAccelProfile
	if err := json.Unmarshal(rec.Body.Bytes(), &profile); err != nil {
		t.Fatalf("解析探测响应失败：%v", err)
	}
	if !profile.Available || profile.HostID != id || len(profile.GPUs) != 1 {
		t.Fatalf("探测结果异常：%+v", profile)
	}
	if !profile.EndpointReady || !profile.AccelEnabled || profile.CUDA != "12.4" {
		t.Fatalf("加速状态异常：%+v", profile)
	}
	if _, ok := app.cachedAccelProfile(id); !ok {
		t.Fatalf("探测结果未进入缓存")
	}

	// 轻量实时指标
	rec = httptest.NewRecorder()
	req = withPathValue(newCatalogRequest(t, "GET", "/api/v1/ssh/hosts/x/accel/live", nil, "viewer"), "id", idText)
	app.handleSSHHostAccelLive(rec, req)
	if rec.Code != 200 {
		t.Fatalf("实时指标返回 %d：%s", rec.Code, rec.Body.String())
	}
	var live sshAccelLive
	if err := json.Unmarshal(rec.Body.Bytes(), &live); err != nil {
		t.Fatalf("解析实时指标失败：%v", err)
	}
	if !live.Available || len(live.GPUs) != 1 || live.GPUs[0].TempC != 62 {
		t.Fatalf("实时指标异常：%+v", live)
	}
	if _, ok := app.cachedAccelLive(id); !ok {
		t.Fatalf("实时指标未进入缓存")
	}

	// 记录基线
	rec = httptest.NewRecorder()
	req = withPathValue(newCatalogRequest(t, "POST", "/api/v1/ssh/hosts/x/accel/baseline", nil, "operator"), "id", idText)
	app.handleSSHHostAccelBaseline(rec, req)
	if rec.Code != 200 {
		t.Fatalf("记录基线返回 %d：%s", rec.Code, rec.Body.String())
	}
	var baseline struct {
		Profile   sshHostAccelProfile `json:"profile"`
		Metrics   sshHostMetrics      `json:"metrics"`
		CreatedAt string              `json:"createdAt"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &baseline); err != nil {
		t.Fatalf("解析基线响应失败：%v", err)
	}
	if baseline.CreatedAt == "" || baseline.Metrics.CPUPercent <= 0 {
		t.Fatalf("基线内容异常：%+v", baseline)
	}

	// 对比
	rec = httptest.NewRecorder()
	req = withPathValue(newCatalogRequest(t, "POST", "/api/v1/ssh/hosts/x/accel/compare", nil, "operator"), "id", idText)
	app.handleSSHHostAccelCompare(rec, req)
	if rec.Code != 200 {
		t.Fatalf("对比返回 %d：%s", rec.Code, rec.Body.String())
	}
	var comparison sshAccelComparison
	if err := json.Unmarshal(rec.Body.Bytes(), &comparison); err != nil {
		t.Fatalf("解析对比响应失败：%v", err)
	}
	if comparison.BaselineAt == "" || len(comparison.Metrics) != 5 || comparison.After.HostID != id {
		t.Fatalf("对比结果异常：%+v", comparison)
	}

	// 加速节点列表
	rec = httptest.NewRecorder()
	req = newCatalogRequest(t, "GET", "/api/v1/accel/hosts", nil, "viewer")
	app.handleAccelHosts(rec, req)
	if rec.Code != 200 {
		t.Fatalf("节点列表返回 %d：%s", rec.Code, rec.Body.String())
	}
	var nodes struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &nodes); err != nil {
		t.Fatalf("解析节点列表失败：%v", err)
	}
	if len(nodes.Items) != 1 || nodes.Items[0]["hostName"] != "accel-host" {
		t.Fatalf("节点列表异常：%+v", nodes.Items)
	}
}
