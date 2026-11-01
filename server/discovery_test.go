package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"vulnagent/server/internal/application/ports"
	"vulnagent/server/internal/discovery"
)

func newDiscoveryTestApp(t *testing.T) *App {
	t.Helper()
	db, err := openDB(filepath.Join(t.TempDir(), "discovery.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败：%v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &App{db: db}
}

func newDiscoveryRequest(t *testing.T, method, target string, body any, role string) *http.Request {
	t.Helper()
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("序列化请求失败：%v", err)
		}
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, target, reader)
	req.Header.Set("Content-Type", "application/json")
	return req.WithContext(context.WithValue(req.Context(), ctxKeyUser{}, User{Username: "tester", Name: "测试员", Role: role}))
}

func TestDiscoveryPolicyValidationAndPermission(t *testing.T) {
	app := newDiscoveryTestApp(t)

	rec := httptest.NewRecorder()
	app.handleDiscoveryPolicy(rec, newDiscoveryRequest(t, "PUT", "/api/v1/settings/discovery",
		discovery.Policy{AllowedCIDRs: []string{"10.0.0.0/8"}}, "operator"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator 修改策略应返回 403，实际 %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	app.handleDiscoveryPolicy(rec, newDiscoveryRequest(t, "PUT", "/api/v1/settings/discovery",
		discovery.Policy{AllowedCIDRs: []string{"0.0.0.0/0"}}, "admin"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("全网段应被拒绝，实际 %d：%s", rec.Code, rec.Body.String())
	}

	payload := discovery.Policy{
		AllowedCIDRs:   []string{"10.0.0.0/8", "127.0.0.0/8"},
		DefaultPorts:   []int{22, 80},
		MaxHosts:       16,
		MaxConcurrency: 4,
		TimeoutMS:      300,
		MaxPorts:       8,
		MaxJobsPerHour: 5,
		ReverseDNS:     false,
	}
	rec = httptest.NewRecorder()
	app.handleDiscoveryPolicy(rec, newDiscoveryRequest(t, "PUT", "/api/v1/settings/discovery", payload, "admin"))
	if rec.Code != http.StatusOK {
		t.Fatalf("管理员保存策略失败：%d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	app.handleDiscoveryPolicy(rec, newDiscoveryRequest(t, "GET", "/api/v1/settings/discovery", nil, "viewer"))
	if rec.Code != http.StatusOK {
		t.Fatalf("读取策略失败：%d", rec.Code)
	}
	var got struct {
		Policy discovery.Policy `json:"policy"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("解析策略失败：%v", err)
	}
	if got.Policy.MaxHosts != 16 || len(got.Policy.AllowedCIDRs) != 2 || got.Policy.MaxJobsPerHour != 5 {
		t.Fatalf("策略未持久化：%+v", got.Policy)
	}
}

func TestDiscoveryJobRejectsUnauthorizedCIDR(t *testing.T) {
	app := newDiscoveryTestApp(t)

	rec := httptest.NewRecorder()
	app.handleDiscoveryJobs(rec, newDiscoveryRequest(t, "POST", "/api/v1/discovery/jobs",
		discoveryJobRequest{CIDRs: []string{"8.8.8.0/24"}, Ports: []int{22}}, "operator"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("未授权网段应返回 400，实际 %d：%s", rec.Code, rec.Body.String())
	}
	var count int
	if err := app.db.QueryRow(`SELECT COUNT(*) FROM audit_logs WHERE action = 'discovery.job.reject'`).Scan(&count); err != nil {
		t.Fatalf("查询审计失败：%v", err)
	}
	if count != 1 {
		t.Fatalf("拒绝任务应写审计，实际 %d 条", count)
	}
}

func TestDiscoveryApproveCreatesAsset(t *testing.T) {
	app := newDiscoveryTestApp(t)
	ctx := context.Background()
	jobID, err := app.discoveryRepo().CreateJob(ctx, ports.DiscoveryJob{
		Name: "候选", CIDRs: "10.0.0.0/30", Ports: "22", Status: "completed", Total: 4,
		CreatedAt: fmtT(nowT()),
	})
	if err != nil {
		t.Fatalf("创建任务失败：%v", err)
	}
	candidateID, err := app.discoveryRepo().InsertCandidate(ctx, ports.DiscoveryCandidate{
		JobID: jobID, IP: "10.0.0.9", Hostname: "web-99", OpenPorts: "22,80",
		Evidence: "tcp/22 open", Decision: "new", Confidence: 0.6, CreatedAt: fmtT(nowT()),
	})
	if err != nil {
		t.Fatalf("写入候选失败：%v", err)
	}

	req := newDiscoveryRequest(t, "POST", "/api/v1/discovery/candidates/"+strconv.FormatInt(candidateID, 10)+"/approve", nil, "operator")
	req.SetPathValue("id", strconv.FormatInt(candidateID, 10))
	req.SetPathValue("action", "approve")
	rec := httptest.NewRecorder()
	app.handleDiscoveryCandidateAction(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("确认候选失败：%d %s", rec.Code, rec.Body.String())
	}
	var approved struct {
		AssetID int64 `json:"assetId"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &approved)
	if approved.AssetID == 0 {
		t.Fatal("确认候选应返回资产 ID")
	}

	detail, err := app.assetRepo().Detail(ctx, approved.AssetID)
	if err != nil {
		t.Fatalf("读取资产失败：%v", err)
	}
	if detail.Hostname != "web-99" || detail.IP != "10.0.0.9" || detail.Source != "discovery" {
		t.Fatalf("资产档案不正确：%+v", detail)
	}
	identifiers, err := app.assetRepo().Identifiers(ctx, approved.AssetID)
	if err != nil || len(identifiers) < 2 {
		t.Fatalf("资产标识未写入：len=%d err=%v", len(identifiers), err)
	}
	candidate, _ := app.discoveryRepo().GetCandidate(ctx, candidateID)
	if candidate.Decision != "approved" || candidate.AssetID != approved.AssetID {
		t.Fatalf("候选决策未更新：%+v", candidate)
	}

	// 重复确认应幂等
	rec = httptest.NewRecorder()
	app.handleDiscoveryCandidateAction(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("重复确认失败：%d", rec.Code)
	}
	var again struct {
		AssetID int64 `json:"assetId"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &again)
	if again.AssetID != approved.AssetID {
		t.Fatalf("重复确认不应新建资产：%d → %d", approved.AssetID, again.AssetID)
	}
}

func TestDiscoveryIgnoreAndMerge(t *testing.T) {
	app := newDiscoveryTestApp(t)
	ctx := context.Background()
	jobID, _ := app.discoveryRepo().CreateJob(ctx, ports.DiscoveryJob{
		Name: "候选2", CIDRs: "10.0.0.0/30", Ports: "22", Status: "completed", Total: 4, CreatedAt: fmtT(nowT()),
	})
	ignoreID, _ := app.discoveryRepo().InsertCandidate(ctx, ports.DiscoveryCandidate{
		JobID: jobID, IP: "10.0.0.10", Decision: "new", CreatedAt: fmtT(nowT()),
	})
	mergeID, _ := app.discoveryRepo().InsertCandidate(ctx, ports.DiscoveryCandidate{
		JobID: jobID, IP: "10.0.0.11", Hostname: "db-99", Decision: "new", CreatedAt: fmtT(nowT()),
	})

	req := newDiscoveryRequest(t, "POST", "/api/v1/discovery/candidates/x/ignore", nil, "operator")
	req.SetPathValue("id", strconv.FormatInt(ignoreID, 10))
	req.SetPathValue("action", "ignore")
	rec := httptest.NewRecorder()
	app.handleDiscoveryCandidateAction(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("忽略候选失败：%d %s", rec.Code, rec.Body.String())
	}
	ignored, _ := app.discoveryRepo().GetCandidate(ctx, ignoreID)
	if ignored.Decision != "ignored" {
		t.Fatalf("忽略状态未更新：%+v", ignored)
	}

	targetID, err := app.assetRepo().Create(ctx, map[string]string{"hostname": "db-01", "ip": "10.0.0.11"}, nil, nil, "agent")
	if err != nil {
		t.Fatalf("创建目标资产失败：%v", err)
	}

	// operator 不允许合并
	req = newDiscoveryRequest(t, "POST", "/api/v1/discovery/candidates/x/merge", map[string]any{"assetId": targetID}, "operator")
	req.SetPathValue("id", strconv.FormatInt(mergeID, 10))
	req.SetPathValue("action", "merge")
	rec = httptest.NewRecorder()
	app.handleDiscoveryCandidateAction(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator 合并应返回 403，实际 %d", rec.Code)
	}

	req = newDiscoveryRequest(t, "POST", "/api/v1/discovery/candidates/x/merge", map[string]any{"assetId": targetID}, "admin")
	req.SetPathValue("id", strconv.FormatInt(mergeID, 10))
	req.SetPathValue("action", "merge")
	rec = httptest.NewRecorder()
	app.handleDiscoveryCandidateAction(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("管理员合并失败：%d %s", rec.Code, rec.Body.String())
	}
	merged, _ := app.discoveryRepo().GetCandidate(ctx, mergeID)
	if merged.Decision != "merged" || merged.AssetID != targetID {
		t.Fatalf("合并状态未更新：%+v", merged)
	}
	if id, ok, err := app.assetRepo().FindByIdentity(ctx, "ip", "10.0.0.11"); err != nil || !ok || id != targetID {
		t.Fatalf("候选 IP 未登记到目标资产：id=%d ok=%v err=%v", id, ok, err)
	}
}

func TestDiscoveryJobRunnerEndToEnd(t *testing.T) {
	app := newDiscoveryTestApp(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听本地端口失败：%v", err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port

	rec := httptest.NewRecorder()
	app.handleDiscoveryJobs(rec, newDiscoveryRequest(t, "POST", "/api/v1/discovery/jobs", discoveryJobRequest{
		Name: "本机发现", CIDRs: []string{"127.0.0.1/32"}, Ports: []int{port},
		Concurrency: 1, TimeoutMs: 500, ReverseDNS: boolPtr(false),
	}, "operator"))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("创建发现任务失败：%d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Job ports.DiscoveryJob `json:"job"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.Job.ID == 0 {
		t.Fatalf("解析任务失败：%v %s", err, rec.Body.String())
	}

	deadline := time.Now().Add(6 * time.Second)
	var job ports.DiscoveryJob
	for time.Now().Before(deadline) {
		job, err = app.discoveryRepo().GetJob(context.Background(), created.Job.ID)
		if err == nil && (job.Status == "completed" || job.Status == "failed" || job.Status == "cancelled") {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if job.Status != "completed" {
		t.Fatalf("任务未正常结束：%+v", job)
	}
	if job.Found != 1 || job.Scanned != 1 {
		t.Fatalf("扫描统计异常：%+v", job)
	}

	items, total, err := app.discoveryRepo().ListCandidates(context.Background(),
		ports.DiscoveryCandidateFilter{JobID: job.ID}, 10, 0)
	if err != nil || total != 1 || len(items) != 1 {
		t.Fatalf("候选列表异常：total=%d err=%v", total, err)
	}
	if items[0].IP != "127.0.0.1" || items[0].OpenPorts != strconv.Itoa(port) {
		t.Fatalf("候选内容异常：%+v", items[0])
	}
}

func boolPtr(value bool) *bool { return &value }
