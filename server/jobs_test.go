package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func setupAgentToken(t *testing.T, app *App, token string) {
	t.Helper()
	sum := sha256.Sum256([]byte(token))
	if err := app.identityRepo().SaveTokenHash(context.Background(), hex.EncodeToString(sum[:]), fmtNow()); err != nil {
		t.Fatalf("写入 Agent 令牌失败：%v", err)
	}
}

func fmtNow() string { return fmtT(nowT()) }

func TestHostJobQueueClaimAndResult(t *testing.T) {
	app, _, assetID := newTicketTestApp(t)
	setupAgentToken(t, app, "test-agent-token")

	first, err := app.queueHostJob(assetID, "run_command", json.RawMessage(`{"argv":["whoami"]}`), "李维", "")
	if err != nil {
		t.Fatalf("排队失败：%v", err)
	}
	if first.Status != "pending" || !strings.HasPrefix(first.ID, "JOB-") {
		t.Fatalf("新作业状态异常：%+v", first)
	}
	again, err := app.queueHostJob(assetID, "run_command", json.RawMessage(`{"argv":["whoami"]}`), "王倩", "")
	if err != nil || again.ID != first.ID {
		t.Fatalf("幂等建单失败：id=%s err=%v", again.ID, err)
	}

	// 列表
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/jobs?hostname=ticket-host", nil)
	req.Header.Set("Authorization", "Bearer test-agent-token")
	rec := httptest.NewRecorder()
	app.handleAgentJobs(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("拉取作业失败：%d %s", rec.Code, rec.Body.String())
	}
	var listed struct {
		Jobs []struct {
			ID string `json:"id"`
		} `json:"jobs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil || len(listed.Jobs) != 1 {
		t.Fatalf("作业列表异常：%+v err=%v", listed, err)
	}

	// 抢占
	req = httptest.NewRequest(http.MethodPost, "/api/v1/agent/jobs/"+first.ID+"/claim",
		strings.NewReader(`{"hostname":"ticket-host"}`))
	req.SetPathValue("id", first.ID)
	req.Header.Set("Authorization", "Bearer test-agent-token")
	rec = httptest.NewRecorder()
	app.handleAgentJobClaim(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("抢占失败：%d %s", rec.Code, rec.Body.String())
	}
	claimed, _, _ := app.jobRepo().ByID(context.Background(), first.ID)
	if claimed.Status != "running" || claimed.Attempts != 1 {
		t.Fatalf("抢占后状态异常：%+v", claimed)
	}

	// 回传成功结果
	req = httptest.NewRequest(http.MethodPost, "/api/v1/agent/jobs/"+first.ID+"/result",
		strings.NewReader(`{"hostname":"ticket-host","status":"succeeded","output":"liwei","exitCode":0,"durationMs":12}`))
	req.SetPathValue("id", first.ID)
	req.Header.Set("Authorization", "Bearer test-agent-token")
	rec = httptest.NewRecorder()
	app.handleAgentJobResult(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("回传结果失败：%d %s", rec.Code, rec.Body.String())
	}
	done, _, _ := app.jobRepo().ByID(context.Background(), first.ID)
	if done.Status != "succeeded" || done.Output != "liwei" {
		t.Fatalf("结果未落库：%+v", done)
	}

	// 资产作业列表（控制台）
	req = httptest.NewRequest(http.MethodGet, "/api/v1/assets/"+strconv.FormatInt(assetID, 10)+"/jobs", nil)
	req.SetPathValue("id", strconv.FormatInt(assetID, 10))
	req = req.WithContext(context.WithValue(req.Context(), ctxKeyUser{}, User{
		Username: "u", Name: "李维", Role: "operator",
	}))
	rec = httptest.NewRecorder()
	app.handleAssetJobs(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), first.ID) {
		t.Fatalf("资产作业列表异常：%d %s", rec.Code, rec.Body.String())
	}
}

func TestHostJobRetryScheduling(t *testing.T) {
	app, _, assetID := newTicketTestApp(t)
	setupAgentToken(t, app, "test-agent-token")

	job, err := app.queueHostJob(assetID, "run_command", json.RawMessage(`{"argv":["uptime"]}`), "李维", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := app.jobRepo().Claim(context.Background(), job.ID, "ticket-host", fmtNow()); err != nil || !ok {
		t.Fatalf("抢占失败：%v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/jobs/"+job.ID+"/result",
		strings.NewReader(`{"hostname":"ticket-host","status":"failed","error":"网络抖动","exitCode":-1,"retryable":true}`))
	req.SetPathValue("id", job.ID)
	req.Header.Set("Authorization", "Bearer test-agent-token")
	rec := httptest.NewRecorder()
	app.handleAgentJobResult(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("回传失败：%d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"retryScheduled":true`) {
		t.Fatalf("应安排重试：%s", rec.Body.String())
	}
	got, _, _ := app.jobRepo().ByID(context.Background(), job.ID)
	if got.Status != "pending" || got.NextRunAt == "" {
		t.Fatalf("重试状态异常：%+v", got)
	}

	// 错误主机不能回传
	other, _ := app.queueHostJob(assetID, "read_file", json.RawMessage(`{"path":"/etc/hosts"}`), "李维", "")
	if _, ok, _ := app.jobRepo().Claim(context.Background(), other.ID, "ticket-host", fmtNow()); !ok {
		t.Fatal("抢占第二作业失败")
	}
	req = httptest.NewRequest(http.MethodPost, "/api/v1/agent/jobs/"+other.ID+"/result",
		strings.NewReader(`{"hostname":"other-host","status":"succeeded"}`))
	req.SetPathValue("id", other.ID)
	req.Header.Set("Authorization", "Bearer test-agent-token")
	rec = httptest.NewRecorder()
	app.handleAgentJobResult(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("跨主机回传应拒绝：%d", rec.Code)
	}
}
