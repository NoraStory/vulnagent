package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"vulnagent/server/internal/agentexec"
	"vulnagent/server/internal/collect"
)

// runAgentWatch 常驻运行：上报一次清单后循环拉取并执行主机作业。
func runAgentWatch(server, token string, interval, timeout time.Duration) error {
	if interval < 2*time.Second {
		interval = 2 * time.Second
	}
	report, err := collect.Collect(collect.Options{IncludeSelf: true})
	if err != nil {
		return fmt.Errorf("采集失败：%w", err)
	}
	if err := postAgentReport(server, token, report, timeout); err != nil {
		fmt.Fprintf(os.Stderr, "首次上报失败（将继续轮询作业）：%v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "已上报 %s：%d 个组件\n", report.Hostname, len(report.Components))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	exe, _ := os.Executable()
	fmt.Fprintf(os.Stderr, "Agent 常驻模式已启动：hostname=%s interval=%s\n", report.Hostname, interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		pollHostJobs(ctx, server, token, report.Hostname, exe)
		select {
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "Agent 常驻模式已停止")
			return nil
		case <-ticker.C:
		}
	}
}

func postAgentReport(server, token string, report collect.Report, timeout time.Duration) error {
	body, err := json.Marshal(report)
	if err != nil {
		return err
	}
	endpoint := trimServer(server) + "/api/v1/agent/report"
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("HTTP %d：%s", resp.StatusCode, string(data))
	}
	return nil
}

func pollHostJobs(ctx context.Context, server, token, hostname, exe string) {
	jobs, err := listHostJobs(ctx, server, token, hostname)
	if err != nil {
		fmt.Fprintf(os.Stderr, "拉取作业失败：%v\n", err)
		return
	}
	for _, envelope := range jobs {
		if ctx.Err() != nil {
			return
		}
		job := envelope.HostJob
		if !verifyJobSignature([]byte(token), job, envelope.Signature) {
			fmt.Fprintf(os.Stderr, "作业 %s 签名校验失败，已丢弃\n", job.ID)
			continue
		}
		claimedEnvelope, err := claimHostJob(ctx, server, token, hostname, job.ID)
		if err != nil {
			if err != errJobUnavailable {
				fmt.Fprintf(os.Stderr, "抢占作业 %s 失败：%v\n", job.ID, err)
			}
			continue
		}
		claimed := claimedEnvelope.HostJob
		if !verifyJobSignature([]byte(token), claimed, claimedEnvelope.Signature) {
			fmt.Fprintf(os.Stderr, "作业 %s 领取响应签名校验失败，已丢弃\n", claimed.ID)
			continue
		}
		fmt.Fprintf(os.Stderr, "执行作业 %s：%s\n", claimed.ID, claimed.Action)
		runCtx, cancel := context.WithTimeout(ctx, 130*time.Second)
		res := agentexec.ExecuteSmart(runCtx, agentexec.Request{
			JobID: claimed.ID, Action: claimed.Action, Params: json.RawMessage(claimed.Params),
		}, agentexec.DefaultOptions(), exe)
		cancel()
		if err := postJobResult(ctx, server, token, hostname, claimed.ID, res); err != nil {
			fmt.Fprintf(os.Stderr, "回传作业 %s 结果失败：%v\n", claimed.ID, err)
			continue
		}
		fmt.Fprintf(os.Stderr, "作业 %s 完成：%s（exit=%d，%dms）\n",
			claimed.ID, res.Status, res.ExitCode, res.DurationMs)
	}
}

var errJobUnavailable = fmt.Errorf("作业不可用")

func listHostJobs(ctx context.Context, server, token, hostname string) ([]signedJob, error) {
	endpoint := trimServer(server) + "/api/v1/agent/jobs?hostname=" + url.QueryEscape(hostname)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var payload struct {
		Jobs []signedJob `json:"jobs"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload); err != nil {
		return nil, err
	}
	return payload.Jobs, nil
}

func claimHostJob(ctx context.Context, server, token, hostname, jobID string) (signedJob, error) {
	body, _ := json.Marshal(map[string]string{"hostname": hostname})
	endpoint := trimServer(server) + "/api/v1/agent/jobs/" + url.PathEscape(jobID) + "/claim"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return signedJob{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return signedJob{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusConflict {
		return signedJob{}, errJobUnavailable
	}
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return signedJob{}, fmt.Errorf("HTTP %d：%s", resp.StatusCode, string(data))
	}
	var payload struct {
		Job signedJob `json:"job"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload); err != nil {
		return signedJob{}, err
	}
	return payload.Job, nil
}

func postJobResult(ctx context.Context, server, token, hostname, jobID string, res agentexec.Result) error {
	payload := map[string]any{
		"hostname":   hostname,
		"status":     res.Status,
		"output":     res.Output,
		"error":      res.Error,
		"exitCode":   res.ExitCode,
		"durationMs": res.DurationMs,
		"retryable":  res.Retryable,
	}
	body, _ := json.Marshal(payload)
	endpoint := trimServer(server) + "/api/v1/agent/jobs/" + url.PathEscape(jobID) + "/result"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("HTTP %d：%s", resp.StatusCode, string(data))
	}
	return nil
}

func trimServer(server string) string {
	for len(server) > 0 && server[len(server)-1] == '/' {
		server = server[:len(server)-1]
	}
	return server
}
