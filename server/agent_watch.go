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
	"path/filepath"
	"syscall"
	"time"

	"vulnagent/server/internal/agentexec"
	"vulnagent/server/internal/collect"
)

// runAgentWatch 常驻运行：上报清单与遥测，循环拉取并执行主机作业与 Agent 命令。
func runAgentWatch(server string, auth agentAuth, initial collect.Report, interval, reportInterval, timeout time.Duration) error {
	if interval < 2*time.Second {
		interval = 2 * time.Second
	}
	if reportInterval > 0 && reportInterval < time.Minute {
		reportInterval = time.Minute
	}
	report := initial
	if err := postAgentReport(server, auth, report, timeout); err != nil {
		fmt.Fprintf(os.Stderr, "首次上报失败（将继续轮询作业）：%v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "已上报 %s：%d 个组件\n", report.Hostname, len(report.Components))
	}
	hostname := report.Hostname
	sendHeartbeat(context.Background(), server, auth, report)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := flushAgentJobResults(ctx, server, auth); err != nil {
		fmt.Fprintf(os.Stderr, "续传历史作业结果失败（将继续重试）：%v\n", err)
	}
	exe, _ := os.Executable()
	fmt.Fprintf(os.Stderr, "Agent 常驻模式已启动：hostname=%s interval=%s reportInterval=%s enrolled=%v\n",
		hostname, interval, reportInterval, auth.enrolled())

	var reportCh <-chan time.Time
	if reportInterval > 0 {
		reportTicker := time.NewTicker(reportInterval)
		defer reportTicker.Stop()
		reportCh = reportTicker.C
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		pollHostJobs(ctx, server, auth, hostname, exe)
		sendHeartbeat(ctx, server, auth, report)
		runAgentCommands(ctx, server, auth, timeout)
		select {
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "Agent 常驻模式已停止")
			return nil
		case <-reportCh:
			fresh, err := collect.Collect(collect.Options{IncludeSelf: true})
			if err != nil {
				fmt.Fprintf(os.Stderr, "定时采集失败：%v\n", err)
				continue
			}
			report = fresh
			if err := postAgentReport(server, auth, fresh, timeout); err != nil {
				fmt.Fprintf(os.Stderr, "定时上报失败：%v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "已重新上报 %s：%d 个组件\n", fresh.Hostname, len(fresh.Components))
			}
		case <-ticker.C:
		}
	}
}

func postAgentReport(server string, auth agentAuth, report collect.Report, timeout time.Duration) error {
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
	auth.apply(req)
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

func pollHostJobs(ctx context.Context, server string, auth agentAuth, hostname, exe string) {
	if err := flushAgentJobResults(ctx, server, auth); err != nil {
		fmt.Fprintf(os.Stderr, "续传作业结果失败：%v\n", err)
		return
	}
	jobs, err := listHostJobs(ctx, server, auth, hostname)
	if err != nil {
		fmt.Fprintf(os.Stderr, "拉取作业失败：%v\n", err)
		return
	}
	for _, envelope := range jobs {
		if ctx.Err() != nil {
			return
		}
		job := envelope.HostJob
		if !verifyJobSignature(auth.signingKey(), job, envelope.Signature) {
			fmt.Fprintf(os.Stderr, "作业 %s 签名校验失败，已丢弃\n", job.ID)
			continue
		}
		claimedEnvelope, err := claimHostJob(ctx, server, auth, hostname, job.ID)
		if err != nil {
			if err != errJobUnavailable {
				fmt.Fprintf(os.Stderr, "抢占作业 %s 失败：%v\n", job.ID, err)
			}
			continue
		}
		claimed := claimedEnvelope.HostJob
		if !verifyJobSignature(auth.signingKey(), claimed, claimedEnvelope.Signature) {
			fmt.Fprintf(os.Stderr, "作业 %s 领取响应签名校验失败，已丢弃\n", claimed.ID)
			continue
		}
		fmt.Fprintf(os.Stderr, "执行作业 %s：%s\n", claimed.ID, claimed.Action)
		runCtx, cancel := context.WithTimeout(ctx, 130*time.Second)
		res := agentexec.ExecuteSmart(runCtx, agentexec.Request{
			JobID: claimed.ID, Action: claimed.Action, Params: json.RawMessage(claimed.Params),
		}, agentexec.DefaultOptions(), exe)
		cancel()
		pending := agentPendingResult{Hostname: hostname, JobID: claimed.ID, Attempt: claimed.Attempts, Result: res}
		if err := persistAgentJobResult(pending); err != nil {
			fmt.Fprintf(os.Stderr, "持久化作业 %s 结果失败：%v\n", claimed.ID, err)
			continue
		}
		if err := flushAgentJobResults(ctx, server, auth); err != nil {
			fmt.Fprintf(os.Stderr, "回传作业 %s 结果失败（已持久化，将自动重试）：%v\n", claimed.ID, err)
			continue
		}
		fmt.Fprintf(os.Stderr, "作业 %s 完成：%s（exit=%d，%dms）\n",
			claimed.ID, res.Status, res.ExitCode, res.DurationMs)
	}
}

var errJobUnavailable = fmt.Errorf("作业不可用")

func listHostJobs(ctx context.Context, server string, auth agentAuth, hostname string) ([]signedJob, error) {
	endpoint := trimServer(server) + "/api/v1/agent/jobs?hostname=" + url.QueryEscape(hostname)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	auth.apply(req)
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

func claimHostJob(ctx context.Context, server string, auth agentAuth, hostname, jobID string) (signedJob, error) {
	body, _ := json.Marshal(map[string]string{"hostname": hostname})
	endpoint := trimServer(server) + "/api/v1/agent/jobs/" + url.PathEscape(jobID) + "/claim"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return signedJob{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	auth.apply(req)
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

type agentPendingResult struct {
	Hostname string           `json:"hostname"`
	JobID    string           `json:"jobId"`
	Attempt  int              `json:"attempt"`
	Result   agentexec.Result `json:"result"`
}

func agentResultOutboxDir() string {
	return filepath.Join(dataDirFromEnv(), "agent-results")
}

func agentResultPath(pending agentPendingResult) string {
	return filepath.Join(agentResultOutboxDir(), fmt.Sprintf("%x-%d.json", pending.JobID, pending.Attempt))
}

// persistAgentJobResult 每个尝试单独落盘；成功回传后删除，崩溃重启可从目录恢复。
func persistAgentJobResult(pending agentPendingResult) error {
	if pending.JobID == "" || pending.Attempt <= 0 || pending.Hostname == "" {
		return fmt.Errorf("结果缺少 jobId、attempt 或 hostname")
	}
	if err := os.MkdirAll(agentResultOutboxDir(), 0o700); err != nil {
		return err
	}
	path := agentResultPath(pending)
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	data, err := json.Marshal(pending)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func loadAgentJobResults() ([]agentPendingResult, error) {
	entries, err := os.ReadDir(agentResultOutboxDir())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	items := make([]agentPendingResult, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(agentResultOutboxDir(), entry.Name()))
		if err != nil {
			return nil, err
		}
		var pending agentPendingResult
		if err := json.Unmarshal(data, &pending); err != nil {
			return nil, fmt.Errorf("解析结果文件 %s：%w", entry.Name(), err)
		}
		if pending.JobID == "" || pending.Attempt <= 0 || pending.Hostname == "" {
			return nil, fmt.Errorf("结果文件 %s 缺少必要字段", entry.Name())
		}
		items = append(items, pending)
	}
	return items, nil
}

func flushAgentJobResults(ctx context.Context, server string, auth agentAuth) error {
	items, err := loadAgentJobResults()
	if err != nil {
		return err
	}
	for _, pending := range items {
		if err := postJobResult(ctx, server, auth, pending); err != nil {
			return err
		}
		if err := os.Remove(agentResultPath(pending)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("清理已回传结果：%w", err)
		}
	}
	return nil
}

func postJobResult(ctx context.Context, server string, auth agentAuth, pending agentPendingResult) error {
	payload := map[string]any{
		"hostname":   pending.Hostname,
		"status":     pending.Result.Status,
		"output":     pending.Result.Output,
		"error":      pending.Result.Error,
		"exitCode":   pending.Result.ExitCode,
		"durationMs": pending.Result.DurationMs,
		"retryable":  pending.Result.Retryable,
		"attempt":    pending.Attempt,
	}
	body, _ := json.Marshal(payload)
	endpoint := trimServer(server) + "/api/v1/agent/jobs/" + url.PathEscape(pending.JobID) + "/result"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	auth.apply(req)
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
