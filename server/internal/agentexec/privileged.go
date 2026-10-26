package agentexec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// ExecuteSmart 优先直接执行；权限不足时通过 helper 提权重试。
func ExecuteSmart(ctx context.Context, req Request, opts Options, exe string) Result {
	if !NeedsPrivilege(req.Action) || isElevated() {
		return Execute(ctx, req, opts)
	}
	direct := Execute(ctx, req, opts)
	if direct.Status == "succeeded" {
		return direct
	}
	helper, err := runHelper(ctx, req, exe)
	if err != nil {
		direct.Error = fmt.Sprintf("%s；提权 helper 失败：%v", direct.Error, err)
		return direct
	}
	return helper
}

func runHelper(ctx context.Context, req Request, exe string) (Result, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return Result{}, err
	}
	runCtx, cancel := context.WithTimeout(ctx, 150*time.Second)
	defer cancel()
	cmd := helperCommand(runCtx, exe)
	cmd.Stdin = bytes.NewReader(payload)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := stderr.String()
		if msg == "" {
			msg = err.Error()
		}
		return Result{}, fmt.Errorf("%s", msg)
	}
	var res Result
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		return Result{}, fmt.Errorf("helper 返回格式错误：%w", err)
	}
	return res, nil
}

// HelperOptions 从环境变量读取策略，缺省使用平台默认值；专供 helper 进程使用。
func HelperOptions() Options {
	opts := DefaultOptions()
	opts.HelperMode = true
	return opts
}
