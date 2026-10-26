//go:build windows

package agentexec

import (
	"context"
	"os/exec"
)

// isElevated Windows 下无法可靠判断令牌提升状态；由直接执行失败后再尝试 helper。
func isElevated() bool { return false }

// helperCommand 仅当 Agent 以管理员/SYSTEM 运行时才能成功
func helperCommand(ctx context.Context, exe string) *exec.Cmd {
	return exec.CommandContext(ctx, exe, "helper")
}
