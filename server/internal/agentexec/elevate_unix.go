//go:build !windows

package agentexec

import (
	"context"
	"os"
	"os/exec"
)

// isElevated 当前进程是否具备 root 权限
func isElevated() bool { return os.Geteuid() == 0 }

// helperCommand 通过 sudo -n 调用 helper；需要在 sudoers 中预授权
func helperCommand(ctx context.Context, exe string) *exec.Cmd {
	return exec.CommandContext(ctx, "sudo", "-n", exe, "helper")
}
