package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"vulnagent/server/internal/agentexec"
)

// runHelperCommand 提权 helper：从 stdin 读取动作请求并执行白名单动作。
// Linux 通过 sudoers 授权 `vulnagent helper`；Windows 需要 Agent 以管理员/SYSTEM 运行。
func runHelperCommand() {
	data, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	if err != nil {
		writeHelperResult(agentexec.Result{Status: "failed", Error: "读取请求失败：" + err.Error()})
		return
	}
	var req agentexec.Request
	if err := json.Unmarshal(data, &req); err != nil {
		writeHelperResult(agentexec.Result{Status: "failed", Error: "请求不是合法 JSON"})
		return
	}
	res := agentexec.Execute(context.Background(), req, agentexec.HelperOptions())
	writeHelperResult(res)
}

func writeHelperResult(res agentexec.Result) {
	encoded, err := json.Marshal(res)
	if err != nil {
		fmt.Fprintf(os.Stdout, `{"status":"failed","error":"结果序列化失败"}`)
		return
	}
	_, _ = os.Stdout.Write(encoded)
}
