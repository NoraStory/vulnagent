package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"vulnagent/server/internal/collect"
	"vulnagent/server/internal/infrastructure/sqlite"
	"vulnagent/server/internal/platform/config"
)

const agentTokenFileName = "agent.token"

// ensureAgentToken 保证存在 Agent 接入令牌。
// 优先级：VA_AGENT_TOKEN > 数据目录下的 agent.token > 新生成（写入 0600 文件）。
// 数据库只保存 SHA-256 摘要，明文仅落在本机数据目录。
func ensureAgentToken(db *sql.DB, dataDir string) (string, error) {
	token := config.Load().AgentToken
	path := filepath.Join(dataDir, agentTokenFileName)
	source := "环境变量 VA_AGENT_TOKEN"

	if token == "" {
		if data, err := os.ReadFile(path); err == nil {
			token = strings.TrimSpace(string(data))
			source = "已有令牌文件"
		}
	}
	if token == "" {
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		token = hex.EncodeToString(buf)
		if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
			return "", err
		}
		source = "新生成令牌"
		slog.Warn("已生成 Agent 接入令牌（仅本机可读）", "file", path)
	}

	sum := sha256.Sum256([]byte(token))
	sumHex := hex.EncodeToString(sum[:])
	if err := sqlite.NewIdentityRepo(db).SaveTokenHash(context.Background(), sumHex, fmtT(nowT())); err != nil {
		return "", err
	}
	slog.Info("Agent 接入凭据就绪", "source", source, "file", path)
	return token, nil
}

func (a *App) agentAuthorized(r *http.Request) bool {
	_, ok := a.authenticateAgent(r)
	return ok
}

// handleAgentReport 接收 Agent 上报的 SBOM，落库后立即匹配。
func (a *App) handleAgentReport(w http.ResponseWriter, r *http.Request) {
	principal, ok := a.authenticateAgent(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthorized", "Agent 身份无效")
		return
	}

	var payload collect.Report
	dec := json.NewDecoder(io.LimitReader(r.Body, 8<<20))
	if err := dec.Decode(&payload); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "上报内容不是有效的 JSON")
		return
	}
	hostname := strings.TrimSpace(payload.Hostname)
	if hostname == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "缺少 hostname")
		return
	}
	if len(payload.Components) > 20000 {
		writeErr(w, http.StatusBadRequest, "too_many_components", "单次上报组件数超过 20000")
		return
	}

	components := append([]collect.Component{}, payload.Components...)
	for _, dep := range payload.SelfSBOM {
		dep.Source = "self"
		components = append(components, dep)
	}
	if len(components) > 20000 {
		writeErr(w, http.StatusBadRequest, "too_many_components", "单次上报组件数超过 20000")
		return
	}

	outcome, err := a.ingestComponents(hostname, payload.IP, payload.OS, payload.OSVersion, "agent", components)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db_error", "写入资产失败")
		return
	}
	if !principal.Legacy {
		if principal.Agent.ClusterID > 0 && outcome.AssetID > 0 {
			_, _ = a.db.ExecContext(r.Context(), `UPDATE assets SET cluster_id = ? WHERE id = ?`,
				principal.Agent.ClusterID, outcome.AssetID)
		}
		a.touchAgent(r.Context(), principal.Agent.ID, clientIP(r))
		_, _ = a.db.ExecContext(r.Context(), `UPDATE agents SET hostname=?, os=?, os_version=? WHERE id=?`,
			hostname, payload.OS, payload.OSVersion, principal.Agent.ID)
	}
	// 遥测写入失败不影响清单入库与漏洞匹配，只记录告警
	if payload.Telemetry != nil {
		if err := a.telemetryRepo().Save(r.Context(), outcome.AssetID, toPortsTelemetry(*payload.Telemetry)); err != nil {
			slog.Warn("主机遥测写入失败", "hostname", hostname, "assetId", outcome.AssetID, "err", err)
		}
	}

	actor := "Agent " + hostname
	if !principal.Legacy && principal.Agent.Name != "" {
		actor = "Agent " + principal.Agent.Name
	}
	a.auditAs(actor, "agent", clientIP(r), r.UserAgent(), "agent.report",
		fmt.Sprintf("%s · %d 个组件", hostname, outcome.Components),
		fmt.Sprintf("新增 %d 条漏洞，更新 %d 条，验证 %d 条，关闭 %d 条，重新打开 %d 条",
			outcome.Created, outcome.Updated, outcome.Verified, outcome.Closed, outcome.Reopened))
	slog.Info("Agent 上报完成", "hostname", hostname, "components", outcome.Components,
		"created", outcome.Created, "updated", outcome.Updated, "verified", outcome.Verified,
		"closed", outcome.Closed, "reopened", outcome.Reopened)

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"assetId":    outcome.AssetID,
		"components": outcome.Components,
		"created":    outcome.Created,
		"updated":    outcome.Updated,
		"verified":   outcome.Verified,
		"closed":     outcome.Closed,
		"reopened":   outcome.Reopened,
		"matchedAt":  fmtT(nowT()),
	})
}
