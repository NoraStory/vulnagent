package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// runtimeSettingDef 网页可调节的运行配置项。
// 优先级：网页保存的数据库值 > 环境变量/.env > 默认值。
type runtimeSettingDef struct {
	Key         string
	Group       string
	Label       string
	Description string
	Kind        string // text|url|secret|int|duration|bool
	MinRole     string
	Default     string
	Placeholder string
	Restart     bool
}

var runtimeSettingDefs = []runtimeSettingDef{
	{Key: "VA_LLM_BASE_URL", Group: "AI 模型", Label: "模型地址", Kind: "url", MinRole: "admin", Restart: true,
		Description: "OpenAI 兼容 Chat Completions 地址，例如 https://ark.cn-beijing.volces.com/api/v3", Placeholder: "https://…/v1"},
	{Key: "VA_LLM_API_KEY", Group: "AI 模型", Label: "模型密钥", Kind: "secret", MinRole: "admin", Restart: true,
		Description: "仅写入，不回显；留空表示保持现有值", Placeholder: "sk-…"},
	{Key: "VA_LLM_MODEL", Group: "AI 模型", Label: "模型名称", Kind: "text", MinRole: "operator", Restart: true,
		Description: "例如 deepseek-v4-1-flash-261017；运维可调整模型名", Placeholder: "deepseek-v4-1-flash-261017"},
	{Key: "VA_GPU_LLM_BASE_URL", Group: "GPU 推理", Label: "GPU 端点", Kind: "url", MinRole: "admin", Restart: true,
		Description: "OpenAI 兼容本地推理端点（vLLM / TensorRT-LLM），与模型名称齐备才启用", Placeholder: "http://127.0.0.1:8000/v1"},
	{Key: "VA_GPU_LLM_API_KEY", Group: "GPU 推理", Label: "GPU 端点密钥", Kind: "secret", MinRole: "admin", Restart: true,
		Description: "本地服务不校验时可留空；仅写入，不回显", Placeholder: "local"},
	{Key: "VA_GPU_LLM_MODEL", Group: "GPU 推理", Label: "GPU 模型名称", Kind: "text", MinRole: "admin", Restart: true,
		Description: "GPU 端点上的模型名称，按主机加速开关生效", Placeholder: "Qwen2.5-32B-Instruct"},
	{Key: "VA_AGENT_CONTEXT_BUDGET", Group: "AI 模型", Label: "上下文预算", Kind: "int", MinRole: "operator",
		Description: "Agent/问答上下文 token 预算，范围 4000–1000000（长上下文模型可调到 1M）", Placeholder: "16000"},
	{Key: "VA_SYNC_INTERVAL", Group: "情报与扫描", Label: "情报同步周期", Kind: "duration", MinRole: "admin", Default: "12h", Restart: true,
		Description: "CVE/POC 定时同步周期，支持 30m/12h，0 或 off 关闭", Placeholder: "12h"},
	{Key: "VA_RESCAN_INTERVAL", Group: "情报与扫描", Label: "定时复扫周期", Kind: "duration", MinRole: "admin", Default: "30m", Restart: true,
		Description: "全部资产定时复扫周期，0 或 off 关闭", Placeholder: "30m"},
	{Key: "VA_RESCAN_DEBOUNCE", Group: "情报与扫描", Label: "复扫最小间隔", Kind: "duration", MinRole: "admin", Default: "10m", Restart: true,
		Description: "同一资产两次复扫的最小间隔", Placeholder: "10m"},
	{Key: "VULNAGENT_CVE_BASE_URL", Group: "情报与扫描", Label: "CVE 情报源", Kind: "url", MinRole: "admin",
		Description: "漏洞平台 API 根地址，留空使用默认值", Placeholder: "https://cve.imfht.com"},
	{Key: "VA_EPSS_URL", Group: "情报与扫描", Label: "EPSS 数据源", Kind: "url", MinRole: "admin",
		Description: "EPSS 全量评分 gzip CSV 地址", Placeholder: "https://epss.cyentia.com/epss_scores-current.csv.gz"},
	{Key: "VA_OSV_URL", Group: "情报与扫描", Label: "OSV 接口", Kind: "url", MinRole: "admin",
		Description: "OSV 精确版本查询接口", Placeholder: "https://api.osv.dev/v1/query"},
	{Key: "VA_SESSION_IDLE", Group: "安全", Label: "会话空闲过期", Kind: "duration", MinRole: "admin", Default: "30m",
		Description: "登录会话空闲多久后失效，例如 30m", Placeholder: "30m"},
	{Key: "VA_COOKIE_SECURE", Group: "安全", Label: "Secure Cookie", Kind: "bool", MinRole: "admin", Default: "off",
		Description: "HTTPS 反向代理部署时开启，只允许通过 HTTPS 发送会话 Cookie", Placeholder: "off"},
}

func runtimeSettingDefFor(key string) (runtimeSettingDef, bool) {
	for _, def := range runtimeSettingDefs {
		if def.Key == key {
			return def, true
		}
	}
	return runtimeSettingDef{}, false
}

// runtimeEnvSnapshot 保存网页覆盖前的环境变量值，清空网页配置时用于回退到 .env。
var runtimeEnvSnapshot map[string]string

func captureRuntimeEnvSnapshot() {
	if runtimeEnvSnapshot != nil {
		return
	}
	snapshot := make(map[string]string, len(runtimeSettingDefs))
	for _, def := range runtimeSettingDefs {
		snapshot[def.Key] = os.Getenv(def.Key)
	}
	runtimeEnvSnapshot = snapshot
}

func restoreRuntimeEnv(key string) {
	value := ""
	if runtimeEnvSnapshot != nil {
		value = runtimeEnvSnapshot[key]
	}
	if value == "" {
		_ = os.Unsetenv(key)
		return
	}
	_ = os.Setenv(key, value)
}

// runtimeSettingValue 返回给前端的配置项（密钥只返回是否已设置）
type runtimeSettingValue struct {
	Key         string `json:"key"`
	Group       string `json:"group"`
	Label       string `json:"label"`
	Description string `json:"description"`
	Kind        string `json:"kind"`
	MinRole     string `json:"minRole"`
	Default     string `json:"default"`
	Placeholder string `json:"placeholder"`
	Restart     bool   `json:"restart"`
	Value       string `json:"value"`
	HasValue    bool   `json:"hasValue"`
	Source      string `json:"source"`
	UpdatedBy   string `json:"updatedBy"`
	UpdatedAt   string `json:"updatedAt"`
}

func settingSource(dbValue, envValue string) string {
	if dbValue != "" {
		return "db"
	}
	if envValue != "" {
		return "env"
	}
	return "default"
}

// handleRuntimeSettings 读取网页可调节的运行配置（viewer+）。
func (a *App) handleRuntimeSettings(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "viewer"); !ok {
		return
	}
	rows, err := a.db.QueryContext(r.Context(), `SELECT key, value, secret, updated_by, updated_at FROM app_settings`)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取运行配置失败")
		return
	}
	defer rows.Close()
	stored := make(map[string]struct {
		value     string
		secret    bool
		updatedBy string
		updatedAt string
	})
	for rows.Next() {
		var key, value, updatedBy, updatedAt string
		var secret int
		if err := rows.Scan(&key, &value, &secret, &updatedBy, &updatedAt); err != nil {
			continue
		}
		stored[key] = struct {
			value     string
			secret    bool
			updatedBy string
			updatedAt string
		}{value: value, secret: secret == 1, updatedBy: updatedBy, updatedAt: updatedAt}
	}
	items := make([]runtimeSettingValue, 0, len(runtimeSettingDefs))
	for _, def := range runtimeSettingDefs {
		envValue := strings.TrimSpace(os.Getenv(def.Key))
		item := runtimeSettingValue{
			Key: def.Key, Group: def.Group, Label: def.Label, Description: def.Description,
			Kind: def.Kind, MinRole: def.MinRole, Default: def.Default, Placeholder: def.Placeholder,
			Restart: def.Restart,
		}
		if record, ok := stored[def.Key]; ok {
			item.HasValue = true
			item.Source = "db"
			item.UpdatedBy = record.updatedBy
			item.UpdatedAt = record.updatedAt
			if def.Kind == "secret" {
				item.Value = ""
			} else {
				item.Value = record.value
			}
		} else {
			item.Source = settingSource("", envValue)
			item.HasValue = envValue != ""
			if def.Kind != "secret" {
				item.Value = envValue
			}
		}
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

type runtimeSettingUpdate struct {
	Values map[string]string `json:"values"`
}

// handleRuntimeSettingsUpdate 保存运行配置（按配置项要求 admin/operator）。
func (a *App) handleRuntimeSettingsUpdate(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "operator")
	if !ok {
		return
	}
	var req runtimeSettingUpdate
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	if len(req.Values) == 0 {
		writeErr(w, http.StatusBadRequest, "bad_request", "没有需要保存的配置")
		return
	}
	changed := make([]string, 0, len(req.Values))
	restart := false
	for key, raw := range req.Values {
		def, exists := runtimeSettingDefFor(key)
		if !exists {
			writeErr(w, http.StatusBadRequest, "bad_request", "不支持的配置项："+key)
			return
		}
		if roleRank(u.Role) < roleRank(def.MinRole) {
			writeErr(w, http.StatusForbidden, "forbidden", "无权修改配置项："+def.Label)
			return
		}
		value := strings.TrimSpace(raw)
		if def.Kind == "secret" && value == "********" {
			continue
		}
		if err := validateRuntimeSetting(def, value); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", def.Label+"："+err.Error())
			return
		}
		if value == "" {
			if _, err := a.db.ExecContext(r.Context(), `DELETE FROM app_settings WHERE key = ?`, key); err != nil {
				writeErr(w, http.StatusInternalServerError, "internal_error", "保存运行配置失败")
				return
			}
			_ = os.Unsetenv(key)
			restoreRuntimeEnv(key)
		} else {
			storeValue := value
			secret := 0
			if def.Kind == "secret" {
				sealed, err := a.sealSSHSecret(value)
				if err != nil {
					writeErr(w, http.StatusInternalServerError, "internal_error", "加密配置失败")
					return
				}
				storeValue, secret = sealed, 1
			}
			if _, err := a.db.ExecContext(r.Context(), `INSERT INTO app_settings(key, value, secret, updated_by, updated_at)
				VALUES(?,?,?,?,?)
				ON CONFLICT(key) DO UPDATE SET value=excluded.value, secret=excluded.secret,
					updated_by=excluded.updated_by, updated_at=excluded.updated_at`,
				key, storeValue, secret, u.Username, fmtT(nowT())); err != nil {
				writeErr(w, http.StatusInternalServerError, "internal_error", "保存运行配置失败")
				return
			}
			_ = os.Setenv(key, value)
		}
		changed = append(changed, key)
		if def.Restart {
			restart = true
		}
	}
	if len(changed) == 0 {
		writeErr(w, http.StatusBadRequest, "bad_request", "没有实际变更")
		return
	}
	a.audit(r, "settings.runtime.update", "runtime", fmt.Sprintf("更新 %d 项：%s", len(changed), strings.Join(changed, ", ")))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "changed": changed, "restartRequired": restart,
		"message": map[bool]string{true: "已保存，部分配置需重启服务后生效", false: "已保存并生效"}[restart],
	})
}

func validateRuntimeSetting(def runtimeSettingDef, value string) error {
	if value == "" {
		return nil
	}
	if len(value) > 4096 {
		return fmt.Errorf("内容过长")
	}
	switch def.Kind {
	case "url":
		if !strings.HasPrefix(value, "http://") && !strings.HasPrefix(value, "https://") {
			return fmt.Errorf("必须以 http:// 或 https:// 开头")
		}
	case "int":
		number, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("必须是整数")
		}
		if def.Key == "VA_AGENT_CONTEXT_BUDGET" && (number < agentContextBudgetMin || number > agentContextBudgetMax) {
			return fmt.Errorf("必须在 %d–%d 之间", agentContextBudgetMin, agentContextBudgetMax)
		}
	case "duration":
		if value == "0" || strings.EqualFold(value, "off") {
			return nil
		}
		duration, err := time.ParseDuration(value)
		if err != nil || duration <= 0 {
			return fmt.Errorf("必须是有效时长，例如 30m、12h，或 0/off")
		}
	case "bool":
		switch strings.ToLower(value) {
		case "1", "0", "on", "off", "true", "false", "yes", "no":
			return nil
		default:
			return fmt.Errorf("必须是 1/0、on/off 或 true/false")
		}
	}
	return nil
}

// applyStoredRuntimeSettings 启动时把网页保存的配置写入进程环境，
// 让既有的 config.Load() 调用点无需改动即可读取覆盖值。
func (a *App) applyStoredRuntimeSettings(ctx context.Context) error {
	captureRuntimeEnvSnapshot()
	rows, err := a.db.QueryContext(ctx, `SELECT key, value, secret FROM app_settings`)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var key, value string
		var secret int
		if err := rows.Scan(&key, &value, &secret); err != nil {
			continue
		}
		if _, ok := runtimeSettingDefFor(key); !ok {
			continue
		}
		if secret == 1 {
			plain, err := a.openSSHSecret(value)
			if err != nil || plain == "" {
				continue
			}
			value = plain
		}
		_ = os.Setenv(key, value)
	}
	return rows.Err()
}
