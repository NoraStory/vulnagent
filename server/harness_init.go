package main

import (
	"log/slog"

	harnessapp "vulnagent/server/internal/application/harness"
	"vulnagent/server/internal/application/ports"
	"vulnagent/server/internal/infrastructure/llm/openai"
	"vulnagent/server/internal/platform/config"
)

// initHarness 组装 Agent Harness。模型凭据缺失时服务仍启动，只是助手不可用。
func (a *App) initHarness(cfg config.Config) {
	var llm ports.LLM
	if cfg.HarnessEnabled() {
		llm = openai.New(openai.Config{
			BaseURL: cfg.LLMBaseURL,
			APIKey:  cfg.LLMAPIKey,
			Model:   cfg.LLMModel,
		})
	}
	a.harness = harnessapp.New(a.harnessRepo(), llm, harnessapp.NewRegistry(a.harnessTools()), a.verifyPassword)
	a.harness.Memory = a.memoryRepo()
	a.harness.SystemPrompt = harnessSystemPrompt()
	if a.harness.Available() {
		slog.Info("Agent Harness 已启用", "model", cfg.LLMModel, "tools", a.harness.Registry.Len())
	} else {
		slog.Info("Agent Harness 未启用", "hint", "设置 VA_LLM_BASE_URL / VA_LLM_API_KEY / VA_LLM_MODEL 后重启")
	}
}
