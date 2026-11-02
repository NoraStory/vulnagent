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
	if cfg.GPUEnabled() {
		// 本地 vLLM / TensorRT-LLM 通常不校验 Key，但 OpenAI 客户端要求非空
		apiKey := cfg.GPUAPIKey
		if apiKey == "" {
			apiKey = "local"
		}
		a.gpuLLM = openai.New(openai.Config{
			BaseURL: cfg.GPUBaseURL,
			APIKey:  apiKey,
			Model:   cfg.GPUModel,
		})
		slog.Info("GPU 推理端点已配置", "model", cfg.GPUModel, "endpoint", cfg.GPUBaseURL)
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

// llmForHost 为指定主机选择模型端点：开启 GPU 加速且已配置 GPU 端点时优先使用 GPU。
func (a *App) llmForHost(h sshHost) ports.LLM {
	if h.GPUAccel && a.gpuLLM != nil {
		return a.gpuLLM
	}
	if a.harness == nil {
		return nil
	}
	return a.harness.LLM
}

// hostAccelerated 该主机是否实际使用 GPU 推理端点
func (a *App) hostAccelerated(h sshHost) bool {
	return h.GPUAccel && a.gpuLLM != nil
}
