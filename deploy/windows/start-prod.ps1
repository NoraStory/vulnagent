# VulnAgent 生产模式启动脚本（Windows）
# 用法：右键“使用 PowerShell 运行”，或注册为登录自启任务
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$exe = Join-Path $root 'server\bin\vulnagent.exe'
if (-not (Test-Path $exe)) {
    throw "未找到 $exe，请先在 server 目录执行 go build -o bin\vulnagent.exe ."
}

$env:VA_DATA_DIR = Join-Path $root 'data-prod'
$env:VA_SEED_DEMO = 'off'
$env:VA_ADDR = ':8787'
# 情报定时同步：默认每 12 小时（设 0/off 关闭）
$env:VA_SYNC_INTERVAL = '12h'
# 经反向代理终止 TLS 后取消下一行注释
# $env:VA_COOKIE_SECURE = '1'
# 前置可信反向代理时开启，登录限速与审计按 X-Forwarded-For 取真实 IP
# $env:VA_TRUST_PROXY = '1'
# Prometheus 指标抓取专用令牌（未设置时兼容 Agent 令牌）
# $env:VA_METRICS_TOKEN = '...'
# CVE 情报密钥建议放系统环境变量，避免写进脚本
# $env:VULNAGENT_CVE_API_KEY = '...'
# Agent Harness：三项齐备才启用，建议从系统环境变量注入，不要写进脚本
# $env:VA_LLM_BASE_URL = 'https://ark.cn-beijing.volces.com/api/v3'
# $env:VA_LLM_API_KEY = '...'
# $env:VA_LLM_MODEL = 'deepseek-v4-1-flash-261017'
# 可选 GPU 推理端点（OpenAI 兼容，如 vLLM）：BASE_URL 与 MODEL 齐备即启用，按主机开关生效
# $env:VA_GPU_LLM_BASE_URL = 'http://127.0.0.1:8000/v1'
# $env:VA_GPU_LLM_API_KEY = 'local'
# $env:VA_GPU_LLM_MODEL = 'Qwen2.5-32B-Instruct'
# 可选上下文预算（4000–128000，默认 16000）
# $env:VA_AGENT_CONTEXT_BUDGET = '16000'

Write-Host "VulnAgent 生产模式启动：$env:VA_ADDR，数据目录 $env:VA_DATA_DIR" -ForegroundColor Cyan
Set-Location (Join-Path $root 'server')
& $exe server
