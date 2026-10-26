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
# CVE 情报密钥建议放系统环境变量，避免写进脚本
# $env:VULNAGENT_CVE_API_KEY = '...'
# Agent Harness：三项齐备才启用，建议从系统环境变量注入，不要写进脚本
# $env:VA_LLM_BASE_URL = 'https://ark.cn-beijing.volces.com/api/v3'
# $env:VA_LLM_API_KEY = '...'
# $env:VA_LLM_MODEL = 'deepseek-v4-1-flash-261017'

Write-Host "VulnAgent 生产模式启动：$env:VA_ADDR，数据目录 $env:VA_DATA_DIR" -ForegroundColor Cyan
Set-Location (Join-Path $root 'server')
& $exe server
