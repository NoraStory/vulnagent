# VulnAgent 本机 Agent 常驻上报（Windows）
# 用法：右键“使用 PowerShell 运行”，或注册为登录自启任务
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$exe = Join-Path $root 'server\bin\vulnagent.exe'
if (-not (Test-Path $exe)) {
    throw "未找到 $exe，请先在 server 目录执行 go build -o bin\vulnagent.exe ."
}

$env:VA_DATA_DIR = Join-Path $root 'data-prod'
$token = Join-Path $env:VA_DATA_DIR 'agent.token'
if (-not (Test-Path $token)) {
    throw "未找到 $token，请先启动控制面生成全局令牌"
}

Write-Host "VulnAgent Agent 常驻上报：http://127.0.0.1:8787" -ForegroundColor Cyan
& $exe agent --server http://127.0.0.1:8787 --token-file $token --watch
