#Requires -Version 7.2
<#
.SYNOPSIS
  VulnAgent 控制面一键安装 / 升级脚本（Windows，PowerShell 7+）。

.DESCRIPTION
  完成环境检查、依赖安装（可选）、前端与后端构建、目录部署、.env 生成、
  计划任务注册、服务启动、健康检查与安装摘要输出。重复执行即为升级，
  默认保留数据目录与已有 .env。

.PARAMETER InstallDir
  安装目录。默认优先 E:\VulnAgent、D:\VulnAgent，最后回退到 LOCALAPPDATA。

.PARAMETER DataDir
  数据目录。默认 <InstallDir>\data，包含数据库、SSH 密钥与 Agent 令牌。

.PARAMETER Port
  控制面监听端口，默认 8787。

.PARAMETER AdminPassword
  首次初始化管理员（admin）的口令；不传则自动生成 20 位强口令。
  已有数据库时该参数不会覆盖现有口令。

.PARAMETER LLMBaseUrl / LLMApiKey / LLMModel
  OpenAI 兼容模型配置，三项齐备才启用 AI 助手与 Agent 自动执行。

.PARAMETER CVEApiKey
  可选的情报平台密钥（写入 VULNAGENT_CVE_API_KEY）。

.PARAMETER EnableHttpsCookie
  经反向代理终止 TLS 时启用 Secure Cookie（VA_COOKIE_SECURE=1）。

.PARAMETER OpenFirewall
  创建 Windows 防火墙入站规则（需要管理员权限）。

.PARAMETER InstallDeps
  缺少 Go / Node.js 时尝试通过 winget 自动安装。

.PARAMETER NoAgent
  不安装本机采集 Agent 计划任务。

.PARAMETER NoService
  不注册计划任务，仅以独立进程启动（适合临时验证）。

.PARAMETER SkipBuild
  跳过前端与后端构建，直接使用仓库内已有产物（server\bin\vulnagent.exe、web\dist）。

.PARAMETER Force
  覆盖已有安装目录中的二进制与前端产物，并更新 .env 中由参数指定的键。

.EXAMPLE
  pwsh -File deploy\windows\install.ps1 -Port 8787 -LLMBaseUrl https://ark.cn-beijing.volces.com/api/v3 -LLMApiKey "..." -LLMModel deepseek-v4-1-flash-261017

.EXAMPLE
  pwsh -File deploy\windows\install.ps1 -InstallDir E:\VulnAgent -InstallDeps -OpenFirewall
#>
[CmdletBinding()]
param(
    [string]$InstallDir,
    [string]$DataDir,
    [int]$Port = 8787,
    [string]$AdminPassword,
    [string]$LLMBaseUrl,
    [string]$LLMApiKey,
    [string]$LLMModel,
    [string]$CVEApiKey,
    [switch]$EnableHttpsCookie,
    [switch]$OpenFirewall,
    [switch]$InstallDeps,
    [switch]$NoAgent,
    [switch]$NoService,
    [switch]$SkipBuild,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------- 基础路径与默认值 ----------
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..') -ErrorAction SilentlyContinue
if (-not $repoRoot -or -not (Test-Path (Join-Path $repoRoot 'server\go.mod'))) {
    throw "未找到仓库根目录：请在仓库的 deploy\windows 目录下运行本脚本（需要 server\go.mod 与 web\package.json）。"
}
$repoRoot = $repoRoot.Path

if (-not $InstallDir) {
    if (Test-Path 'E:\') {
        $InstallDir = 'E:\VulnAgent'
    } elseif (Test-Path 'D:\') {
        $InstallDir = 'D:\VulnAgent'
    } else {
        $InstallDir = Join-Path $env:LOCALAPPDATA 'VulnAgent'
        Write-Warning "未发现 E:/D: 盘，安装目录回退到 $InstallDir（C 盘）。建议使用 -InstallDir 指定非系统盘。"
    }
}
$InstallDir = [System.IO.Path]::GetFullPath($InstallDir)
if (-not $DataDir) { $DataDir = Join-Path $InstallDir 'data' }
$DataDir = [System.IO.Path]::GetFullPath($DataDir)

$serverDir = Join-Path $InstallDir 'server'
$webDir = Join-Path $InstallDir 'web\dist'
$logDir = Join-Path $InstallDir 'logs'
$scriptDir = Join-Path $InstallDir 'scripts'
$envFile = Join-Path $InstallDir '.env'
$summaryFile = Join-Path $InstallDir 'install-summary.txt'
$taskServer = 'VulnAgentServer'
$taskAgent = 'VulnAgentAgent'

# ---------- 输出与日志 ----------
New-Item -ItemType Directory -Force -Path $InstallDir, $logDir | Out-Null
$logFile = Join-Path $logDir ("install-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + ".log")
try { Start-Transcript -Path $logFile -Append | Out-Null } catch { }

function Step([string]$Message) { Write-Host "`n=== $Message ===" -ForegroundColor Cyan }
function Ok([string]$Message) { Write-Host "  [OK] $Message" -ForegroundColor Green }
function Warn([string]$Message) { Write-Host "  [WARN] $Message" -ForegroundColor Yellow }
function Info([string]$Message) { Write-Host "  · $Message" -ForegroundColor Gray }
function Fail([string]$Message) { Write-Host "  [FAIL] $Message" -ForegroundColor Red; throw $Message }
function Have([string]$Command) { [bool](Get-Command $Command -ErrorAction SilentlyContinue) }

function Invoke-Native {
    param(
        [Parameter(Mandatory)][string]$File,
        [string[]]$Arguments = @(),
        [string]$WorkDir = (Get-Location).Path,
        [string]$Label = ''
    )
    Write-Host "  > $File $($Arguments -join ' ')" -ForegroundColor DarkGray
    Push-Location $WorkDir
    try {
        & $File @Arguments 2>&1 | ForEach-Object { Write-Host "    $_" }
        if ($LASTEXITCODE -ne 0) { throw "$Label 执行失败（exit $LASTEXITCODE）" }
    } finally {
        Pop-Location
    }
}

function Test-HttpReachable {
    param([string]$Url, [int]$TimeoutSec = 6)
    try {
        $response = Invoke-WebRequest -Uri $Url -Method Head -TimeoutSec $TimeoutSec -SkipHttpErrorCheck -MaximumRedirection 3
        return ($response.StatusCode -lt 500)
    } catch {
        try {
            $response = Invoke-WebRequest -Uri $Url -Method Get -TimeoutSec $TimeoutSec -SkipHttpErrorCheck -MaximumRedirection 3
            return ($response.StatusCode -lt 500)
        } catch {
            return $false
        }
    }
}

function Wait-Health {
    param([int]$Seconds = 40)
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $response = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/healthz" -TimeoutSec 3 -SkipHttpErrorCheck
            if ($response.StatusCode -eq 200) { return $true }
        } catch { }
        Start-Sleep -Seconds 1
    }
    return $false
}

function Set-PrivateAcl {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return }
    try {
        & icacls.exe $Path /inheritance:r /grant:r "${env:USERNAME}:(F)" 'SYSTEM:(F)' '*S-1-5-32-544:(F)' | Out-Null
    } catch {
        Warn "设置文件 ACL 失败：$Path"
    }
}

function Write-EnvFile {
    param([hashtable]$Values, [string[]]$Order)
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("# VulnAgent 配置（由 install.ps1 生成于 $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')）")
    $lines.Add("# 修改后需重启：pwsh -File `"$scriptDir\stop.ps1`"; pwsh -File `"$scriptDir\start.ps1`"")
    foreach ($key in $Order) {
        if ($Values.ContainsKey($key) -and $null -ne $Values[$key] -and "$($Values[$key])" -ne '') {
            $lines.Add("$key=$($Values[$key])")
        }
    }
    $lines.Add('')
    [System.IO.File]::WriteAllLines($envFile, $lines, (New-Object System.Text.UTF8Encoding($false)))
    Set-PrivateAcl $envFile
}

$script:exitCode = 0
try {
    Step '1/9 环境检查'
    if ($PSVersionTable.PSVersion.Major -lt 7) { Fail '需要 PowerShell 7.2 及以上版本（当前 $($PSVersionTable.PSVersion)）' }
    Ok "PowerShell $($PSVersionTable.PSVersion)"
    Ok "安装目录：$InstallDir"
    Ok "数据目录：$DataDir"

    $qualifier = [System.IO.Path]::GetPathRoot($InstallDir)
    try {
        $freeGB = [math]::Round((Get-PSDrive -Name $qualifier.TrimEnd('\').TrimEnd(':')).Free / 1GB, 1)
        if ($freeGB -lt 3) { Fail "安装盘剩余空间不足 3GB（当前 $freeGB GB）" }
        Ok "安装盘剩余空间：$freeGB GB"
    } catch {
        Warn '无法读取磁盘剩余空间'
    }

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) { Ok '当前为管理员权限' } else { Warn '当前非管理员：防火墙规则与全局计划任务可能失败' }

    $listener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($listener) {
        $ownerProc = Get-Process -Id $listener.OwningProcess -ErrorAction SilentlyContinue
        if ($ownerProc -and $ownerProc.ProcessName -like 'vulnagent*') {
            Warn "端口 $Port 已被现有 VulnAgent（PID $($ownerProc.Id)）占用，升级时将先停止"
        } else {
            Fail "端口 $Port 已被 $($ownerProc.ProcessName)（PID $($listener.OwningProcess)）占用，请使用 -Port 指定其他端口"
        }
    } else {
        Ok "端口 $Port 可用"
    }

    Step '2/9 构建工具检查'
    $goVersion = $null
    $nodeVersion = $null
    if ($SkipBuild) {
        if (-not (Test-Path (Join-Path $repoRoot 'server\bin\vulnagent.exe'))) { Fail '未找到 server\bin\vulnagent.exe，无法使用 -SkipBuild' }
        if (-not (Test-Path (Join-Path $repoRoot 'web\dist\index.html'))) { Fail '未找到 web\dist，无法使用 -SkipBuild' }
        Ok '已跳过构建工具检查（-SkipBuild）'
    } else {
        if (-not (Have 'go') -and $InstallDeps -and (Have 'winget')) {
            Warn '未检测到 Go，尝试通过 winget 安装 GoLang.Go'
            Invoke-Native -File 'winget' -Arguments @('install','--id','GoLang.Go','-e','--silent','--accept-source-agreements','--accept-package-agreements') -Label 'winget 安装 Go'
            $env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')
        }
        if (-not (Have 'node') -and $InstallDeps -and (Have 'winget')) {
            Warn '未检测到 Node.js，尝试通过 winget 安装 OpenJS.NodeJS.LTS'
            Invoke-Native -File 'winget' -Arguments @('install','--id','OpenJS.NodeJS.LTS','-e','--silent','--accept-source-agreements','--accept-package-agreements') -Label 'winget 安装 Node.js'
            $env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')
        }
        if (-not (Have 'go')) { Fail '未找到 go。请安装 Go 1.26+：winget install GoLang.Go，或重新运行并加 -InstallDeps' }
        if (-not (Have 'node')) { Fail '未找到 node。请安装 Node.js 20+：winget install OpenJS.NodeJS.LTS，或重新运行并加 -InstallDeps' }
        if (-not (Have 'npm')) { Fail '未找到 npm，请检查 Node.js 安装是否完整' }

        $goVersion = (& go version) -join ' '
        if ($goVersion -notmatch 'go(\d+)\.(\d+)') { Fail "无法识别 Go 版本：$goVersion" }
        if ([int]$Matches[1] -lt 1 -or ([int]$Matches[1] -eq 1 -and [int]$Matches[2] -lt 26)) {
            Fail "Go 版本过低（$goVersion），需要 1.26+"
        }
        Ok "Go：$goVersion"

        $nodeVersion = (& node --version) -join ' '
        if ($nodeVersion -notmatch 'v(\d+)') { Fail "无法识别 Node.js 版本：$nodeVersion" }
        if ([int]$Matches[1] -lt 20) { Fail "Node.js 版本过低（$nodeVersion），需要 20+" }
        Ok "Node.js：$nodeVersion / npm $((& npm --version) -join ' ')"
    }

    Step '3/9 外网连通性检查（失败仅告警）'
    $targets = @(
        @{ Name = 'CVE 情报源'; Url = 'https://cve.imfht.com' },
        @{ Name = 'OSV 漏洞库'; Url = 'https://api.osv.dev' },
        @{ Name = '命令参考 cheat.sh'; Url = 'https://cheat.sh/tar?T' }
    )
    if ($LLMBaseUrl) { $targets += @{ Name = '模型服务'; Url = $LLMBaseUrl } }
    foreach ($target in $targets) {
        if (Test-HttpReachable -Url $target.Url) { Ok "$($target.Name) 可访问" }
        else { Warn "$($target.Name) 不可访问（离线环境可稍后导入情报包）" }
    }

    Step '4/9 构建前端与后端'
    if ($SkipBuild) {
        $builtExe = Join-Path $repoRoot 'server\bin\vulnagent.exe'
        $builtWeb = Join-Path $repoRoot 'web\dist'
        Ok "使用已有产物：$builtExe"
    } else {
        Info '安装前端依赖（npm ci）…'
        $npmCiArgs = @('ci', '--no-audit', '--no-fund')
        if (-not (Test-Path (Join-Path $repoRoot 'web\package-lock.json'))) { $npmCiArgs = @('install', '--no-audit', '--no-fund') }
        Invoke-Native -File 'npm' -Arguments $npmCiArgs -WorkDir (Join-Path $repoRoot 'web') -Label 'npm ci'
        Info '构建前端（tsc + vite build）…'
        Invoke-Native -File 'npm' -Arguments @('run','build') -WorkDir (Join-Path $repoRoot 'web') -Label 'npm run build'

        Info '编译控制面（go build，静态单文件）…'
        $builtExe = Join-Path $env:TEMP ("vulnagent-install-" + [guid]::NewGuid().ToString('N') + ".exe")
        $env:GOFLAGS = '-mod=vendor'
        Invoke-Native -File 'go' -Arguments @('build','-trimpath','-ldflags','-s -w','-o',$builtExe,'.') -WorkDir (Join-Path $repoRoot 'server') -Label 'go build'
        $builtWeb = Join-Path $repoRoot 'web\dist'
    }
    if (-not (Test-Path $builtExe)) { Fail "未找到构建产物：$builtExe" }
    if (-not (Test-Path (Join-Path $builtWeb 'index.html'))) { Fail "未找到前端产物：$builtWeb" }
    Ok '构建产物就绪'

    Step '5/9 停止旧实例并部署文件'
    foreach ($task in @($taskServer, $taskAgent)) {
        $existingTask = Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
        if ($existingTask) {
            try { Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue } catch { }
            Ok "已停止计划任务 $task"
        }
    }
    $listener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($listener) {
        $ownerProc = Get-Process -Id $listener.OwningProcess -ErrorAction SilentlyContinue
        if ($ownerProc -and $ownerProc.ProcessName -like 'vulnagent*') {
            Stop-Process -Id $ownerProc.Id -Force
            Start-Sleep -Milliseconds 800
            Ok "已停止旧进程 PID $($ownerProc.Id)"
        }
    }

    New-Item -ItemType Directory -Force -Path $serverDir, $webDir, $scriptDir, $DataDir, $logDir | Out-Null
    Copy-Item $builtExe (Join-Path $serverDir 'vulnagent.exe') -Force
    Get-ChildItem -Path $webDir -Force | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Copy-Item -Path (Join-Path $builtWeb '*') -Destination $webDir -Recurse -Force
    Ok "已部署二进制与前端资源"

    Step '6/9 写入配置'
    $existingDb = Test-Path (Join-Path $DataDir 'vulnagent.db')
    $generatedPassword = $false
    if (-not $AdminPassword) {
        if ($existingDb) {
            $AdminPassword = ''
        } else {
            $raw = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(15))
            $AdminPassword = 'Va' + $raw.Replace('/','x').Replace('+','y').Replace('=','') + '2026!'
            $generatedPassword = $true
        }
    }
    if ($AdminPassword -and $AdminPassword.Length -lt 10) { Fail '管理员口令至少 10 位' }

    $values = @{}
    $order = @(
        'VA_ADDR','VA_DATA_DIR','VA_WEB_DIST','VA_SEED_DEMO','VA_SESSION_IDLE',
        'VA_RESCAN_INTERVAL','VA_RESCAN_DEBOUNCE','VA_SYNC_INTERVAL','VA_COOKIE_SECURE',
        'VA_ADMIN_PASSWORD','VULNAGENT_CVE_API_KEY','VA_LLM_BASE_URL','VA_LLM_API_KEY','VA_LLM_MODEL'
    )
    if (Test-Path $envFile) {
        foreach ($line in Get-Content $envFile) {
            $trim = $line.Trim()
            if ($trim -eq '' -or $trim.StartsWith('#')) { continue }
            $idx = $trim.IndexOf('=')
            if ($idx -gt 0) { $values[$trim.Substring(0,$idx)] = $trim.Substring($idx+1) }
        }
        Copy-Item $envFile "$envFile.bak-$(Get-Date -Format 'yyyyMMdd-HHmmss')" -Force
        Ok '已检测到现有 .env，沿用并合并配置'
    }
    $values['VA_ADDR'] = ":$Port"
    $values['VA_DATA_DIR'] = $DataDir
    $values['VA_WEB_DIST'] = $webDir
    $values['VA_SEED_DEMO'] = 'off'
    $values['VA_SESSION_IDLE'] = '30m'
    $values['VA_RESCAN_INTERVAL'] = '30m'
    $values['VA_RESCAN_DEBOUNCE'] = '10m'
    $values['VA_SYNC_INTERVAL'] = '12h'
    if ($EnableHttpsCookie) { $values['VA_COOKIE_SECURE'] = '1' }
    if ($AdminPassword) { $values['VA_ADMIN_PASSWORD'] = $AdminPassword }
    if ($CVEApiKey) { $values['VULNAGENT_CVE_API_KEY'] = $CVEApiKey }
    if ($LLMBaseUrl) { $values['VA_LLM_BASE_URL'] = $LLMBaseUrl }
    if ($LLMApiKey) { $values['VA_LLM_API_KEY'] = $LLMApiKey }
    if ($LLMModel) { $values['VA_LLM_MODEL'] = $LLMModel }

    Write-EnvFile -Values $values -Order $order
    Ok "配置已写入：$envFile"
    if ($generatedPassword) { Ok '已生成管理员初始口令（见安装摘要）' }
    if ($existingDb) { Warn '检测到已有数据库：管理员口令沿用现有值，本次生成的配置不会重置它' }

    Step '7/9 生成运维脚本'
    $startScript = @"
`$ErrorActionPreference = 'Stop'
`$root = Split-Path -Parent `$PSScriptRoot
`$logDir = Join-Path `$root 'logs'
New-Item -ItemType Directory -Force `$logDir | Out-Null
`$log = Join-Path `$logDir 'server.log'
if ((Test-Path `$log) -and ((Get-Item `$log).Length -gt 20MB)) { Move-Item `$log "`$log.1" -Force }
Set-Location (Join-Path `$root 'server')
& (Join-Path `$root 'server\vulnagent.exe') server *>> `$log
"@
    [System.IO.File]::WriteAllText((Join-Path $scriptDir 'start.ps1'), $startScript, (New-Object System.Text.UTF8Encoding($false)))

    $stopScript = @"
`$port = $Port
`$listener = Get-NetTCPConnection -LocalPort `$port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
if (`$listener) {
    Stop-Process -Id `$listener.OwningProcess -Force
    Write-Host "已停止 VulnAgent（PID `$(`$listener.OwningProcess)）" -ForegroundColor Green
} else {
    Write-Host "端口 `$port 没有运行中的 VulnAgent" -ForegroundColor Yellow
}
foreach (`$task in @('$taskServer','$taskAgent')) {
    if (Get-ScheduledTask -TaskName `$task -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName `$task -ErrorAction SilentlyContinue
        Write-Host "已停止计划任务 `$task" -ForegroundColor Green
    }
}
"@
    [System.IO.File]::WriteAllText((Join-Path $scriptDir 'stop.ps1'), $stopScript, (New-Object System.Text.UTF8Encoding($false)))

    $statusScript = @"
`$port = $Port
`$listener = Get-NetTCPConnection -LocalPort `$port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
`$health = 0
try { `$health = (Invoke-WebRequest -Uri "http://127.0.0.1:`$port/healthz" -TimeoutSec 5 -SkipHttpErrorCheck).StatusCode } catch { }
Write-Host "端口 `$port：" -NoNewline
if (`$listener) { Write-Host "监听中（PID `$(`$listener.OwningProcess)）" -ForegroundColor Green } else { Write-Host "未监听" -ForegroundColor Red }
Write-Host "健康检查：HTTP `$health"
foreach (`$task in @('$taskServer','$taskAgent')) {
    `$info = Get-ScheduledTask -TaskName `$task -ErrorAction SilentlyContinue
    if (`$info) { Write-Host "计划任务 `$task：`$(`$info.State)" }
}
`$log = Join-Path (Split-Path -Parent `$PSScriptRoot) 'logs\server.log'
if (Test-Path `$log) {
    Write-Host "`n最近日志："
    Get-Content `$log -Tail 20
}
"@
    [System.IO.File]::WriteAllText((Join-Path $scriptDir 'status.ps1'), $statusScript, (New-Object System.Text.UTF8Encoding($false)))

    $backupScript = @"
`$root = Split-Path -Parent `$PSScriptRoot
`$dir = Join-Path `$root 'backups'
New-Item -ItemType Directory -Force `$dir | Out-Null
`$out = Join-Path `$dir ("vulnagent-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + ".db")
Set-Location (Join-Path `$root 'server')
& (Join-Path `$root 'server\vulnagent.exe') backup --out `$out
if (`$LASTEXITCODE -eq 0) { Write-Host "备份完成：`$out" -ForegroundColor Green } else { Write-Host "备份失败" -ForegroundColor Red }
"@
    [System.IO.File]::WriteAllText((Join-Path $scriptDir 'backup.ps1'), $backupScript, (New-Object System.Text.UTF8Encoding($false)))

    $agentScript = @"
`$ErrorActionPreference = 'Stop'
`$root = Split-Path -Parent `$PSScriptRoot
`$logDir = Join-Path `$root 'logs'
New-Item -ItemType Directory -Force `$logDir | Out-Null
`$log = Join-Path `$logDir 'agent.log'
if ((Test-Path `$log) -and ((Get-Item `$log).Length -gt 10MB)) { Move-Item `$log "`$log.1" -Force }
& (Join-Path `$root 'server\vulnagent.exe') agent --server "http://127.0.0.1:$Port" --token-file (Join-Path `$root 'data\agent.token') --watch --interval 15s *>> `$log
"@
    [System.IO.File]::WriteAllText((Join-Path $scriptDir 'agent.ps1'), $agentScript, (New-Object System.Text.UTF8Encoding($false)))

    $uninstallScript = @"
param([switch]`$Purge)
`$root = Split-Path -Parent `$PSScriptRoot
`$port = $Port
`$listener = Get-NetTCPConnection -LocalPort `$port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
if (`$listener) { Stop-Process -Id `$listener.OwningProcess -Force -ErrorAction SilentlyContinue }
foreach (`$task in @('$taskServer','$taskAgent')) {
    if (Get-ScheduledTask -TaskName `$task -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName `$task -Confirm:`$false
        Write-Host "已移除计划任务 `$task"
    }
}
if (`$Purge) {
    Set-Location `$env:SystemDrive\
    Get-ChildItem -LiteralPath `$root -Force -Recurse -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending |
        Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath `$root -Force -Recurse -ErrorAction SilentlyContinue
    if (Test-Path `$root) {
        Write-Host "部分文件未能删除（可能被占用），请关闭资源管理器/杀毒扫描后重试：`$root" -ForegroundColor Yellow
    } else {
        Write-Host '已删除安装目录（含数据）' -ForegroundColor Yellow
    }
} else {
    Write-Host '已停止服务并移除自启动；安装目录与数据保留。加 -Purge 可彻底删除。' -ForegroundColor Green
}
"@
    [System.IO.File]::WriteAllText((Join-Path $scriptDir 'uninstall.ps1'), $uninstallScript, (New-Object System.Text.UTF8Encoding($false)))
    Ok "已生成 $scriptDir 下的 start/stop/status/backup/agent/uninstall 脚本"

    Step '8/9 注册自启动并启动服务'
    $started = $false
    if (-not $NoService) {
        try {
            $pwshPath = (Get-Command pwsh).Source
            $action = New-ScheduledTaskAction -Execute $pwshPath -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptDir\start.ps1`""
            $trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
            Register-ScheduledTask -TaskName $taskServer -Action $action -Trigger $trigger -Settings $settings -Description 'VulnAgent 控制面（API + Web）' -Force | Out-Null
            Start-ScheduledTask -TaskName $taskServer
            $started = $true
            Ok "已注册并启动计划任务 $taskServer"
        } catch {
            Warn "计划任务注册失败：$($_.Exception.Message)。将以独立进程启动，重启后需手动运行 start.ps1。"
        }
    }
    if (-not $started) {
        $cmdLine = '"' + (Join-Path $serverDir 'vulnagent.exe') + '" server'
        Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
            CommandLine = $cmdLine; CurrentDirectory = $serverDir
        } | Out-Null
        Ok '已以独立进程启动（无自启动）'
    }

    if (-not (Wait-Health -Seconds 40)) {
        $serverLog = Join-Path $logDir 'server.log'
        if (Test-Path $serverLog) {
            Write-Host "`n最近服务日志：" -ForegroundColor Yellow
            Get-Content $serverLog -Tail 40
        }
        Fail "健康检查失败：http://127.0.0.1:$Port/healthz 未在 40 秒内返回 200"
    }
    Ok "健康检查通过：http://127.0.0.1:$Port/healthz"

    if (-not $NoAgent) {
        $tokenFile = Join-Path $DataDir 'agent.token'
        $deadline = (Get-Date).AddSeconds(20)
        while (-not (Test-Path $tokenFile) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
        if (Test-Path $tokenFile) {
            if (-not $NoService) {
                try {
                    $pwshPath = (Get-Command pwsh).Source
                    $agentAction = New-ScheduledTaskAction -Execute $pwshPath -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptDir\agent.ps1`""
                    $agentTrigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
                    $agentSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
                    Register-ScheduledTask -TaskName $taskAgent -Action $agentAction -Trigger $agentTrigger -Settings $agentSettings -Description 'VulnAgent 本机采集与上报' -Force | Out-Null
                    Start-ScheduledTask -TaskName $taskAgent
                    Ok "已注册并启动计划任务 $taskAgent"
                } catch {
                    Warn "Agent 计划任务注册失败：$($_.Exception.Message)"
                }
            }
        } else {
            Warn '未找到 agent.token，已跳过本机 Agent 安装'
        }
    }

    Step '9/9 写入安装摘要'
    $summary = @()
    $summary += 'VulnAgent 安装摘要'
    $summary += "生成时间：$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $summary += "访问地址：http://127.0.0.1:$Port"
    $summary += '管理员账号：admin'
    if ($AdminPassword) { $summary += "管理员口令：$AdminPassword" } else { $summary += '管理员口令：沿用现有数据库（本脚本未修改）' }
    $summary += "安装目录：$InstallDir"
    $summary += "数据目录：$DataDir"
    $summary += "配置文件：$envFile"
    $summary += "日志目录：$logDir"
    $summary += "安装日志：$logFile"
    $summary += ''
    $summary += '常用命令（PowerShell 7）：'
    $summary += "  pwsh -File `"$scriptDir\status.ps1`""
    $summary += "  pwsh -File `"$scriptDir\stop.ps1`""
    $summary += "  pwsh -File `"$scriptDir\start.ps1`""
    $summary += "  pwsh -File `"$scriptDir\backup.ps1`""
    $summary += "  pwsh -File `"$scriptDir\uninstall.ps1`""
    $summary += ''
    $summary += '后续建议：'
    $summary += '  1. 修改 .env 中的模型/情报密钥后重启服务'
    $summary += '  2. 对外提供服务时使用反向代理终止 TLS，并设置 VA_COOKIE_SECURE=1'
    $summary += "  3. 定期执行 backup.ps1，备份目录：$(Join-Path $InstallDir 'backups')"
    [System.IO.File]::WriteAllLines($summaryFile, $summary, (New-Object System.Text.UTF8Encoding($false)))
    Set-PrivateAcl $summaryFile

    if ($OpenFirewall) {
        if ($isAdmin) {
            try {
                New-NetFirewallRule -DisplayName "VulnAgent $Port" -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow -Profile Any -Force | Out-Null
                Ok "已创建防火墙入站规则（TCP $Port）"
            } catch {
                Warn "创建防火墙规则失败：$($_.Exception.Message)"
            }
        } else {
            Warn '未以管理员运行，跳过防火墙规则'
        }
    }

    Write-Host "`n安装完成。" -ForegroundColor Green
    Write-Host "访问地址：http://127.0.0.1:$Port" -ForegroundColor Cyan
    Write-Host "管理员：admin / $AdminPassword" -ForegroundColor Cyan
    Write-Host "安装摘要：$summaryFile" -ForegroundColor Cyan
    Write-Host "日志目录：$logDir" -ForegroundColor Cyan
} catch {
    $script:exitCode = 1
    Write-Host "`n安装失败：$($_.Exception.Message)" -ForegroundColor Red
    Write-Host "请查看安装日志：$logFile" -ForegroundColor Yellow
    throw
} finally {
    try { Stop-Transcript | Out-Null } catch { }
}

if ($script:exitCode -ne 0) { exit $script:exitCode }
