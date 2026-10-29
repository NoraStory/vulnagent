#!/usr/bin/env bash
# VulnAgent 控制面一键安装 / 升级脚本（Linux）
#
# 功能：环境检查 → 依赖与工具链（可选下载 Go/Node）→ 前端/后端构建 →
#       用户与目录、systemd 服务、环境变量、Agent 安装 → 健康检查与安装摘要。
#
# 用法：
#   sudo bash deploy/linux/install.sh
#   sudo bash deploy/linux/install.sh --port 8787 --llm-base-url ... --llm-api-key ... --llm-model ...
#   sudo bash deploy/linux/install.sh --install-deps --open-firewall
#   sudo bash deploy/linux/install.sh --no-agent --no-service --skip-build
#
# 说明：重复执行即为升级，默认保留数据与已有 /etc/vulnagent/server.env，
#       升级前自动备份数据库，失败时尝试回滚上一版二进制。

set -Eeuo pipefail

APP_NAME="vulnagent"
INSTALL_DIR="${VA_INSTALL_DIR:-/opt/vulnagent}"
DATA_DIR="${VA_DATA_DIR:-/var/lib/vulnagent}"
ENV_DIR="/etc/vulnagent"
PORT=8787
ADMIN_PASSWORD=""
LLM_BASE_URL=""
LLM_API_KEY=""
LLM_MODEL=""
CVE_API_KEY=""
COOKIE_SECURE=0
OPEN_FIREWALL=0
INSTALL_DEPS=0
WITH_AGENT=1
NO_SERVICE=0
SKIP_BUILD=0
GO_MIN_MINOR=26
NODE_MIN_MAJOR=20
NODE_MAJOR=22

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
LOG_DIR="${INSTALL_DIR}/logs"
SUMMARY_FILE="${ENV_DIR}/install-summary.txt"
SERVER_ENV="${ENV_DIR}/server.env"
AGENT_ENV="${ENV_DIR}/agent.env"
SERVER_UNIT="/etc/systemd/system/vulnagent-server.service"
AGENT_UNIT="/etc/systemd/system/vulnagent-agent.service"

C_RESET=$'\033[0m'; C_CYAN=$'\033[36m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_RED=$'\033[31m'; C_GRAY=$'\033[90m'
step() { echo; echo "${C_CYAN}=== $* ===${C_RESET}"; }
ok()   { echo "  ${C_GREEN}[OK]${C_RESET} $*"; }
warn() { echo "  ${C_YELLOW}[WARN]${C_RESET} $*"; }
info() { echo "  ${C_GRAY}·${C_RESET} $*"; }
die()  { echo "  ${C_RED}[FAIL]${C_RESET} $*" >&2; exit 1; }
trap 'die "第 $LINENO 行执行失败，请检查上方输出"' ERR

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
  cat <<'EOF'

参数：
  --dir PATH              安装目录（默认 /opt/vulnagent）
  --data PATH             数据目录（默认 /var/lib/vulnagent）
  --port PORT             监听端口（默认 8787）
  --admin-password VALUE  首次初始化 admin 口令（不传则自动生成）
  --llm-base-url URL      OpenAI 兼容模型地址
  --llm-api-key VALUE     模型密钥
  --llm-model NAME        模型名称
  --cve-api-key VALUE     情报平台密钥（可选）
  --https-cookie          启用 Secure Cookie（反向代理终止 TLS 时）
  --open-firewall         自动放行端口（ufw/firewalld）
  --install-deps          缺少 Go/Node 时下载官方工具链到安装目录
  --no-agent              不安装本机采集 Agent
  --no-service            不安装 systemd，以后台进程启动（临时验证）
  --skip-build            跳过构建，使用仓库内已有产物
  -h, --help              显示帮助
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir) INSTALL_DIR="$2"; shift 2 ;;
    --data) DATA_DIR="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --admin-password) ADMIN_PASSWORD="$2"; shift 2 ;;
    --llm-base-url) LLM_BASE_URL="$2"; shift 2 ;;
    --llm-api-key) LLM_API_KEY="$2"; shift 2 ;;
    --llm-model) LLM_MODEL="$2"; shift 2 ;;
    --cve-api-key) CVE_API_KEY="$2"; shift 2 ;;
    --https-cookie) COOKIE_SECURE=1; shift ;;
    --open-firewall) OPEN_FIREWALL=1; shift ;;
    --install-deps) INSTALL_DEPS=1; shift ;;
    --no-agent) WITH_AGENT=0; shift ;;
    --no-service) NO_SERVICE=1; shift ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "未知参数：$1（使用 --help 查看用法）" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "请使用 root 运行：sudo bash $0 $*"
[[ -f "${REPO_ROOT}/server/go.mod" ]] || die "未找到仓库根目录（需要 server/go.mod）：${REPO_ROOT}"
[[ "$PORT" =~ ^[0-9]+$ ]] && (( PORT > 0 && PORT < 65536 )) || die "端口不合法：$PORT"
for value in "$LLM_BASE_URL" "$LLM_API_KEY" "$LLM_MODEL" "$ADMIN_PASSWORD" "$CVE_API_KEY"; do
  [[ "$value" != *$'\n'* ]] || die "参数中不允许包含换行"
done

mkdir -p "$INSTALL_DIR" "$LOG_DIR" "$ENV_DIR"
chmod 0750 "$ENV_DIR" 2>/dev/null || true
LOG_FILE="${LOG_DIR}/install-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1

# 优先使用安装目录内的工具链，保证离线/重复安装可用
[[ -x "${INSTALL_DIR}/.toolchain/go/bin/go" ]] && export PATH="${INSTALL_DIR}/.toolchain/go/bin:${PATH}"
[[ -x "${INSTALL_DIR}/.toolchain/node/bin/node" ]] && export PATH="${INSTALL_DIR}/.toolchain/node/bin:${PATH}"

have() { command -v "$1" >/dev/null 2>&1; }
http_ok() { curl -fsS -o /dev/null -m 6 -I "$1" >/dev/null 2>&1 || curl -fsS -o /dev/null -m 6 "$1" >/dev/null 2>&1; }
rand_password() {
  local base
  base=$(head -c 32 /dev/urandom | base64 | tr -d '/+=\n' | cut -c1-16)
  echo "Va${base}2026!"
}
go_ok() {
  have go || return 1
  local version major minor
  version=$(go version | awk '{print $3}' | sed 's/^go//')
  major=${version%%.*}; minor=$(echo "$version" | cut -d. -f2)
  [[ "$major" -gt 1 || ( "$major" -eq 1 && "$minor" -ge "$GO_MIN_MINOR" ) ]]
}
node_ok() {
  have node || return 1
  local major
  major=$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)
  [[ "$major" -ge "$NODE_MIN_MAJOR" ]]
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *) die "不支持的 CPU 架构：$(uname -m)" ;;
  esac
}

pkg_install() {
  if have apt-get; then DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
  elif have dnf; then dnf install -y "$@"
  elif have yum; then yum install -y "$@"
  elif have apk; then apk add --no-cache "$@"
  else die "无法识别包管理器，请手动安装：$*"
  fi
}

step "1/9 环境检查"
[[ "$(uname -s)" == "Linux" ]] || die "仅支持 Linux"
ok "系统：$(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-Linux}" || uname -s)"
ok "内核：$(uname -r) / 架构：$(uname -m)"
ok "安装目录：$INSTALL_DIR"
ok "数据目录：$DATA_DIR"
free_kb=$(df -Pk "$(dirname "$INSTALL_DIR")" | awk 'NR==2 {print $4}')
(( free_kb >= 3*1024*1024 )) || die "磁盘剩余空间不足 3GB（当前 $((free_kb/1024/1024))GB）"
ok "磁盘剩余：$((free_kb/1024/1024))GB"
if ss -lntp 2>/dev/null | grep -q ":${PORT} "; then
  owner=$(ss -lntp 2>/dev/null | grep ":${PORT} " | head -1)
  if echo "$owner" | grep -q vulnagent; then warn "端口 $PORT 已被现有 VulnAgent 占用，升级时将重启服务"; else die "端口 $PORT 已被占用：$owner"; fi
else
  ok "端口 $PORT 可用"
fi
have curl || die "缺少 curl，请先安装：apt install curl / dnf install curl"
for tool in tar sha256sum; do have "$tool" || die "缺少基础命令：$tool"; done
ok "基础命令：curl / tar / sha256sum"

step "2/9 外网连通性检查（失败仅告警）"
for target in "https://cve.imfht.com|CVE 情报源" "https://api.osv.dev|OSV 漏洞库" "https://cheat.sh/tar?T|命令参考 cheat.sh"; do
  url=${target%%|*}; name=${target##*|}
  if http_ok "$url"; then ok "$name 可访问"; else warn "$name 不可访问（离线环境可后续导入情报包）"; fi
done
if [[ -n "$LLM_BASE_URL" ]]; then
  if http_ok "$LLM_BASE_URL"; then ok "模型服务可访问"; else warn "模型服务不可访问，AI 助手将不可用"; fi
fi

step "3/9 构建工具链"
if (( SKIP_BUILD == 1 )); then
  [[ -x "${REPO_ROOT}/server/bin/vulnagent" ]] || die "未找到 server/bin/vulnagent，无法 --skip-build"
  [[ -f "${REPO_ROOT}/web/dist/index.html" ]] || die "未找到 web/dist，无法 --skip-build"
  ok "使用仓库内已有产物"
else
  if ! go_ok || ! node_ok; then
    (( INSTALL_DEPS == 1 )) || die "缺少 Go ${GO_MIN_MINOR}+ 或 Node ${NODE_MIN_MAJOR}+；请加 --install-deps 自动下载，或先手动安装"
    arch=$(detect_arch)
    tc="${INSTALL_DIR}/.toolchain"
    mkdir -p "$tc"
    if ! go_ok; then
      info "解析 Go 最新稳定版本…"
      go_json=$(curl -fsSL --retry 3 --max-time 30 https://go.dev/dl/?mode=json) || die "无法访问 go.dev"
      go_version=$(printf '%s' "$go_json" | grep -o '"version": *"go[0-9.]*"' | head -1 | sed 's/.*go//;s/"//')
      [[ -n "$go_version" ]] || die "无法解析 Go 版本信息"
      go_file="go${go_version}.linux-${arch}.tar.gz"
      go_sha=$(printf '%s' "$go_json" | tr '{' '\n' | grep -F "$go_file" | grep -o '"sha256": *"[0-9a-f]*"' | head -1 | sed 's/.*"\([0-9a-f]*\)"/\1/')
      info "下载 Go ${go_version}…"
      curl -fL --retry 3 -o "/tmp/$go_file" "https://go.dev/dl/$go_file" || die "Go 下载失败"
      if [[ -n "$go_sha" ]]; then echo "$go_sha  /tmp/$go_file" | sha256sum -c - >/dev/null || die "Go 校验失败"; ok "Go 校验通过"; fi
      rm -rf "${tc}/go"
      tar -C "$tc" -xzf "/tmp/$go_file"
      rm -f "/tmp/$go_file"
      export PATH="${tc}/go/bin:${PATH}"
    fi
    if ! node_ok; then
      info "解析 Node.js latest-v${NODE_MAJOR}.x…"
      if ! have xz; then pkg_install xz-utils || die "缺少 xz，用于解压 Node.js"; fi
      case "$arch" in amd64) node_arch=x64 ;; arm64) node_arch=arm64 ;; esac
      shasums=$(curl -fsSL --retry 3 --max-time 30 "https://nodejs.org/dist/latest-v${NODE_MAJOR}.x/SHASUMS256.txt") || die "无法访问 nodejs.org"
      node_file=$(printf '%s\n' "$shasums" | awk -v suffix="linux-${node_arch}.tar.xz" '$2 ~ suffix"$" {print $2; exit}')
      [[ -n "$node_file" ]] || die "未找到 Node.js Linux 包"
      node_sha=$(printf '%s\n' "$shasums" | awk -v f="$node_file" '$2==f {print $1}')
      [[ -n "$node_sha" ]] || die "无法获取 Node.js 校验值"
      info "下载 Node.js ${node_file}…"
      curl -fL --retry 3 -o "/tmp/$node_file" "https://nodejs.org/dist/latest-v${NODE_MAJOR}.x/$node_file" || die "Node.js 下载失败"
      echo "$node_sha  /tmp/$node_file" | sha256sum -c - >/dev/null || die "Node.js 校验失败"
      rm -rf "${tc}/node"
      tar -C "$tc" -xJf "/tmp/$node_file"
      mv "${tc}/${node_file%.tar.xz}" "${tc}/node"
      rm -f "/tmp/$node_file"
      export PATH="${tc}/node/bin:${PATH}"
    fi
  fi
  go_ok || die "Go 安装后仍不可用"
  node_ok || die "Node.js 安装后仍不可用"
  ok "Go：$(go version)"
  ok "Node.js：$(node --version) / npm $(npm --version)"
fi

step "4/9 构建前端与后端"
if (( SKIP_BUILD == 0 )); then
  info "安装前端依赖…"
  if [[ -f "${REPO_ROOT}/web/package-lock.json" ]]; then
    (cd "${REPO_ROOT}/web" && npm ci --no-audit --no-fund)
  else
    (cd "${REPO_ROOT}/web" && npm install --no-audit --no-fund)
  fi
  info "构建前端…"
  (cd "${REPO_ROOT}/web" && npm run build)
  info "编译控制面…"
  export GOFLAGS="-mod=vendor"
  (cd "${REPO_ROOT}/server" && go build -trimpath -ldflags "-s -w" -o /tmp/vulnagent-new .)
  BUILT_EXE=/tmp/vulnagent-new
  BUILT_WEB="${REPO_ROOT}/web/dist"
else
  BUILT_EXE="${REPO_ROOT}/server/bin/vulnagent"
  BUILT_WEB="${REPO_ROOT}/web/dist"
fi
[[ -x "$BUILT_EXE" ]] || die "构建产物不存在：$BUILT_EXE"
[[ -f "${BUILT_WEB}/index.html" ]] || die "前端产物不存在：$BUILT_WEB"
ok "构建产物就绪"

step "5/9 停止旧服务并备份"
if have systemctl && systemctl list-unit-files | grep -q '^vulnagent-server.service'; then
  systemctl stop vulnagent-server.service || true
  ok "已停止 vulnagent-server.service"
fi
if [[ -f "${INSTALL_DIR}/run/server.pid" ]]; then
  kill "$(cat "${INSTALL_DIR}/run/server.pid")" 2>/dev/null || true
  rm -f "${INSTALL_DIR}/run/server.pid"
fi
if [[ -x "${INSTALL_DIR}/server/vulnagent" && -f "${DATA_DIR}/vulnagent.db" ]]; then
  mkdir -p "${DATA_DIR}/backups"
  VA_ENV_FILE="$SERVER_ENV" "${INSTALL_DIR}/server/vulnagent" backup \
    --out "${DATA_DIR}/backups/pre-upgrade-$(date +%Y%m%d-%H%M%S).db" \
    && ok "升级前数据库已备份" || warn "升级前备份失败（继续安装）"
  cp -f "${INSTALL_DIR}/server/vulnagent" "${INSTALL_DIR}/server/vulnagent.previous"
fi

step "6/9 部署文件与用户"
if ! id -u vulnagent >/dev/null 2>&1; then
  if have useradd; then useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin vulnagent
  elif have adduser; then adduser -S -H -h "$DATA_DIR" -s /sbin/nologin vulnagent
  else die "无法创建 vulnagent 系统用户"
  fi
  ok "已创建系统用户 vulnagent"
else
  ok "系统用户 vulnagent 已存在"
fi
chown root:vulnagent "$ENV_DIR" 2>/dev/null || true
chmod 0750 "$ENV_DIR" 2>/dev/null || true
mkdir -p "${INSTALL_DIR}/server" "${INSTALL_DIR}/web/dist" "${INSTALL_DIR}/logs" "${INSTALL_DIR}/scripts" "${INSTALL_DIR}/run" "$DATA_DIR" "${DATA_DIR}/backups"
install -m 0755 "$BUILT_EXE" "${INSTALL_DIR}/server/vulnagent"
rm -rf "${INSTALL_DIR}/web/dist"
mkdir -p "${INSTALL_DIR}/web/dist"
cp -a "${BUILT_WEB}/." "${INSTALL_DIR}/web/dist/"
chown -R root:root "${INSTALL_DIR}/server" "${INSTALL_DIR}/web"
chown -R vulnagent:vulnagent "$DATA_DIR" "${INSTALL_DIR}/logs"
chmod 0750 "$DATA_DIR" "${INSTALL_DIR}/logs"
ok "二进制与前端资源已部署"

step "7/9 写入配置"
if [[ -f "$SERVER_ENV" ]]; then
  cp -f "$SERVER_ENV" "${SERVER_ENV}.bak-$(date +%Y%m%d-%H%M%S)"
  env_value() { awk -F= -v key="$1" '$1==key {sub(/^[^=]*=/, ""); print; exit}' "$SERVER_ENV"; }
  # 命令行未显式提供的项沿用现有配置（只读取，不 source，避免执行配置内容）
  [[ -z "$ADMIN_PASSWORD" ]] && ADMIN_PASSWORD="$(env_value VA_ADMIN_PASSWORD)"
  [[ -z "$CVE_API_KEY" ]] && CVE_API_KEY="$(env_value VULNAGENT_CVE_API_KEY)"
  [[ -z "$LLM_BASE_URL" ]] && LLM_BASE_URL="$(env_value VA_LLM_BASE_URL)"
  [[ -z "$LLM_API_KEY" ]] && LLM_API_KEY="$(env_value VA_LLM_API_KEY)"
  [[ -z "$LLM_MODEL" ]] && LLM_MODEL="$(env_value VA_LLM_MODEL)"
  [[ "$COOKIE_SECURE" == "0" && "$(env_value VA_COOKIE_SECURE)" == "1" ]] && COOKIE_SECURE=1
  ok "已合并现有 server.env"
fi
NEW_DB=0
[[ -f "${DATA_DIR}/vulnagent.db" ]] || NEW_DB=1
if (( NEW_DB == 1 )) && [[ -z "$ADMIN_PASSWORD" ]]; then
  ADMIN_PASSWORD=$(rand_password)
  ok "已生成管理员初始口令（见安装摘要）"
fi
{
  printf '# VulnAgent 控制面配置（由 install.sh 生成于 %s）\n' "$(date '+%Y-%m-%d %H:%M:%S')"
  printf 'VA_ADDR=:%s\n' "$PORT"
  printf 'VA_DATA_DIR=%s\n' "$DATA_DIR"
  printf 'VA_WEB_DIST=%s\n' "${INSTALL_DIR}/web/dist"
  printf 'VA_SEED_DEMO=off\n'
  printf 'VA_SESSION_IDLE=30m\n'
  printf 'VA_RESCAN_INTERVAL=30m\n'
  printf 'VA_RESCAN_DEBOUNCE=10m\n'
  printf 'VA_SYNC_INTERVAL=12h\n'
  if (( COOKIE_SECURE == 1 )); then printf 'VA_COOKIE_SECURE=1\n'; else printf '# VA_COOKIE_SECURE=1\n'; fi
  if [[ -n "$ADMIN_PASSWORD" ]]; then printf 'VA_ADMIN_PASSWORD=%s\n' "$ADMIN_PASSWORD"; else printf '# VA_ADMIN_PASSWORD 沿用现有数据库\n'; fi
  if [[ -n "$CVE_API_KEY" ]]; then printf 'VULNAGENT_CVE_API_KEY=%s\n' "$CVE_API_KEY"; else printf '# VULNAGENT_CVE_API_KEY=\n'; fi
  if [[ -n "$LLM_BASE_URL" ]]; then printf 'VA_LLM_BASE_URL=%s\n' "$LLM_BASE_URL"; else printf '# VA_LLM_BASE_URL=\n'; fi
  if [[ -n "$LLM_API_KEY" ]]; then printf 'VA_LLM_API_KEY=%s\n' "$LLM_API_KEY"; else printf '# VA_LLM_API_KEY=\n'; fi
  if [[ -n "$LLM_MODEL" ]]; then printf 'VA_LLM_MODEL=%s\n' "$LLM_MODEL"; else printf '# VA_LLM_MODEL=\n'; fi
} > "$SERVER_ENV"
chmod 0600 "$SERVER_ENV"
chown root:root "$SERVER_ENV"
ok "配置已写入：$SERVER_ENV"

step "8/9 安装服务并启动"
HEALTH_OK=0
if (( NO_SERVICE == 0 )) && have systemctl; then
  cat > "$SERVER_UNIT" <<EOF
[Unit]
Description=VulnAgent 控制面（API + Web）
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=vulnagent
Group=vulnagent
WorkingDirectory=${INSTALL_DIR}/server
EnvironmentFile=-${SERVER_ENV}
ExecStart=${INSTALL_DIR}/server/vulnagent server
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${DATA_DIR}
CapabilityBoundingSet=
AmbientCapabilities=
LimitNOFILE=8192

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable vulnagent-server.service >/dev/null
  systemctl restart vulnagent-server.service
  ok "systemd 服务已启动：vulnagent-server.service"
else
  info "以独立进程启动（--no-service）"
  env VA_ENV_FILE="$SERVER_ENV" nohup "${INSTALL_DIR}/server/vulnagent" server \
    >> "${INSTALL_DIR}/logs/server.log" 2>&1 &
  echo $! > "${INSTALL_DIR}/run/server.pid"
  ok "后台进程 PID $(cat "${INSTALL_DIR}/run/server.pid")"
fi

for _ in $(seq 1 40); do
  if curl -fsS -m 2 "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1; then HEALTH_OK=1; break; fi
  sleep 1
done
if (( HEALTH_OK == 0 )); then
  if [[ -x "${INSTALL_DIR}/server/vulnagent.previous" ]]; then
    warn "健康检查失败，尝试回滚上一版二进制"
    install -m 0755 "${INSTALL_DIR}/server/vulnagent.previous" "${INSTALL_DIR}/server/vulnagent"
    if (( NO_SERVICE == 0 )) && have systemctl; then systemctl restart vulnagent-server.service; else
      env VA_ENV_FILE="$SERVER_ENV" nohup "${INSTALL_DIR}/server/vulnagent" server >> "${INSTALL_DIR}/logs/server.log" 2>&1 &
    fi
    sleep 3
  fi
  (( NO_SERVICE == 0 )) && journalctl -u vulnagent-server.service -n 40 --no-pager || tail -n 40 "${INSTALL_DIR}/logs/server.log"
  die "健康检查失败：http://127.0.0.1:${PORT}/healthz"
fi
ok "健康检查通过：http://127.0.0.1:${PORT}/healthz"

if (( WITH_AGENT == 1 )); then
  token_file="${DATA_DIR}/agent.token"
  for _ in $(seq 1 20); do [[ -s "$token_file" ]] && break; sleep 1; done
  if [[ -s "$token_file" ]]; then
    install -m 0600 "$token_file" "${ENV_DIR}/agent.token"
    cat > "$AGENT_ENV" <<EOF
# VulnAgent 本机采集 Agent
VA_SERVER=http://127.0.0.1:${PORT}
EOF
    chmod 0600 "$AGENT_ENV"
    if (( NO_SERVICE == 0 )) && have systemctl; then
      cat > "$AGENT_UNIT" <<EOF
[Unit]
Description=VulnAgent 本机采集与上报
After=network-online.target vulnagent-server.service
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=${INSTALL_DIR}/server/vulnagent agent --server http://127.0.0.1:${PORT} --token-file ${ENV_DIR}/agent.token --watch --interval 15s
Restart=always
RestartSec=5
Nice=10
IOSchedulingClass=idle
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
      systemctl daemon-reload
      systemctl enable vulnagent-agent.service >/dev/null
      systemctl restart vulnagent-agent.service
      ok "Agent 服务已启动：vulnagent-agent.service"
    fi
  else
    warn "未找到 agent.token，已跳过本机 Agent"
  fi
fi

step "9/9 生成运维脚本与摘要"
cat > "${INSTALL_DIR}/scripts/status.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
if (( ${NO_SERVICE} == 0 )) && command -v systemctl >/dev/null; then
  systemctl --no-pager --full status vulnagent-server.service || true
  systemctl --no-pager --full status vulnagent-agent.service || true
fi
echo
echo "健康检查：\$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:${PORT}/healthz || echo 000)"
if [[ -f "${INSTALL_DIR}/run/server.pid" ]]; then echo "后台 PID：\$(cat "${INSTALL_DIR}/run/server.pid")"; fi
echo "最近日志："
journalctl -u vulnagent-server.service -n 20 --no-pager 2>/dev/null || tail -n 20 "${INSTALL_DIR}/logs/server.log" 2>/dev/null || true
EOF
cat > "${INSTALL_DIR}/scripts/stop.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
if command -v systemctl >/dev/null; then
  systemctl stop vulnagent-agent.service vulnagent-server.service 2>/dev/null || true
fi
if [[ -f "${INSTALL_DIR}/run/server.pid" ]]; then
  kill "\$(cat "${INSTALL_DIR}/run/server.pid")" 2>/dev/null || true
  rm -f "${INSTALL_DIR}/run/server.pid"
fi
echo "VulnAgent 已停止"
EOF
cat > "${INSTALL_DIR}/scripts/start.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
if command -v systemctl >/dev/null; then
  systemctl start vulnagent-server.service vulnagent-agent.service 2>/dev/null || systemctl start vulnagent-server.service
else
  VA_ENV_FILE="${SERVER_ENV}" nohup "${INSTALL_DIR}/server/vulnagent" server >> "${INSTALL_DIR}/logs/server.log" 2>&1 &
  echo \$! > "${INSTALL_DIR}/run/server.pid"
fi
echo "VulnAgent 已启动"
EOF
cat > "${INSTALL_DIR}/scripts/backup.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
out="${DATA_DIR}/backups/vulnagent-\$(date +%Y%m%d-%H%M%S).db"
VA_ENV_FILE="${SERVER_ENV}" "${INSTALL_DIR}/server/vulnagent" backup --out "\$out"
echo "备份完成：\$out"
EOF
uninstall_script="${INSTALL_DIR}/scripts/uninstall.sh"
{
  echo '#!/usr/bin/env bash'
  echo 'set -euo pipefail'
  echo '[[ $EUID -eq 0 ]] || { echo "请使用 root 运行"; exit 1; }'
  if (( NO_SERVICE == 0 )); then
    cat <<'UNIT'
systemctl disable --now vulnagent-agent.service vulnagent-server.service 2>/dev/null || true
rm -f /etc/systemd/system/vulnagent-agent.service /etc/systemd/system/vulnagent-server.service
systemctl daemon-reload
UNIT
  fi
  echo "bash \"${INSTALL_DIR}/scripts/stop.sh\" || true"
  cat <<EOF
if [[ "\${1:-}" == "--purge" ]]; then
  rm -rf "${INSTALL_DIR}" "$DATA_DIR" "${ENV_DIR}"
  echo "已删除安装目录、数据与配置"
else
  echo "已停止并移除服务；安装目录、数据与配置保留。加 --purge 可彻底删除。"
fi
EOF
} > "$uninstall_script"
chmod 0755 "${INSTALL_DIR}/scripts/"*.sh
chown -R root:root "${INSTALL_DIR}/scripts"

{
  echo "VulnAgent 安装摘要"
  echo "生成时间：$(date '+%Y-%m-%d %H:%M:%S')"
  echo "访问地址：http://127.0.0.1:${PORT}"
  echo "管理员账号：admin"
  if [[ -n "$ADMIN_PASSWORD" ]]; then echo "管理员口令：${ADMIN_PASSWORD}"; else echo "管理员口令：沿用现有数据库（本次未修改）"; fi
  echo "安装目录：${INSTALL_DIR}"
  echo "数据目录：${DATA_DIR}"
  echo "配置目录：${ENV_DIR}"
  echo "安装日志：${LOG_FILE}"
  echo
  echo "常用命令："
  echo "  sudo ${INSTALL_DIR}/scripts/status.sh"
  echo "  sudo ${INSTALL_DIR}/scripts/start.sh"
  echo "  sudo ${INSTALL_DIR}/scripts/stop.sh"
  echo "  sudo ${INSTALL_DIR}/scripts/backup.sh"
  echo "  sudo ${INSTALL_DIR}/scripts/uninstall.sh [--purge]"
  echo "  journalctl -u vulnagent-server.service -f"
  echo
  echo "后续建议："
  echo "  1. 对外服务时通过反向代理终止 TLS，并在 server.env 设置 VA_COOKIE_SECURE=1"
  echo "  2. 定期执行 backup.sh 或配置 cron 备份 ${DATA_DIR}/backups"
  echo "  3. 升级：重新执行 deploy/linux/install.sh（自动备份并回滚保护）"
} > "$SUMMARY_FILE"
chmod 0600 "$SUMMARY_FILE"

if (( OPEN_FIREWALL == 1 )); then
  if have ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow "${PORT}/tcp" >/dev/null && ok "ufw 已放行 ${PORT}/tcp"
  elif have firewall-cmd && systemctl is-active --quiet firewalld; then
    firewall-cmd --permanent --add-port="${PORT}/tcp" >/dev/null && firewall-cmd --reload >/dev/null && ok "firewalld 已放行 ${PORT}/tcp"
  else
    warn "未检测到启用中的 ufw/firewalld，跳过防火墙配置"
  fi
fi

echo
echo -e "${C_GREEN}安装完成。${C_RESET}"
echo -e "访问地址：${C_CYAN}http://127.0.0.1:${PORT}${C_RESET}"
echo -e "管理员：${C_CYAN}admin / ${ADMIN_PASSWORD:-沿用现有口令}${C_RESET}"
echo -e "安装摘要：${C_CYAN}${SUMMARY_FILE}${C_RESET}"
echo -e "安装日志：${C_CYAN}${LOG_FILE}${C_RESET}"
