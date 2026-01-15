#!/bin/bash
# 靶场一键启动脚本（支持模块选择）

set -e

# 颜色输出
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 固定变量
export BASE=/home/ubuntu/attack-trace-analyzer
export REPO="$BASE"/repo/attack-trace-analyzer

# 自动加载 nvm（如果已安装）
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
[ -s "$NVM_DIR/nvm.sh" ] && nvm use 20 2>/dev/null || true

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

show_help() {
    cat <<EOF
用法: $0 [选项]

选项:
  -m, --modules MODULES    指定要启动的模块（用逗号分隔，不指定则启动全部）
  -h, --help              显示此帮助信息

可用模块:
  center      - 中心机依赖（OpenSearch、Neo4j）
  c2          - C2服务（DNS+HTTP）
  client      - 客户机采集栈（4个实例）
  backend     - 中心机后端（FastAPI）
  frontend    - 中心机前端（Next.js）
  register    - 注册客户机到中心机
  all         - 启动所有模块（默认）

示例:
  $0                      # 启动所有模块
  $0 -m center,c2         # 只启动中心机和C2
  $0 -m backend,frontend  # 只启动后端和前端
  $0 -m client,register   # 只启动客户机和注册
EOF
}

# 解析参数
MODULES="all"
while [[ $# -gt 0 ]]; do
    case $1 in
        -m|--modules)
            MODULES="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            log_warn "未知参数: $1"
            show_help
            exit 1
            ;;
    esac
done

# 检查模块是否在列表中
should_start() {
    local module=$1
    if [ "$MODULES" = "all" ]; then
        return 0
    fi
    echo "$MODULES" | grep -q "\b$module\b"
}

log_info "=========================================="
log_info "靶场一键启动脚本"
log_info "=========================================="
log_info "启动模块: $MODULES"
log_info "=========================================="

# 1. 启动中心机依赖（OpenSearch、Neo4j）
if should_start "center"; then
    log_info "步骤 1/6: 启动中心机依赖..."
    cd "$REPO"/backend
    docker-compose up -d
    sleep 5
else
    log_warn "跳过: 中心机依赖"
fi

# 2. 启动 C2（DNS+HTTP）
if should_start "c2"; then
    log_info "步骤 2/6: 启动 C2..."
    docker rm -f c2-dns c2-http 2>/dev/null || true
    docker run -d --name c2-dns \
      --network c2-macvlan --ip 10.92.35.50 \
      -v "$BASE"/run/c2/Corefile:/etc/coredns/Corefile:ro \
      -v "$BASE"/run/c2/hosts:/etc/coredns/hosts:ro \
      coredns/coredns:latest

    docker run -d --name c2-http \
      --network c2-macvlan --ip 10.92.35.51 \
      -v "$BASE"/run/c2/html:/usr/share/nginx/html:ro \
      nginx:latest
    sleep 2
else
    log_warn "跳过: C2"
fi

# 3. 启动 4 套客户机采集栈
if should_start "client"; then
    log_info "步骤 3/6: 启动客户机..."
    for i in 01 02 03 04; do
        cd "$BASE"/run/client-$i
        docker-compose -p client-$i up -d
    done
    sleep 5
else
    log_warn "跳过: 客户机"
fi

# 4. 启动中心机后端（FastAPI）
# 在 start.sh 的前端启动部分添加依赖检查
# 5. 启动中心机前端（Next.js）
if should_start "frontend"; then
    log_info "步骤 5/6: 启动前端..."
    cd "$REPO"/frontend

    # 确保使用 Node.js 20（如果 nvm 可用）
    [ -s "$NVM_DIR/nvm.sh" ] && nvm use 20 2>/dev/null || true

    # 检查并安装依赖
    if [ ! -d "node_modules" ] || [ ! -f "node_modules/sonner/package.json" ]; then
        log_info "检测到依赖缺失，正在安装..."
        npm install
    fi

    # 检查 Node.js 版本
    NODE_VERSION=$(node --version 2>/dev/null | cut -d'v' -f2 | cut -d'.' -f1 || echo "0")
    if [ "$NODE_VERSION" -lt 20 ]; then
        log_info "当前 Node.js 版本: $(node --version 2>/dev/null || echo '未知')"
        log_info "尝试使用 nvm 切换到 Node.js 20..."
        [ -s "$NVM_DIR/nvm.sh" ] && nvm use 20 2>/dev/null || log_info "nvm 不可用，使用系统默认 Node.js"
    fi

    if ! pgrep -f "next-server" > /dev/null; then
        nohup npm run dev -- -H 0.0.0.0 -p 3000 > "$BASE"/run/frontend.log 2>&1 &
        echo $! > "$BASE"/run/frontend.pid
        log_info "前端已启动，PID: $(cat "$BASE"/run/frontend.pid)"
        log_info "Node.js 版本: $(node --version 2>/dev/null || echo '未知')"
    else
        log_warn "前端已在运行"
    fi
    sleep 3
else
    log_warn "跳过: 前端"
fi

# 5. 启动中心机前端（Next.js）
if should_start "frontend"; then
    log_info "步骤 5/6: 启动前端..."
    cd "$REPO"/frontend

    # 确保使用 Node.js 20（如果 nvm 可用）
    [ -s "$NVM_DIR/nvm.sh" ] && nvm use 20 2>/dev/null || true

    # 检查 Node.js 版本
    NODE_VERSION=$(node --version 2>/dev/null | cut -d'v' -f2 | cut -d'.' -f1 || echo "0")
    if [ "$NODE_VERSION" -lt 20 ]; then
        log_info "当前 Node.js 版本: $(node --version 2>/dev/null || echo '未知')"
        log_info "尝试使用 nvm 切换到 Node.js 20..."
        [ -s "$NVM_DIR/nvm.sh" ] && nvm use 20 2>/dev/null || log_info "nvm 不可用，使用系统默认 Node.js"
    fi

    if ! pgrep -f "next-server" > /dev/null; then
        nohup npm run dev -- -H 0.0.0.0 -p 3000 > "$BASE"/run/frontend.log 2>&1 &
        echo $! > "$BASE"/run/frontend.pid
        log_info "前端已启动，PID: $(cat "$BASE"/run/frontend.pid)"
        log_info "Node.js 版本: $(node --version 2>/dev/null || echo '未知')"
    else
        log_warn "前端已在运行"
    fi
    sleep 3
else
    log_warn "跳过: 前端"
fi

# 6. 注册 4 个客户机到中心机
if should_start "register"; then
    log_info "步骤 6/6: 注册客户机..."
    sleep 2
    
    register_client() {
        local client_id=$1
        local port=$2
        local host_id=$3
        local host_name=$4
        
        curl -sS -X POST "http://localhost:8001/api/v1/clients/register" \
          -H "Content-Type: application/json" \
          -d "{\"client_id\":\"$client_id\",\"client_version\":\"0.1.0\",\"listen_url\":\"http://10.92.35.13:$port\",\"host\":{\"id\":\"$host_id\",\"name\":\"$host_name\"},\"capabilities\":{\"filebeat\":true,\"falco\":true,\"suricata\":true}}" \
          | grep -q '"status":"ok"' && log_info "$client_id 注册成功" || log_warn "$client_id 注册失败"
    }
    
    register_client "client-01" "18881" "h-client-01" "victim-01"
    register_client "client-02" "18882" "h-client-02" "victim-02"
    register_client "client-03" "18883" "h-client-03" "victim-03"
    register_client "client-04" "18884" "h-client-04" "victim-04"
else
    log_warn "跳过: 注册客户机"
fi

log_info "=========================================="
log_info "启动完成！"
log_info "=========================================="
log_info "验证: ss -lntup | grep -E ':(9200|9600|7474|7687|8001|3000|18881|18882|18883|18884)'"