#!/bin/bash
# 靶场一键关闭脚本

set -e

# 颜色输出
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# 固定变量
export BASE=/home/ubuntu/attack-trace-analyzer
export REPO="$BASE"/repo/attack-trace-analyzer

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_info "=========================================="
log_info "靶场一键关闭脚本"
log_info "=========================================="

# 1. 停止前端（Next.js）
log_info "步骤 1/5: 停止前端..."
if [ -f "$BASE"/run/frontend.pid ]; then
    FRONTEND_PID=$(cat "$BASE"/run/frontend.pid)
    if ps -p "$FRONTEND_PID" > /dev/null 2>&1; then
        kill "$FRONTEND_PID" 2>/dev/null || true
        log_info "前端进程 $FRONTEND_PID 已停止"
    else
        log_warn "前端进程 $FRONTEND_PID 不存在"
    fi
    rm -f "$BASE"/run/frontend.pid
else
    # 如果没有 PID 文件，尝试通过进程名停止
    pkill -f "next-server" 2>/dev/null && log_info "前端进程已停止" || log_warn "未找到前端进程"
fi

# 2. 停止后端（FastAPI）
log_info "步骤 2/5: 停止后端..."
if [ -f "$BASE"/run/backend.pid ]; then
    BACKEND_PID=$(cat "$BASE"/run/backend.pid)
    if ps -p "$BACKEND_PID" > /dev/null 2>&1; then
        kill "$BACKEND_PID" 2>/dev/null || true
        log_info "后端进程 $BACKEND_PID 已停止"
    else
        log_warn "后端进程 $BACKEND_PID 不存在"
    fi
    rm -f "$BASE"/run/backend.pid
else
    # 如果没有 PID 文件，尝试通过进程名停止
    pkill -f "uvicorn main:app" 2>/dev/null && log_info "后端进程已停止" || log_warn "未找到后端进程"
fi

sleep 2

# 3. 停止 4 套客户机采集栈
log_info "步骤 3/5: 停止客户机..."
for i in 01 02 03 04; do
    if [ -d "$BASE"/run/client-$i ]; then
        cd "$BASE"/run/client-$i
        docker-compose -p client-$i down 2>/dev/null && log_info "client-$i 已停止" || log_warn "client-$i 停止失败"
    else
        log_warn "client-$i 目录不存在"
    fi
done

# 4. 停止 C2（DNS+HTTP）
log_info "步骤 4/5: 停止 C2..."
docker rm -f c2-dns c2-http 2>/dev/null && log_info "C2 容器已停止" || log_warn "C2 容器不存在或已停止"

# 5. 停止中心机依赖（OpenSearch、Neo4j）
log_info "步骤 5/5: 停止中心机依赖..."
cd "$REPO"/backend
docker-compose down 2>/dev/null && log_info "中心机依赖已停止" || log_warn "中心机依赖停止失败"

log_info "=========================================="
log_info "关闭完成！"
log_info "=========================================="
log_info "验证: docker ps | grep -E '(opensearch|neo4j|c2|client)'"