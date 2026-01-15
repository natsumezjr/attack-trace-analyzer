#!/bin/bash
# 靶场一键关闭脚本（支持模块选择）

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

show_help() {
    cat <<EOF
用法: $0 [选项]

选项:
  -m, --modules MODULES    指定要关闭的模块（用逗号分隔，不指定则关闭全部）
  -c, --clear-db          关闭时清空数据库（OpenSearch 和 Neo4j）
  -h, --help              显示此帮助信息

可用模块:
  frontend    - 中心机前端（Next.js）
  backend     - 中心机后端（FastAPI）
  client      - 客户机采集栈（4个实例）
  c2          - C2服务（DNS+HTTP）
  center      - 中心机依赖（OpenSearch、Neo4j）
  db          - 数据库（OpenSearch、Neo4j）- 仅清空数据，不停止服务
  all         - 关闭所有模块（默认）

示例:
  $0                      # 关闭所有模块
  $0 -m frontend,backend  # 只关闭前端和后端
  $0 -m client            # 只关闭客户机
  $0 -m c2,center         # 只关闭C2和中心机
  $0 -c                   # 关闭所有模块并清空数据库
  $0 -m center -c         # 只关闭中心机依赖并清空数据库
  $0 -m db                # 只清空数据库（不停止服务）
  $0 -m db,center         # 清空数据库并关闭中心机依赖
EOF
}

# 解析参数
MODULES="all"
CLEAR_DB=false
while [[ $# -gt 0 ]]; do
    case $1 in
        -m|--modules)
            MODULES="$2"
            shift 2
            ;;
        -c|--clear-db)
            CLEAR_DB=true
            shift
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
should_stop() {
    local module=$1
    if [ "$MODULES" = "all" ]; then
        return 0
    fi
    echo "$MODULES" | grep -q "\b$module\b"
}

# 清空数据库函数
clear_databases() {
    log_info "清空数据库..."
    
    # 检查中心机依赖是否运行
    if ! docker ps | grep -qE '(opensearch|neo4j)'; then
        log_warn "中心机依赖未运行，跳过数据库清空"
        return 1
    fi
    
    # 清空 OpenSearch
    log_info "清空 OpenSearch..."
    OPENSEARCH_PASSWORD="${OPENSEARCH_INITIAL_ADMIN_PASSWORD:-OpenSearch@2024!Dev}"
    
    # 使用 docker exec 在容器内执行，获取所有非系统索引
    if docker ps | grep -q opensearch; then
        # 获取所有非系统索引（排除以 . 开头的系统索引和 security-auditlog）
        INDICES=$(docker exec opensearch curl -k -s -u "admin:$OPENSEARCH_PASSWORD" "https://localhost:9200/_cat/indices?h=index" 2>/dev/null | grep -v '^\.' | grep -v '^security-auditlog' | grep -v '^$' || true)
        
        if [ -n "$INDICES" ]; then
            # 删除所有非系统索引
            DELETED_COUNT=0
            while IFS= read -r idx; do
                if [ -n "$idx" ]; then
                    if docker exec opensearch curl -k -s -u "admin:$OPENSEARCH_PASSWORD" -X DELETE "https://localhost:9200/$idx" >/dev/null 2>&1; then
                        log_info "  已删除索引: $idx"
                        DELETED_COUNT=$((DELETED_COUNT + 1))
                    else
                        log_warn "  删除索引失败: $idx"
                    fi
                fi
            done <<< "$INDICES"
            
            if [ $DELETED_COUNT -gt 0 ]; then
                log_info "OpenSearch 清空完成（已删除 $DELETED_COUNT 个索引）"
            else
                log_info "OpenSearch 清空完成（没有可删除的索引）"
            fi
        else
            log_info "OpenSearch 没有需要删除的索引"
        fi
    else
        log_warn "OpenSearch 容器未运行，跳过清空"
    fi
    
    # 清空 Neo4j
    log_info "清空 Neo4j..."
    if docker ps | grep -q neo4j; then
        # 使用 docker exec 在容器内执行 cypher-shell
        NEO4J_AUTH="${NEO4J_AUTH:-neo4j/password}"
        NEO4J_USER=$(echo "$NEO4J_AUTH" | cut -d'/' -f1)
        NEO4J_PASSWORD=$(echo "$NEO4J_AUTH" | cut -d'/' -f2)
        
        # 在 Neo4j 容器内执行 Cypher 命令
        docker exec neo4j cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" "MATCH (n) DETACH DELETE n;" >/dev/null 2>&1 && \
            log_info "Neo4j 清空完成" || \
            log_warn "Neo4j 清空失败（可能数据库已关闭或连接失败）"
    else
        log_warn "Neo4j 容器未运行，跳过清空"
    fi
}

log_info "=========================================="
log_info "靶场一键关闭脚本"
log_info "=========================================="
log_info "关闭模块: $MODULES"
if [ "$CLEAR_DB" = true ]; then
    log_warn "清空数据库: 已启用（将清空 OpenSearch 和 Neo4j）"
fi
log_info "=========================================="

# 计算总步骤数
TOTAL_STEPS=5
if [ "$CLEAR_DB" = true ] && should_stop "center"; then
    TOTAL_STEPS=6
fi
if should_stop "db"; then
    TOTAL_STEPS=$((TOTAL_STEPS + 1))
fi

# 1. 停止前端（Next.js）
if should_stop "frontend"; then
    log_info "步骤 1/$TOTAL_STEPS: 停止前端..."
    FRONTEND_STOPPED=false
    
    # 首先尝试通过 PID 文件停止
    if [ -f "$BASE"/run/frontend.pid ]; then
        FRONTEND_PID=$(cat "$BASE"/run/frontend.pid)
        if ps -p "$FRONTEND_PID" > /dev/null 2>&1; then
            kill "$FRONTEND_PID" 2>/dev/null || true
            sleep 1
            # 如果进程还在，强制杀死
            if ps -p "$FRONTEND_PID" > /dev/null 2>&1; then
                kill -9 "$FRONTEND_PID" 2>/dev/null || true
                sleep 1
            fi
            FRONTEND_STOPPED=true
            log_info "前端进程 $FRONTEND_PID 已停止"
        else
            log_warn "前端进程 $FRONTEND_PID 不存在"
        fi
        rm -f "$BASE"/run/frontend.pid
    fi
    
    # 使用 pkill 确保所有相关进程都被停止
    if pkill -f "next-server" 2>/dev/null; then
        sleep 1
        FRONTEND_STOPPED=true
        log_info "前端进程已停止（通过 pkill）"
    fi
    
    # 清理 Next.js 锁文件
    LOCK_FILE="$REPO/frontend/.next/dev/lock"
    if [ -f "$LOCK_FILE" ]; then
        rm -f "$LOCK_FILE"
        log_info "已清理 Next.js 锁文件"
    fi
    
    # 等待端口释放
    if $FRONTEND_STOPPED; then
        sleep 2
    fi
    
    if ! $FRONTEND_STOPPED; then
        log_warn "未找到前端进程"
    fi
else
    log_warn "跳过: 前端"
fi

# 2. 停止后端（FastAPI）
if should_stop "backend"; then
    log_info "步骤 2/$TOTAL_STEPS: 停止后端..."
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
        pkill -f "uvicorn main:app" 2>/dev/null && log_info "后端进程已停止" || log_warn "未找到后端进程"
    fi
else
    log_warn "跳过: 后端"
fi

sleep 2

# 3. 停止 4 套客户机采集栈（并清空卷和数据）
if should_stop "client"; then
    log_info "步骤 3/$TOTAL_STEPS: 停止客户机并清空数据..."
    for i in 01 02 03 04; do
        if [ -d "$BASE"/run/client-$i ]; then
            cd "$BASE"/run/client-$i
            # 停止并删除卷（-v 参数会删除命名卷）
            docker-compose -p client-$i down -v 2>/dev/null && log_info "client-$i 已停止（卷已删除）" || log_warn "client-$i 停止失败"
            
            # 清空数据目录（bind mount 的数据）
            if [ -d "$BASE"/run/client-$i/data ]; then
                # 先尝试普通删除（包括隐藏文件）
                if rm -rf "$BASE"/run/client-$i/data/* "$BASE"/run/client-$i/data/.[!.]* "$BASE"/run/client-$i/data/..?* 2>/dev/null; then
                    log_info "client-$i 数据目录已清空"
                else
                    # 如果普通删除失败，尝试使用 find 命令（更安全）
                    if find "$BASE"/run/client-$i/data -mindepth 1 -delete 2>/dev/null; then
                        log_info "client-$i 数据目录已清空（使用 find）"
                    else
                        # 如果还是失败，尝试使用 sudo（如果可用）
                        if command -v sudo >/dev/null 2>&1; then
                            if sudo rm -rf "$BASE"/run/client-$i/data/* "$BASE"/run/client-$i/data/.[!.]* "$BASE"/run/client-$i/data/..?* 2>/dev/null; then
                                log_info "client-$i 数据目录已清空（使用 sudo）"
                            else
                                log_warn "client-$i 数据目录清空失败（可能需要手动清理：sudo rm -rf $BASE/run/client-$i/data/*）"
                            fi
                        else
                            log_warn "client-$i 数据目录清空失败（权限不足，可能需要手动清理：rm -rf $BASE/run/client-$i/data/*）"
                        fi
                    fi
                fi
            else
                log_info "client-$i 数据目录不存在，跳过清空"
            fi
        else
            log_warn "client-$i 目录不存在"
        fi
    done
else
    log_warn "跳过: 客户机"
fi

# 4. 停止 C2（DNS+HTTP）
if should_stop "c2"; then
    log_info "步骤 4/$TOTAL_STEPS: 停止 C2..."
    docker rm -f c2-dns c2-http 2>/dev/null && log_info "C2 容器已停止" || log_warn "C2 容器不存在或已停止"
else
    log_warn "跳过: C2"
fi

# 5. 清空数据库（如果启用 -c 选项且 center 模块被选中）
CURRENT_STEP=5
if [ "$CLEAR_DB" = true ] && should_stop "center"; then
    log_info "步骤 $CURRENT_STEP/$TOTAL_STEPS: 清空数据库..."
    clear_databases
    CURRENT_STEP=$((CURRENT_STEP + 1))
elif [ "$CLEAR_DB" = true ]; then
    log_warn "跳过: 数据库清空（center 模块未包含在关闭列表中）"
fi

# 5b. 处理 db 模块（仅清空数据库，不停止服务）
if should_stop "db"; then
    log_info "步骤 $CURRENT_STEP/$TOTAL_STEPS: 清空数据库（db 模块）..."
    clear_databases
    CURRENT_STEP=$((CURRENT_STEP + 1))
fi

# 6. 停止中心机依赖（OpenSearch、Neo4j）
if should_stop "center"; then
    log_info "步骤 $CURRENT_STEP/$TOTAL_STEPS: 停止中心机依赖..."
    cd "$REPO"/backend
    docker-compose down 2>/dev/null && log_info "中心机依赖已停止" || log_warn "中心机依赖停止失败"
else
    log_warn "跳过: 中心机依赖"
fi

log_info "=========================================="
log_info "关闭完成！"
log_info "=========================================="
log_info "验证: docker ps | grep -E '(opensearch|neo4j|c2|client)'"