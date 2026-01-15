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
  -c, --clear-db          启动前清空数据库（OpenSearch 和 Neo4j）
  -h, --help              显示此帮助信息

可用模块:
  center      - 中心机依赖（OpenSearch、Neo4j）
  c2          - C2服务（DNS+HTTP）
  client      - 客户机采集栈（4个实例）
  backend     - 中心机后端（FastAPI）
  frontend    - 中心机前端（Next.js）
  register    - 注册客户机到中心机
  db          - 数据库（OpenSearch、Neo4j）- 仅清空数据，不启动服务
  all         - 启动所有模块（默认）

示例:
  $0                      # 启动所有模块
  $0 -m center,c2         # 只启动中心机和C2
  $0 -m backend,frontend  # 只启动后端和前端
  $0 -m client,register   # 只启动客户机和注册
  $0 -c                   # 启动所有模块前清空数据库
  $0 -m center -c         # 启动中心机前清空数据库
  $0 -m db                # 只清空数据库（不启动服务）
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
if [ "$CLEAR_DB" = true ]; then
    log_warn "清空数据库: 已启用（将清空 OpenSearch 和 Neo4j）"
fi
log_info "=========================================="

# 清空数据库函数（与 close.sh 中的相同）
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

# 计算总步骤数
TOTAL_STEPS=6
if [ "$CLEAR_DB" = true ] && should_start "center"; then
    TOTAL_STEPS=7
fi
if should_start "db"; then
    TOTAL_STEPS=$((TOTAL_STEPS + 1))
fi

# 0. 处理 db 模块（仅清空数据库，不启动服务）
CURRENT_STEP=0
if should_start "db"; then
    CURRENT_STEP=$((CURRENT_STEP + 1))
    log_info "步骤 $CURRENT_STEP/$TOTAL_STEPS: 清空数据库（db 模块）..."
    # 如果 center 未运行，先启动它
    if ! docker ps | grep -qE '(opensearch|neo4j)'; then
        log_info "中心机依赖未运行，先启动中心机依赖..."
        cd "$REPO"/backend
        docker-compose up -d
        sleep 5
        log_info "等待数据库就绪..."
        sleep 5
    fi
    clear_databases
fi

# 1. 启动中心机依赖（OpenSearch、Neo4j）
if should_start "center"; then
    CURRENT_STEP=$((CURRENT_STEP + 1))
    log_info "步骤 $CURRENT_STEP/$TOTAL_STEPS: 启动中心机依赖..."
    cd "$REPO"/backend
    docker-compose up -d
    sleep 5
    
    # 如果启用 -c 选项，在启动后清空数据库
    if [ "$CLEAR_DB" = true ]; then
        log_info "等待数据库就绪..."
        sleep 5
        clear_databases
    fi
else
    log_warn "跳过: 中心机依赖"
fi

# 2. 启动 C2（DNS+HTTP）
if should_start "c2"; then
    CURRENT_STEP=$((CURRENT_STEP + 1))
    log_info "步骤 $CURRENT_STEP/$TOTAL_STEPS: 启动 C2..."
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
    CURRENT_STEP=$((CURRENT_STEP + 1))
    log_info "步骤 $CURRENT_STEP/$TOTAL_STEPS: 启动客户机..."
    for i in 01 02 03 04; do
        cd "$BASE"/run/client-$i
        docker-compose -p client-$i up -d
    done
    sleep 5
else
    log_warn "跳过: 客户机"
fi

# 4. 启动中心机后端（FastAPI）
if should_start "backend"; then
    CURRENT_STEP=$((CURRENT_STEP + 1))
    log_info "步骤 $CURRENT_STEP/$TOTAL_STEPS: 启动后端..."
    cd "$REPO"/backend
    export OPENSEARCH_NODE="https://localhost:9200"
    export OPENSEARCH_USERNAME="admin"
    export OPENSEARCH_PASSWORD="OpenSearch@2024!Dev"
    export OPENSEARCH_URL="https://localhost:9200"
    export OPENSEARCH_USER="admin"
    export NEO4J_URI="bolt://localhost:7687"
    export NEO4J_USER="neo4j"
    export NEO4J_PASSWORD="password"

    if ! pgrep -f "uvicorn main:app" > /dev/null; then
        nohup uv run uvicorn main:app --host 0.0.0.0 --port 8001 > "$BASE"/run/backend.log 2>&1 &
        echo $! > "$BASE"/run/backend.pid
        log_info "后端已启动，PID: $(cat "$BASE"/run/backend.pid)"
    else
        log_warn "后端已在运行"
    fi
    sleep 3
else
    log_warn "跳过: 后端"
fi


# 5. 启动中心机前端（Next.js）
if should_start "frontend"; then
    CURRENT_STEP=$((CURRENT_STEP + 1))
    log_info "步骤 $CURRENT_STEP/$TOTAL_STEPS: 启动前端..."
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

# 6. 注册 4 个客户机到中心机
if should_start "register"; then
    CURRENT_STEP=$((CURRENT_STEP + 1))
    log_info "步骤 $CURRENT_STEP/$TOTAL_STEPS: 注册客户机..."
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