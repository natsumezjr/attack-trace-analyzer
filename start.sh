#!/bin/bash
# 靶场一键启动脚本
# 用途：快速启动所有容器服务（中心机、C2、客户机）

set -e  # 遇到错误立即退出

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 固定变量
export BASE=/home/ubuntu/attack-trace-analyzer
export REPO="$BASE"/repo/attack-trace-analyzer

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查命令是否存在
check_command() {
    if ! command -v "$1" &> /dev/null; then
        log_error "$1 命令不存在，请先安装"
        exit 1
    fi
}

# 等待服务就绪
wait_for_service() {
    local url=$1
    local max_attempts=30
    local attempt=0
    
    log_info "等待服务就绪: $url"
    while [ $attempt -lt $max_attempts ]; do
        if curl -sf "$url" > /dev/null 2>&1; then
            log_info "服务已就绪: $url"
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 2
    done
    
    log_warn "服务未在预期时间内就绪: $url"
    return 1
}

# 检查前置条件
log_info "=========================================="
log_info "靶场一键启动脚本"
log_info "=========================================="

log_info "检查前置条件..."
check_command docker
check_command docker-compose
check_command python3

# 检查目录
if [ ! -d "$REPO" ]; then
    log_error "项目目录不存在: $REPO"
    exit 1
fi

# 自动检测物理网卡（优先使用 ens5f1，否则尝试 eth0）
PHYSICAL_INTERFACE=""
if ip link show ens5f1 &> /dev/null; then
    PHYSICAL_INTERFACE="ens5f1"
    log_info "检测到网卡: ens5f1"
elif ip link show eth0 &> /dev/null; then
    PHYSICAL_INTERFACE="eth0"
    log_info "检测到网卡: eth0"
else
    log_error "未找到物理网卡（ens5f1 或 eth0）"
    exit 1
fi

# ==========================================
# 1. 启动中心机依赖（OpenSearch、Neo4j）
# ==========================================
log_info "----------------------------------------"
log_info "步骤 1/6: 启动中心机依赖（OpenSearch、Neo4j）"
log_info "----------------------------------------"

cd "$REPO"/backend
docker-compose up -d

log_info "等待 OpenSearch 启动..."
sleep 10
wait_for_service "https://localhost:9200" || log_warn "OpenSearch 可能未完全就绪"

# ==========================================
# 2. 启动 C2（DNS+HTTP）
# ==========================================
log_info "----------------------------------------"
log_info "步骤 2/6: 启动 C2（DNS+HTTP）"
log_info "----------------------------------------"

# 2.1 创建 Docker macvlan 网络
if ! docker network inspect c2-macvlan &> /dev/null; then
    log_info "创建 Docker macvlan 网络..."
    sudo docker network create -d macvlan \
      --subnet=10.92.35.0/24 \
      --gateway=10.92.35.254 \
      -o parent="$PHYSICAL_INTERFACE" \
      c2-macvlan
else
    log_info "Docker macvlan 网络已存在"
fi

# 2.2 创建宿主机 macvlan0 并添加路由
if ! ip link show macvlan0 &> /dev/null; then
    log_info "创建宿主机 macvlan0 接口..."
    sudo ip link add macvlan0 link "$PHYSICAL_INTERFACE" type macvlan mode bridge
    sudo ip addr add 10.92.35.60/24 dev macvlan0
    sudo ip link set macvlan0 up
    
    sudo ip route add 10.92.35.50/32 dev macvlan0 2>/dev/null || true
    sudo ip route add 10.92.35.51/32 dev macvlan0 2>/dev/null || true
else
    log_info "macvlan0 接口已存在"
fi

# 2.3 准备 C2 配置与静态内容
log_info "准备 C2 配置文件..."
mkdir -p "$BASE"/run/c2/html

cat > "$BASE"/run/c2/Corefile <<'EOF'
.:53 {
  log
  errors
  hosts /etc/coredns/hosts {
    reload 1s
    fallthrough
  }
  forward . 223.5.5.5 114.114.114.114
}
EOF

cat > "$BASE"/run/c2/hosts <<'EOF'
10.92.35.51 c2.lab.local
EOF

printf "ok\n" > "$BASE"/run/c2/html/health
printf "hello from c2 (benign)\n" > "$BASE"/run/c2/html/payload

# 2.4 启动 C2 容器
log_info "启动 C2 容器..."
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

log_info "等待 C2 服务启动..."
sleep 3

# ==========================================
# 3. 启动 4 套客户机采集栈
# ==========================================
log_info "----------------------------------------"
log_info "步骤 3/6: 启动 4 套客户机采集栈"
log_info "----------------------------------------"

# 3.1 准备运行目录
log_info "准备客户机运行目录..."
mkdir -p "$BASE"/run/client-{01,02,03,04}/data

# 3.2 复制 docker-compose.yml 和创建软链接
log_info "复制配置文件..."
for i in 01 02 03 04; do
    cp "$REPO"/client/docker-compose.yml "$BASE"/run/client-$i/docker-compose.yml
    ln -snf "$REPO"/client/sensor "$BASE"/run/client-$i/sensor 2>/dev/null || true
    ln -snf "$REPO"/client/backend "$BASE"/run/client-$i/backend 2>/dev/null || true
done

# 3.3 写入 .env 文件
log_info "写入环境变量配置..."
cat > "$BASE"/run/client-01/.env <<'EOF'
CLIENT_API_PORT=18881
HOST_ID=h-client-01
HOST_NAME=victim-01
SURICATA_INTERFACE=macvlan0
EOF

cat > "$BASE"/run/client-02/.env <<'EOF'
CLIENT_API_PORT=18882
HOST_ID=h-client-02
HOST_NAME=victim-02
SURICATA_INTERFACE=macvlan0
EOF

cat > "$BASE"/run/client-03/.env <<'EOF'
CLIENT_API_PORT=18883
HOST_ID=h-client-03
HOST_NAME=victim-03
SURICATA_INTERFACE=macvlan0
EOF

cat > "$BASE"/run/client-04/.env <<'EOF'
CLIENT_API_PORT=18884
HOST_ID=h-client-04
HOST_NAME=victim-04
SURICATA_INTERFACE=macvlan0
EOF

# 3.4 修复 docker-compose.yml（添加 container_name 和端口映射）
log_info "修复 docker-compose.yml..."
for i in 01 02 03 04; do
    cd "$BASE"/run/client-$i
    
    python3 <<PYEOF
import yaml

with open('docker-compose.yml', 'r') as f:
    compose = yaml.safe_load(f)

project_name = f'client-$i'
port_map = {'01': '18881', '02': '18882', '03': '18883', '04': '18884'}
host_port = port_map['$i']

# 为每个服务添加container_name
for service_name, service_config in compose['services'].items():
    service_config['container_name'] = f"{project_name}_{service_name}_1"

# 修复backend的端口映射
if 'backend' in compose['services']:
    compose['services']['backend']['ports'] = [f"{host_port}:8888"]

# 移除rabbitmq的ports配置（如果存在）
if 'rabbitmq' in compose['services'] and 'ports' in compose['services']['rabbitmq']:
    del compose['services']['rabbitmq']['ports']

with open('docker-compose.yml', 'w') as f:
    yaml.dump(compose, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

print(f"已修复 client-$i: container_name已添加，backend端口映射为 {host_port}:8888")
PYEOF
done

# 3.5 启动 4 个实例
log_info "启动客户机实例..."
for i in 01 02 03 04; do
    log_info "启动 client-$i..."
    cd "$BASE"/run/client-$i
    docker-compose -p client-$i up -d --build
done

log_info "等待客户机服务启动..."
sleep 10

# ==========================================
# 4. 启动中心机后端（FastAPI）
# ==========================================
log_info "----------------------------------------"
log_info "步骤 4/6: 启动中心机后端（FastAPI）"
log_info "----------------------------------------"

cd "$REPO"/backend
export OPENSEARCH_NODE="https://localhost:9200"
export OPENSEARCH_USERNAME="admin"
export OPENSEARCH_PASSWORD="OpenSearch@2024!Dev"
export OPENSEARCH_URL="https://localhost:9200"
export OPENSEARCH_USER="admin"
export NEO4J_URI="bolt://localhost:7687"
export NEO4J_USER="neo4j"
export NEO4J_PASSWORD="password"

# 检查是否已运行
if pgrep -f "uvicorn main:app" > /dev/null; then
    log_warn "后端服务已在运行"
else
    log_info "启动后端服务（后台运行）..."
    nohup uv run uvicorn main:app --host 0.0.0.0 --port 8001 > "$BASE"/run/backend.log 2>&1 &
    echo $! > "$BASE"/run/backend.pid
    log_info "后端服务已启动，PID: $(cat "$BASE"/run/backend.pid)"
    log_info "日志文件: $BASE/run/backend.log"
    
    wait_for_service "http://localhost:8001/health" || log_warn "后端服务可能未完全就绪"
fi

# ==========================================
# 5. 启动中心机前端（Next.js）
# ==========================================
log_info "----------------------------------------"
log_info "步骤 5/6: 启动中心机前端（Next.js）"
log_info "----------------------------------------"

cd "$REPO"/frontend

# 检查 Node.js 版本
NODE_VERSION=$(node --version | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 20 ]; then
    log_error "Node.js 版本过低（当前: $(node --version)），需要 >= 20.9.0"
    log_info "请先升级 Node.js，或使用 nvm: nvm install 20 && nvm use 20"
    exit 1
fi

# 检查是否已运行
if pgrep -f "next-server" > /dev/null; then
    log_warn "前端服务已在运行"
else
    log_info "安装依赖（如果需要）..."
    [ ! -d "node_modules" ] && npm ci
    
    log_info "启动前端服务（后台运行）..."
    nohup npm run dev -- -H 0.0.0.0 -p 3000 > "$BASE"/run/frontend.log 2>&1 &
    echo $! > "$BASE"/run/frontend.pid
    log_info "前端服务已启动，PID: $(cat "$BASE"/run/frontend.pid)"
    log_info "日志文件: $BASE/run/frontend.log"
    
    wait_for_service "http://localhost:3000" || log_warn "前端服务可能未完全就绪"
fi

# ==========================================
# 6. 注册 4 个客户机到中心机
# ==========================================
log_info "----------------------------------------"
log_info "步骤 6/6: 注册客户机到中心机"
log_info "----------------------------------------"

log_info "等待后端服务完全就绪..."
sleep 5

register_client() {
    local client_id=$1
    local port=$2
    local host_id=$3
    local host_name=$4
    
    log_info "注册 $client_id..."
    response=$(curl -sS -X POST "http://localhost:8001/api/v1/clients/register" \
      -H "Content-Type: application/json" \
      -d "{\"client_id\":\"$client_id\",\"client_version\":\"0.1.0\",\"listen_url\":\"http://10.92.35.13:$port\",\"host\":{\"id\":\"$host_id\",\"name\":\"$host_name\"},\"capabilities\":{\"filebeat\":true,\"falco\":true,\"suricata\":true}}")
    
    if echo "$response" | grep -q '"status":"ok"'; then
        log_info "$client_id 注册成功"
    else
        log_warn "$client_id 注册可能失败，响应: $response"
    fi
}

register_client "client-01" "18881" "h-client-01" "victim-01"
register_client "client-02" "18882" "h-client-02" "victim-02"
register_client "client-03" "18883" "h-client-03" "victim-03"
register_client "client-04" "18884" "h-client-04" "victim-04"

# ==========================================
# 完成
# ==========================================
log_info "=========================================="
log_info "启动完成！"
log_info "=========================================="
log_info "服务状态："
log_info "  - 中心机基础设施: OpenSearch (9200), Neo4j (7474, 7687)"
log_info "  - 中心机后端: http://10.92.35.13:8001"
log_info "  - 中心机前端: http://10.92.35.13:3000"
log_info "  - C2 DNS: 10.92.35.50:53"
log_info "  - C2 HTTP: http://10.92.35.51"
log_info "  - 客户机: client-01..04 (18881-18884)"
log_info ""
log_info "验证命令："
log_info "  ss -lntup | grep -E ':(9200|9600|7474|7687|8001|3000|18881|18882|18883|18884)'"
log_info ""
log_info "查看日志："
log_info "  tail -f $BASE/run/backend.log   # 后端日志"
log_info "  tail -f $BASE/run/frontend.log  # 前端日志"
log_info ""
log_info "停止服务："
log_info "  kill \$(cat $BASE/run/backend.pid)   # 停止后端"
log_info "  kill \$(cat $BASE/run/frontend.pid)  # 停止前端"
log_info "  然后执行停机脚本或手动停止容器"
log_info "=========================================="