#!/bin/bash
# 靶场一键启动脚本（最简版）

set -e

# 颜色输出
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 固定变量
export BASE=/home/ubuntu/attack-trace-analyzer
export REPO="$BASE"/repo/attack-trace-analyzer

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_info "=========================================="
log_info "靶场一键启动脚本"
log_info "=========================================="

# 1. 启动中心机依赖（OpenSearch、Neo4j）
log_info "步骤 1/6: 启动中心机依赖..."
cd "$REPO"/backend
docker-compose up -d
sleep 5

# 2. 启动 C2（DNS+HTTP）
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

# 3. 启动 4 套客户机采集栈
log_info "步骤 3/6: 启动客户机..."
for i in 01 02 03 04; do
    cd "$BASE"/run/client-$i
    docker-compose -p client-$i up -d
done
sleep 5

# 4. 启动中心机后端（FastAPI）
log_info "步骤 4/6: 启动后端..."
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
fi
sleep 3

# 5. 启动中心机前端（Next.js）
log_info "步骤 5/6: 启动前端..."
cd "$REPO"/frontend
if ! pgrep -f "next-server" > /dev/null; then
    nohup npm run dev -- -H 0.0.0.0 -p 3000 > "$BASE"/run/frontend.log 2>&1 &
    echo $! > "$BASE"/run/frontend.pid
    log_info "前端已启动，PID: $(cat "$BASE"/run/frontend.pid)"
fi
sleep 3

# 6. 注册 4 个客户机到中心机
log_info "步骤 6/6: 注册客户机..."
sleep 2
curl -sS -X POST "http://localhost:8001/api/v1/clients/register" \
  -H "Content-Type: application/json" \
  -d '{"client_id":"client-01","client_version":"0.1.0","listen_url":"http://10.92.35.13:18881","host":{"id":"h-client-01","name":"victim-01"},"capabilities":{"filebeat":true,"falco":true,"suricata":true}}' | grep -q '"status":"ok"' && log_info "client-01 注册成功" || echo "client-01 注册失败"

curl -sS -X POST "http://localhost:8001/api/v1/clients/register" \
  -H "Content-Type: application/json" \
  -d '{"client_id":"client-02","client_version":"0.1.0","listen_url":"http://10.92.35.13:18882","host":{"id":"h-client-02","name":"victim-02"},"capabilities":{"filebeat":true,"falco":true,"suricata":true}}' | grep -q '"status":"ok"' && log_info "client-02 注册成功" || echo "client-02 注册失败"

curl -sS -X POST "http://localhost:8001/api/v1/clients/register" \
  -H "Content-Type: application/json" \
  -d '{"client_id":"client-03","client_version":"0.1.0","listen_url":"http://10.92.35.13:18883","host":{"id":"h-client-03","name":"victim-03"},"capabilities":{"filebeat":true,"falco":true,"suricata":true}}' | grep -q '"status":"ok"' && log_info "client-03 注册成功" || echo "client-03 注册失败"

curl -sS -X POST "http://localhost:8001/api/v1/clients/register" \
  -H "Content-Type: application/json" \
  -d '{"client_id":"client-04","client_version":"0.1.0","listen_url":"http://10.92.35.13:18884","host":{"id":"h-client-04","name":"victim-04"},"capabilities":{"filebeat":true,"falco":true,"suricata":true}}' | grep -q '"status":"ok"' && log_info "client-04 注册成功" || echo "client-04 注册失败"

log_info "=========================================="
log_info "启动完成！"
log_info "=========================================="
log_info "验证: ss -lntup | grep -E ':(9200|9600|7474|7687|8001|3000|18881|18882|18883|18884)'"