#!/bin/bash
# 部署脚本：更新客户机 Go 后端二进制文件
# 用途：修复 event.id 缺失导致数据被丢弃的 BUG

set -e

echo "=== 开始部署新的 go-client 二进制文件 ==="

# 1. 拉取最新代码
echo "📥 拉取最新代码..."
cd /home/ubuntu/attack-trace-analyzer/repo/attack-trace-analyzer
git pull origin main

# 2. 验证新的二进制文件包含 ensureEventID 函数
echo "🔍 验证新二进制文件..."
NEW_BINARY="/home/ubuntu/attack-trace-analyzer/repo/attack-trace-analyzer/client/backend/go-client"
if strings "$NEW_BINARY" | grep -q "ensureEventID"; then
    echo "✅ 新二进制文件包含 ensureEventID 函数"
else
    echo "❌ 错误：新二进制文件缺少 ensureEventID 函数"
    exit 1
fi

# 3. 停止客户机容器
echo "🛑 停止客户机容器..."
cd /home/ubuntu/attack-trace-analyzer/run
for i in {01..04}; do
    docker-compose -f client/docker-compose.yml stop client-${i}_backend
done

# 4. 备份旧二进制文件
echo "💾 备份旧二进制文件..."
for i in {01..04}; do
    CONTAINER="client-${i}_backend_1"
    if docker cp "$CONTAINER:/usr/local/bin/go-client" "/tmp/go-client.backup.$i" 2>/dev/null; then
        echo "✅ 已备份 client-$i 的旧二进制文件"
    fi
done

# 5. 复制新二进制文件到容器
echo "📋 复制新二进制文件到容器..."
for i in {01..04}; do
    CONTAINER="client-${i}_backend_1"
    docker cp "$NEW_BINARY" "$CONTAINER:/usr/local/bin/go-client"
    docker exec "$CONTAINER" chmod +x /usr/local/bin/go-client
    echo "✅ 已更新 client-$i"
done

# 6. 重启客户机容器
echo "🔄 重启客户机容器..."
for i in {01..04}; do
    docker-compose -f client/docker-compose.yml start client-${i}_backend
done

# 7. 等待容器启动
echo "⏳ 等待容器启动..."
sleep 5

# 8. 验证部署
echo "🧪 测试新二进制文件..."
for i in {01..04}; do
    PORT=$((18880 + i))
    echo "测试 client-$i (端口 $PORT)..."
    RESPONSE=$(curl -s "http://localhost:$PORT/falco" | jq -r '.total')
    echo "  返回事件数: $RESPONSE"

    # 检查 event.id 是否存在
    if [ "$RESPONSE" != "0" ]; then
        HAS_ID=$(curl -s "http://localhost:$PORT/falco" | jq -r '.data[0].event.id // "MISSING"')
        echo "  event.id: $HAS_ID"
        if [ "$HAS_ID" != "MISSING" ]; then
            echo "  ✅ client-$i 部署成功！"
        else
            echo "  ⚠️  client-$i event.id 仍然缺失"
        fi
    fi
done

echo ""
echo "=== 部署完成 ==="
echo ""
echo "📊 验证 OpenSearch 数据存储："
echo "  curl -k -s -u admin:OpenSearch@2024!Dev 'https://localhost:9200/_cat/indices?v' | grep ecs-events"
echo ""
echo "📋 查看后端日志："
echo "  tail -f /home/ubuntu/attack-trace-analyzer/run/backend.log"
