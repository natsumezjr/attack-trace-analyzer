#!/bin/bash
#
# 检测结果验证脚本
#
# 作用：验证攻击是否被检测系统成功捕获
#

echo "=========================================="
echo "检测结果验证"
echo "=========================================="
echo ""

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# 检查函数
check() {
    local name=$1
    local command=$2
    local expected=$3
    
    echo -n "检查 $name... "
    
    result=$(eval "$command" 2>/dev/null)
    
    if [ "$result" != "$expected" ]; then
        echo -e "${RED}✗ 失败${NC}"
        echo "  期望: $expected"
        echo "  实际: $result"
        return 1
    else
        echo -e "${GREEN}✓ 通过${NC}"
        return 0
    fi
}

# 1. 检查后端健康
echo "【1. 检查后端服务】"
check "后端健康检查" \
    "curl -s http://localhost:8001/health | jq -r '.status'" \
    "ok"
echo ""

# 2. 检查虚拟机采集栈
echo "【2. 检查虚拟机采集栈】"
for i in 1 2 3 4; do
    HOST="192.168.1.1$i"
    echo -n "  victim-0$i ($HOST)... "
    
    if curl -s "http://$HOST:18881/falco" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ 运行中${NC}"
    else
        echo -e "${RED}✗ 不可达${NC}"
    fi
done
echo ""

# 3. 检查事件入库
echo "【3. 检查事件入库】"
TOTAL=$(curl -s -X POST http://localhost:8001/api/v1/events/search \
    -H "Content-Type: application/json" \
    -d '{"size": 1}' | jq '.total')

if [ "$TOTAL" -gt 0 ]; then
    echo -e "${GREEN}✓ 事件已入库${NC} (总数: $TOTAL)"
else
    echo -e "${RED}✗ 没有事件${NC}"
fi
echo ""

# 4. 检查告警生成
echo "【4. 检查告警生成】"
ALERTS=$(curl -s -X POST http://localhost:8001/api/v1/findings/search \
    -H "Content-Type: application/json" \
    -d '{"stage": "raw", "size": 1}' | jq '.total')

if [ "$ALERTS" -gt 0 ]; then
    echo -e "${GREEN}✓ 告警已生成${NC} (总数: $ALERTS)"
else
    echo -e "${RED}✗ 没有告警${NC}"
fi
echo ""

# 5. 检查图谱构建
echo "【5. 检查图谱构建】"
echo "  请在前端界面查看图谱节点数量"
echo ""

# 6. 示例事件查询
echo "【6. 示例事件查询】"
echo "  Falco 事件:"
FALCO_COUNT=$(curl -s -X POST http://localhost:8001/api/v1/events/search \
    -H "Content-Type: application/json" \
    -d '{"size": 0, "query": {"bool": {"must": [{"term": {"event.module": "falco"}}]}}}' | jq '.total')
echo "    总数: $FALCO_COUNT"

echo "  Filebeat 事件:"
FILEBEAT_COUNT=$(curl -s -X POST http://localhost:8001/api/v1/events/search \
    -H "Content-Type: application/json" \
    -d '{"size": 0, "query": {"bool": {"must": [{"term": {"event.module": "system"}}]}}}' | jq '.total')
echo "    总数: $FILEBEAT_COUNT"

echo "  Suricata 事件:"
SURICATA_COUNT=$(curl -s -X POST http://localhost:8001/api/v1/events/search \
    -H "Content-Type: application/json" \
    -d '{"size": 0, "query": {"bool": {"must": [{"term": {"event.module": "suricata"}}]}}}' | jq '.total')
echo "    总数: $SURICATA_COUNT"
echo ""

# 7. 总结
echo "=========================================="
echo "验证完成"
echo "=========================================="
echo ""
echo "如果所有检查都通过，说明："
echo "  ✓ 后端服务正常运行"
echo "  ✓ 虚拟机采集栈正常"
echo "  ✓ 事件成功入库"
echo "  ✓ 告警成功生成"
echo ""
echo "下一步："
echo "  1. 打开前端: http://localhost:3000"
echo "  2. 查看图谱可视化"
echo "  3. 创建溯源任务"
echo "  4. 查看 KillChain 分析结果"
echo ""
