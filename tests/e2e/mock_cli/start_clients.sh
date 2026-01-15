#!/bin/bash
# 同时启动 4 个模拟客户机

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== 启动 4 个模拟客户机 ==="
echo ""

# 检查中心机是否运行
if ! curl -s http://localhost:8001/health > /dev/null 2>&1; then
    echo "❌ 中心机后端未运行！"
    echo "请先启动中心机:"
    echo "  cd backend"
    echo "  uvicorn main:app --host 0.0.0.0 --port 8001"
    exit 1
fi

echo "✅ 中心机运行中"
echo ""

# 清理旧日志文件
rm -f client1.log client2.log client3.log client4.log

# 使用 pixi 环境中的 Python
PIXI_PYTHON="/Users/zhangtianhua/.pixi/envs/base/bin/python3"

# 启动 4 个客户机（后台运行）
echo "启动客户机 1 (Web 服务器, 端口 8888)..."
$PIXI_PYTHON client1.py > client1.log 2>&1 &
CLIENT1_PID=$!
echo "  PID: $CLIENT1_PID"

sleep 1

echo "启动客户机 2 (数据库服务器, 端口 8889)..."
$PIXI_PYTHON client2.py > client2.log 2>&1 &
CLIENT2_PID=$!
echo "  PID: $CLIENT2_PID"

sleep 1

echo "启动客户机 3 (文件服务器, 端口 8890)..."
$PIXI_PYTHON client3.py > client3.log 2>&1 &
CLIENT3_PID=$!
echo "  PID: $CLIENT3_PID"

sleep 1

echo "启动客户机 4 (内网跳板机, 端口 8891)..."
$PIXI_PYTHON client4.py > client4.log 2>&1 &
CLIENT4_PID=$!
echo "  PID: $CLIENT4_PID"

echo ""
echo "=== 所有客户机已启动 ==="
echo ""
echo "查看日志:"
echo "  tail -f client1.log"
echo "  tail -f client2.log"
echo "  tail -f client3.log"
echo "  tail -f client4.log"
echo ""
echo "停止所有客户机:"
echo "  kill $CLIENT1_PID $CLIENT2_PID $CLIENT3_PID $CLIENT4_PID"
echo "  或: pkill -f 'client[1-4].py'"
echo ""
echo "中心机将每 5 秒自动轮询这些客户机..."
echo "请使用前端界面验证结果。"
echo ""

# 保存 PID 到文件，方便后续停止
echo "$CLIENT1_PID $CLIENT2_PID $CLIENT3_PID $CLIENT4_PID" > .client_pids.txt
echo "PID 已保存到 .client_pids.txt"
