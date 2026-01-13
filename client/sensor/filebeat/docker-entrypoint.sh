#!/bin/bash
set -e

# 清理函数
cleanup() {
    echo ""
    echo "========================================"
    echo "容器停止，清理 JSON 文件..."
    echo "========================================"

    # 清理 JSON 输出文件
    rm -f /app/output/ecs_logs_with_anomalies.json /app/output/anomalies.json
    echo "✓ JSON 输出文件已清理"

    # 停止 Filebeat
    if [ ! -z "$FILEBEAT_PID" ]; then
        kill $FILEBEAT_PID 2>/dev/null || true
        echo "✓ Filebeat 已停止"
    fi

    echo "数据库已保存在: ${DB_PATH:-/app/output/data.db}"
    exit 0
}

# 捕获退出信号
trap cleanup SIGINT SIGTERM EXIT

echo "========================================"
echo "启动日志异常检测系统"
echo "========================================"

# 启动 Filebeat
echo "[1/2] 启动 Filebeat..."
filebeat -e -c /etc/filebeat/filebeat.yml &
FILEBEAT_PID=$!
echo "✓ Filebeat 已启动 (PID: $FILEBEAT_PID)"

# 等待 Filebeat 初始化
sleep 3

# 启动检测器
echo "[2/2] 启动异常检测器..."
cd /app
python3 detector.py
