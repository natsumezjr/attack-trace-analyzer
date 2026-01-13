#!/bin/bash
# 一键启动异常日志检测系统
# 自动处理所有前置准备并启动Filebeat和检测器

set -e  # 遇到错误立即退出

echo "============================================================"
echo "Ubuntu Log Anomaly Detection System - 一键启动"
echo "============================================================"
echo ""

# 1. 停止所有旧的Filebeat进程
echo "[1/6] 停止旧的Filebeat进程..."
sudo systemctl stop filebeat 2>/dev/null || true
sudo pkill -9 filebeat 2>/dev/null || true
echo "✓ 已停止所有Filebeat进程"
echo ""

# 2. 修复配置文件权限
echo "[2/6] 修复配置文件权限..."
sudo chown root:root filebeat.yml
sudo chmod 644 filebeat.yml
echo "✓ 配置文件权限已修复"
echo ""

# 3. 清理旧的输出文件
echo "[3/6] 清理旧的输出文件..."
sudo rm -f /tmp/filebeat-output/ecs_logs.json* 2>/dev/null || true
sudo mkdir -p /tmp/filebeat-output
sudo chmod 777 /tmp/filebeat-output
echo "✓ 输出目录已准备"
echo ""

# 4. 清理旧的检测器输出
echo "[4/6] 清理旧的检测器 JSON 输出..."
mkdir -p output
rm -f output/ecs_logs_with_anomalies.json output/anomalies.json
echo "✓ JSON 输出文件已清理（保留数据库）"
echo ""

# 5. 后台启动Filebeat
echo "[5/6] 启动Filebeat（后台运行）..."
sudo nohup filebeat -e -c filebeat.yml > /tmp/filebeat.log 2>&1 &
FILEBEAT_PID=$!
echo "✓ Filebeat已启动 (PID: $FILEBEAT_PID)"
echo "   日志文件: /tmp/filebeat.log"
echo ""

# 等待Filebeat初始化
echo "等待Filebeat初始化..."
sleep 3

# 验证Filebeat是否运行
if ! pgrep -x filebeat > /dev/null; then
    echo "✗ Filebeat启动失败！查看日志: tail /tmp/filebeat.log"
    exit 1
fi
echo "✓ Filebeat运行正常"
echo ""

# 6. 启动检测器
echo "[6/6] 启动异常检测器..."
echo "============================================================"
echo ""

sudo python3 detector.py

# 脚本结束时清理
echo ""
echo "============================================================"
echo "检测器已停止"
echo "============================================================"
echo ""
echo "清理进程和 JSON 文件..."
sudo pkill -9 filebeat 2>/dev/null || true
echo "✓ Filebeat已停止"

# 清理 JSON 输出文件（detector.py 已经在退出时清理了，这里再确保一次）
rm -f output/ecs_logs_with_anomalies.json output/anomalies.json 2>/dev/null || true
echo "✓ JSON 输出文件已清理"

echo ""
echo "查看结果："
echo "  python3 query_database.py"
echo "  数据库文件: output/detection_results.db"
echo ""
