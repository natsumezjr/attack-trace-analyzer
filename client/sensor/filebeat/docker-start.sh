#!/bin/bash
# Docker 一键启动脚本
# 自动构建镜像、启动容器并显示日志

set -e  # 遇到错误立即退出

# 解析命令行参数
REBUILD=false
if [ "$1" = "--rebuild" ] || [ "$1" = "-r" ]; then
    REBUILD=true
fi

echo "============================================================"
echo "Ubuntu Log Anomaly Detection System - Docker 一键启动"
echo "============================================================"
echo ""

# 1. 检查 Docker 是否安装
echo "[1/6] 检查 Docker 环境..."
if ! command -v docker &> /dev/null; then
    echo "✗ Docker 未安装！请先安装 Docker"
    echo "   安装指南: https://docs.docker.com/get-docker/"
    exit 1
fi

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "✗ Docker Compose 未安装！请先安装 Docker Compose"
    echo "   安装指南: https://docs.docker.com/compose/install/"
    exit 1
fi
echo "✓ Docker 环境检查通过"
echo ""

# 2. 停止并删除旧容器
echo "[2/6] 清理旧容器..."
docker stop filebeat 2>/dev/null || true
docker rm filebeat 2>/dev/null || true
echo "✓ 已清理旧容器"
echo ""

# 3. 检查镜像是否存在
echo "[3/6] 检查 Docker 镜像..."
IMAGE_EXISTS=$(docker images -q filebeat-log-detector 2>/dev/null)

if [ "$REBUILD" = true ]; then
    echo "   强制重新构建镜像..."
    if docker compose version &> /dev/null; then
        docker compose build --no-cache
    else
        docker-compose build --no-cache
    fi
    echo "✓ 镜像重新构建完成"
elif [ -z "$IMAGE_EXISTS" ]; then
    echo "   镜像不存在，开始构建..."
    echo "   这可能需要几分钟时间（首次构建）..."
    if docker compose version &> /dev/null; then
        docker compose build
    else
        docker-compose build
    fi
    echo "✓ 镜像构建完成"
else
    echo "✓ 镜像已存在，跳过构建"
    echo "   提示：如果代码有更新，运行 './docker-start.sh --rebuild' 重新构建"
fi
echo ""

# 4. 清理 output 目录中的 JSON 文件
echo "[4/6] 清理旧的 JSON 输出文件..."
mkdir -p output
rm -f output/ecs_logs_with_anomalies.json output/anomalies.json
echo "✓ JSON 输出文件已清理（保留数据库）"
echo ""

# 5. 启动容器（后台运行）
echo "[5/6] 启动容器..."
if docker compose version &> /dev/null; then
    docker compose up -d
else
    docker-compose up -d
fi
echo "✓ 容器已启动"
echo ""

# 6. 等待容器初始化
echo "[6/6] 等待系统初始化..."
sleep 3

# 检查容器状态
if ! docker ps | grep -q filebeat; then
    echo "✗ 容器启动失败！查看日志:"
    echo "   docker logs filebeat"
    exit 1
fi
echo "✓ 系统运行正常"
echo ""

echo "============================================================"
echo "系统已成功启动！"
echo "============================================================"
echo ""
echo "📊 查看实时日志:"
echo "   docker logs -f filebeat"
echo ""
echo "📁 输出目录:"
echo "   ./output/ecs_logs_with_anomalies.json  # 所有日志（含异常标记）"
echo "   ./output/anomalies.json                # 仅异常日志"
echo "   ./output/data.db                       # SQLite 数据库"
echo ""
echo "🔍 查询数据库:"
echo "   python3 query_database.py"
echo ""
echo "🛑 停止系统:"
if docker compose version &> /dev/null; then
    echo "   docker compose down"
else
    echo "   docker-compose down"
fi
echo ""
echo "💡 测试异常检测:"
echo "   # SSH 失败登录（在宿主机上执行）"
echo "   ssh wronguser@localhost"
echo ""
echo "   # Sudo 操作"
echo "   sudo ls"
echo ""
echo "   # 创建用户"
echo "   sudo useradd testuser123"
echo ""
echo "按 Ctrl+C 查看日志（不会停止容器）"
echo ""

# 显示实时日志（用户可以按 Ctrl+C 退出，容器继续运行）
trap 'echo ""; echo "日志查看已停止，容器仍在运行"; echo ""; exit 0' INT
docker logs -f filebeat
