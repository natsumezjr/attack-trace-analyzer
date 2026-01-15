#!/bin/bash
# 便捷测试脚本 - 依次执行数据导入和分析

set -e

echo "=========================================="
echo "KillChain 测试流程"
echo "=========================================="
echo ""

# 检查是否在 Docker 容器中
if [ -f /.dockerenv ]; then
    PYTHON_CMD="python"
else
    PYTHON_CMD="python3"
fi

# 步骤 1: 导入测试数据
echo "[步骤 1/2] 导入测试数据到 Neo4j..."
echo "----------------------------------------"
$PYTHON_CMD scripts/import_test_data.py

echo ""
echo "----------------------------------------"
echo ""

# 步骤 2: 运行分析
echo "[步骤 2/2] 运行 KillChain 分析..."
echo "----------------------------------------"
$PYTHON_CMD scripts/test_analyze.py

echo ""
echo "=========================================="
echo "测试流程完成！"
echo "=========================================="
