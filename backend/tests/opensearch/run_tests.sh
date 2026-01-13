#!/bin/bash
# 测试运行脚本
# 用于统一运行所有测试并生成报告

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 获取脚本目录
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/../.." && pwd )"

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}OpenSearch 模块测试套件${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# 检查OpenSearch服务
echo -e "${YELLOW}检查OpenSearch服务...${NC}"
if curl -k -s -u admin:OpenSearch@2024!Dev https://localhost:9200 > /dev/null 2>&1; then
    echo -e "${GREEN}✓ OpenSearch服务运行正常${NC}"
else
    echo -e "${RED}✗ OpenSearch服务不可用${NC}"
    echo "请先启动OpenSearch服务："
    echo "  cd backend && docker compose up -d opensearch"
    exit 1
fi

# 进入 backend 目录（仓库根目录下的 backend/）
REPO_ROOT="$( cd "$SCRIPT_DIR/../../../../.." && pwd )"
cd "$REPO_ROOT/backend"

# 运行单元测试
echo ""
echo -e "${YELLOW}运行单元测试...${NC}"
uv run pytest app/services/opensearch/test/test_unit_opensearch.py \
    app/services/opensearch/test/test_analysis_incremental.py \
    -v --tb=short -m "unit" || {
    echo -e "${RED}单元测试失败${NC}"
    exit 1
}

# 运行集成测试
echo ""
echo -e "${YELLOW}运行集成测试...${NC}"
uv run pytest app/services/opensearch/test/test_system_opensearch.py \
    app/services/opensearch/test/test_integration_full.py \
    -v --tb=short -m "integration" || {
    echo -e "${RED}集成测试失败${NC}"
    exit 1
}

# 生成测试报告
echo ""
echo -e "${YELLOW}生成测试报告...${NC}"
uv run pytest app/services/opensearch/test/ \
    --html=test_report.html \
    --self-contained-html \
    --cov=opensearch \
    --cov-report=html \
    --cov-report=term || true

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}测试完成！${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "测试报告已生成："
echo "  - HTML报告: backend/test_report.html"
echo "  - 覆盖率报告: backend/htmlcov/index.html"
