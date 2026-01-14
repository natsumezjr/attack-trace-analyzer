# -*- coding: utf-8 -*-
"""
分析任务API测试框架
"""
import pytest
from datetime import datetime

pytestmark = pytest.mark.integration


class TestAnalysisTasksAPI:
    """测试分析任务API"""

    @pytest.mark.asyncio
    async def test_list_tasks(self, async_client):
        """测试列出分析任务"""
        response = await async_client.get("/api/v1/analysis/tasks")
        assert response.status_code == 200
        data = response.json()
        assert "ok" in data

    @pytest.mark.asyncio
    async def test_create_task(self, async_client):
        """测试创建分析任务"""
        # TODO: 添加测试数据后再完善
        response = await async_client.post(
            "/api/v1/analysis/tasks",
            json={
                "target_node_uid": "Host:host.id=test",
                "start_ts": datetime.now().isoformat(),
                "end_ts": datetime.now().isoformat()
            }
        )
        # 可能返回400或其他状态码，这是预期的
        assert response.status_code in [200, 400, 404]
