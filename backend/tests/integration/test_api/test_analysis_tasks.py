# -*- coding: utf-8 -*-
"""
分析任务API测试框架
"""
import pytest

pytestmark = pytest.mark.integration


class TestAnalysisTasksAPI:
    """测试分析任务API"""

    @pytest.mark.asyncio
    @pytest.mark.requires_opensearch
    async def test_list_tasks(self, async_client):
        """测试列出分析任务"""
        response = await async_client.get("/api/v1/analysis/tasks")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"

    @pytest.mark.asyncio
    async def test_create_task(self, async_client):
        """测试创建分析任务"""
        # Validate request handling without depending on the task runner/OpenSearch.
        response = await async_client.post(
            "/api/v1/analysis/tasks",
            json={
                "target_node_uid": "Host:host.id=test",
                # Use timezone-aware RFC3339 values to avoid naive/aware comparison issues.
                "start_ts": "1970-01-02T00:00:00Z",
                "end_ts": "1970-01-01T00:00:00Z",
            }
        )
        assert response.status_code == 400
