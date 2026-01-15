# -*- coding: utf-8 -*-
"""
事件搜索API测试框架
"""
import pytest

pytestmark = [pytest.mark.integration, pytest.mark.requires_opensearch]


class TestEventsAPI:
    """测试事件搜索API"""

    @pytest.mark.asyncio
    async def test_search_events_success(self, async_client):
        """测试成功搜索事件"""
        response = await async_client.post("/api/v1/events/search", json={})
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"

    @pytest.mark.asyncio
    async def test_search_events_with_filters(self, async_client):
        """测试带过滤条件的事件搜索"""
        # TODO: 添加测试数据后再完善
        pass
