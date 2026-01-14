# -*- coding: utf-8 -*-
"""
事件搜索API测试框架
"""
import pytest
from datetime import datetime

pytestmark = pytest.mark.integration


class TestEventsAPI:
    """测试事件搜索API"""

    @pytest.mark.asyncio
    async def test_get_events_success(self, async_client):
        """测试成功获取事件列表"""
        response = await async_client.get("/api/v1/events/")
        assert response.status_code == 200
        data = response.json()
        assert "ok" in data

    @pytest.mark.asyncio
    async def test_search_events_with_filters(self, async_client):
        """测试带过滤条件的事件搜索"""
        # TODO: 添加测试数据后再完善
        pass
