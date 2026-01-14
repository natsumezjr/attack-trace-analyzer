# -*- coding: utf-8 -*-
"""
目标节点API测试框架
"""
import pytest

pytestmark = pytest.mark.integration


class TestTargetsAPI:
    """测试目标节点API"""

    @pytest.mark.asyncio
    async def test_list_targets(self, async_client):
        """测试列出目标节点"""
        response = await async_client.get("/api/v1/targets/")
        assert response.status_code == 200
        data = response.json()
        assert "ok" in data
