# -*- coding: utf-8 -*-
"""
告警搜索API测试框架
"""
import pytest

pytestmark = pytest.mark.integration


class TestFindingsAPI:
    """测试告警搜索API"""

    @pytest.mark.asyncio
    async def test_get_findings_success(self, async_client):
        """测试成功获取告警列表"""
        response = await async_client.get("/api/v1/findings/")
        assert response.status_code == 200
        data = response.json()
        assert "ok" in data

    @pytest.mark.asyncio
    async def test_search_findings_by_technique(self, async_client):
        """测试按Technique搜索告警"""
        # TODO: 添加测试数据后再完善
        pass
