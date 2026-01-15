# -*- coding: utf-8 -*-
"""
健康检查和根路径API测试
"""
import pytest

pytestmark = pytest.mark.integration


class TestHealthAPI:
    """测试健康检查API"""

    @pytest.mark.asyncio
    async def test_health_check(self, async_client):
        """测试健康检查端点"""
        response = await async_client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"


class TestRootAPI:
    """测试根路径API"""

    @pytest.mark.asyncio
    async def test_root_endpoint(self, async_client):
        """测试根路径端点"""
        response = await async_client.get("/")
        assert response.status_code == 200
