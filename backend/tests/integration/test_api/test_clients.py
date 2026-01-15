# -*- coding: utf-8 -*-
"""
客户端注册API测试框架
"""
import pytest

pytestmark = [pytest.mark.integration, pytest.mark.requires_opensearch]


class TestClientsAPI:
    """测试客户端注册API"""

    @pytest.mark.asyncio
    async def test_list_clients(self, async_client):
        """测试列出已注册客户端"""
        response = await async_client.get("/api/v1/clients")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"

    @pytest.mark.asyncio
    async def test_register_client(self, async_client):
        """测试注册新客户端"""
        # TODO: 添加测试数据后再完善
        pass
