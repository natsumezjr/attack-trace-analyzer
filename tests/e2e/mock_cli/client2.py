#!/usr/bin/env python3
"""
模拟客户机 2：数据库服务器攻击场景

攻击场景：
- TA0001: 暴力破解 SSH
- TA0002: 执行恶意 SQL
- TA0009: 导出敏感数据
- TA0010: 数据删除
"""

from fastapi import FastAPI
import uvicorn
import requests
from apt_data import generate_db_server_attacks
from typing import List, Dict

app = FastAPI(title="Mock Client 2 - Database Server")

# 预加载数据到内存队列
falco_queue: List[Dict] = []
filebeat_queue: List[Dict] = []
suricata_queue: List[Dict] = []

# 客户机配置
CLIENT_ID = "client-2"
HOST_ID = "db-server-001"
HOST_NAME = "db-01"
PORT = 8889


@app.on_event("startup")
async def startup_event():
    """启动时：加载数据 + 注册到中心机"""
    global falco_queue, filebeat_queue, suricata_queue

    # 1. 生成 APT 攻击数据
    attack_data = generate_db_server_attacks()
    falco_queue = attack_data["falco"]
    # 将 findings 和 filebeat 合并
    filebeat_queue = attack_data["filebeat"] + attack_data.get("findings", [])
    suricata_queue = attack_data["suricata"]

    print(f"[{CLIENT_ID}] 数据加载完成:")
    print(f"  - Falco: {len(falco_queue)} 条")
    print(f"  - Filebeat: {len(filebeat_queue)} 条")
    print(f"  - Suricata: {len(suricata_queue)} 条")
    print(f"  - 总计: {len(falco_queue) + len(filebeat_queue) + len(suricata_queue)} 条")

    # 2. 注册到中心机 (使用不同的 IP 以避免端口冲突)
    try:
        response = requests.post(
            "http://localhost:8001/api/v1/targets/register",
            json={"ip": "127.0.0.1"},
            timeout=5
        )
        if response.status_code == 200:
            print(f"[{CLIENT_ID}] ✅ 注册成功")
        else:
            print(f"[{CLIENT_ID}] ⚠️  注册失败: {response.status_code}")
    except Exception as e:
        print(f"[{CLIENT_ID}] ⚠️  注册异常: {e}")

    print(f"[{CLIENT_ID}] 等待中心机轮询...")


@app.get("/falco")
async def get_falco_events():
    """返回 Falco 事件并清空队列"""
    events = falco_queue.copy()
    falco_queue.clear()
    print(f"[{CLIENT_ID}] 返回 {len(events)} 条 Falco 事件")
    return {"total": len(events), "data": events}


@app.get("/filebeat")
async def get_filebeat_events():
    """返回 Filebeat 事件并清空队列"""
    events = filebeat_queue.copy()
    filebeat_queue.clear()
    print(f"[{CLIENT_ID}] 返回 {len(events)} 条 Filebeat 事件")
    return {"total": len(events), "data": events}


@app.get("/suricata")
async def get_suricata_events():
    """返回 Suricata 事件并清空队列"""
    events = suricata_queue.copy()
    suricata_queue.clear()
    print(f"[{CLIENT_ID}] 返回 {len(events)} 条 Suricata 事件")
    return {"total": len(events), "data": events}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=PORT)
