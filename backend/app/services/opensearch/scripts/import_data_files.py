#!/usr/bin/env python3
"""
导入 data 目录下的 ECS 数据文件到 OpenSearch

用法:
    uv run python import_data_files.py
"""

import json
import sys
import hashlib
from pathlib import Path

# 添加项目根目录到路径
project_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from app.services.opensearch import store_events


def ensure_event_id(event: dict) -> None:
    """确保事件有 event.id 字段，如果没有则生成一个"""
    # 检查是否已有 event.id
    event_obj = event.get("event", {})
    if isinstance(event_obj, dict) and event_obj.get("id"):
        return
    
    if event.get("event.id"):
        return
    
    # 生成 event.id（基于 @timestamp 和其他字段的哈希）
    timestamp = event.get("@timestamp", "")
    host_name = event.get("host", {}).get("name", "") if isinstance(event.get("host"), dict) else event.get("host.name", "")
    message = event.get("message", "")
    
    # 生成唯一 ID
    id_string = f"{timestamp}|{host_name}|{message}"
    event_id = hashlib.sha256(id_string.encode('utf-8')).hexdigest()[:16]
    
    # 添加到事件中
    if isinstance(event_obj, dict):
        event_obj["id"] = event_id
    else:
        event["event.id"] = event_id


def load_json_file(file_path: Path) -> list[dict]:
    """加载 JSON 文件并返回 data 数组"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content_str = f.read()
        
        # 处理 falco.json 的特殊格式（开头可能有 "faclco:"）
        if file_path.name == "falco.json" and content_str.startswith("faclco:"):
            content_str = content_str.replace("faclco:", "", 1).strip()
        
        content = json.loads(content_str)
        
        # 支持两种格式：
        # 1. {"data": [...], "total": ...}
        # 2. 直接是数组 [...]
        if isinstance(content, dict) and "data" in content:
            return content["data"]
        elif isinstance(content, list):
            return content
        else:
            print(f"[WARNING] 文件 {file_path.name} 格式不支持，跳过")
            return []
    except Exception as e:
        print(f"[ERROR] 读取文件 {file_path.name} 失败: {e}")
        return []


def main():
    """主函数"""
    # 获取 data 目录路径
    scripts_dir = Path(__file__).parent
    data_dir = scripts_dir.parent / "data"
    
    if not data_dir.exists():
        print(f"[ERROR] 数据目录不存在: {data_dir}")
        return 1
    
    # 查找所有 JSON 文件
    json_files = list(data_dir.glob("*.json"))
    
    if not json_files:
        print(f"[WARNING] 在 {data_dir} 中未找到 JSON 文件")
        return 0
    
    print(f"[INFO] 找到 {len(json_files)} 个 JSON 文件")
    
    all_events = []
    
    # 读取所有文件
    for json_file in json_files:
        print(f"\n[INFO] 读取文件: {json_file.name}")
        events = load_json_file(json_file)
        
        if events:
            print(f"[INFO]   提取到 {len(events)} 条数据")
            # 确保每条事件都有 event.id
            for event in events:
                ensure_event_id(event)
            all_events.extend(events)
        else:
            print(f"[WARNING]   文件 {json_file.name} 没有有效数据")
    
    if not all_events:
        print("\n[WARNING] 没有找到任何有效数据，退出")
        return 0
    
    print(f"\n[INFO] 总共准备导入 {len(all_events)} 条数据")
    
    # 导入到 OpenSearch
    print("\n[INFO] 开始导入到 OpenSearch...")
    result = store_events(all_events)
    
    # 打印结果
    print("\n[INFO] 导入完成:")
    print(f"    - 总数: {result.get('total', 0)}")
    print(f"    - 成功: {result.get('success', 0)}")
    print(f"    - 失败: {result.get('failed', 0)}")
    print(f"    - 重复: {result.get('duplicated', 0)}")
    dropped = result.get('dropped', 0)
    print(f"    - 丢弃: {dropped}")
    
    if dropped > 0:
        print(f"\n[WARNING] 有 {dropped} 条数据被丢弃，可能原因：")
        print("    1. 缺少必需的字段（如 @timestamp）")
        print("    2. event.kind 不是 'event' 或 'alert'")
        print("    3. 数据格式不符合 ECS 规范")
    
    # 打印详细统计
    details = result.get('details', {})
    if details:
        print("\n[INFO] 各索引详细统计:")
        for index_name, stats in details.items():
            print(f"    - {index_name}:")
            print(f"        成功: {stats.get('success', 0)}")
            print(f"        失败: {stats.get('failed', 0)}")
            print(f"        重复: {stats.get('duplicated', 0)}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
