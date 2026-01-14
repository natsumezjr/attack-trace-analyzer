#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
检查并创建 Security Analytics Detector

用途：
1. 检查 Security Analytics 插件是否可用
2. 检查是否已有 detector
3. 如果没有，创建一个基本的 detector

使用方法：
    python check_and_create_detector.py
"""

import sys
import os
import json

# 添加项目路径
script_dir = os.path.dirname(os.path.abspath(__file__))
scripts_dir = os.path.dirname(script_dir)  # opensearch/
services_dir = os.path.dirname(scripts_dir)  # services/
app_dir = os.path.dirname(services_dir)  # app/
backend_dir = os.path.dirname(app_dir)  # backend/

sys.path.insert(0, backend_dir)

from app.services.opensearch.client import get_client, reset_client


def check_security_analytics_available(client):
    """检查 Security Analytics 插件是否可用"""
    try:
        # 尝试访问 Security Analytics API（使用 POST）
        resp = client.transport.perform_request(
            'POST',
            '/_plugins/_security_analytics/detectors/_search',
            body={"size": 0}
        )
        return True, resp, None
    except Exception as e:
        return False, None, str(e)


def list_detectors(client):
    """列出所有 detector"""
    try:
        resp = client.transport.perform_request(
            'POST',
            '/_plugins/_security_analytics/detectors/_search',
            body={"query": {"match_all": {}}, "size": 100}
        )
        hits = resp.get('hits', {}).get('hits', [])
        detectors = []
        for hit in hits:
            detector = hit.get('_source', {})
            detector['_id'] = hit.get('_id')
            detectors.append(detector)
        return True, detectors, None
    except Exception as e:
        return False, None, str(e)


def get_rules(client, max_rules: int = 20):
    """获取所有可用的规则（预打包或自定义）"""
    try:
        # 先尝试获取所有规则
        resp = client.transport.perform_request(
            'POST',
            '/_plugins/_security_analytics/rules/_search',
            body={
                "query": {"match_all": {}},
                "size": max_rules
            }
        )
        hits = resp.get('hits', {}).get('hits', [])
        
        prepackaged_rules = []
        custom_rules = []
        
        for hit in hits:
            rule_id = hit.get('_id')
            rule_index = hit.get('_index', '')
            rule_source = hit.get('_source', {})
            
            if rule_id:
                # 判断是预打包规则还是自定义规则
                is_prepackaged = ('pre-packaged' in rule_index.lower() or 
                                 'prepackaged' in rule_index.lower() or
                                 rule_source.get('prePackaged', False))
                
                # 获取规则的 log_type 或 category
                log_type = rule_source.get('log_type', rule_source.get('logType', ''))
                category = rule_source.get('category', '')
                
                rule_info = {
                    "id": rule_id,
                    "log_type": log_type,
                    "category": category
                }
                
                if is_prepackaged:
                    prepackaged_rules.append(rule_info)
                else:
                    custom_rules.append(rule_info)
        
        # 优先使用预打包规则，如果没有则使用自定义规则
        rules_to_use = prepackaged_rules if prepackaged_rules else custom_rules
        
        return True, rules_to_use, prepackaged_rules, custom_rules
    except Exception as e:
        return False, [], [], str(e)


def create_detector(client, detector_name: str = "ecs-events-detector", detector_type: str = "NETWORK"):
    """创建 detector（自动查找规则）"""
    # 先尝试获取所有可用规则
    print(f"  查找可用规则...")
    success, rules_to_use, prepackaged, custom = get_rules(client, max_rules=50)
    
    if not success:
        print(f"  [ERROR] 查询规则失败")
        return False, None, "查询规则失败"
    
    if not rules_to_use:
        print(f"  [WARNING] 未找到任何规则（预打包或自定义）")
        print(f"  [INFO] 建议先导入规则:")
        print(f"    uv run python import_sigma_rules.py --auto")
        return False, None, "未找到规则，无法创建 detector"
    
    # 根据 detector_type 筛选兼容的规则
    # OpenSearch Security Analytics 使用 log_type 或 category 来匹配
    compatible_rules = []
    for rule in rules_to_use:
        rule_log_type = rule.get('log_type', '').upper()
        rule_category = rule.get('category', '').lower()
        detector_type_lower = detector_type.lower()
        
        # 检查规则是否与 detector_type 兼容
        if (rule_log_type == detector_type.upper() or 
            rule_category == detector_type_lower or
            detector_type_lower in rule_category or
            rule_log_type in ['NETWORK', 'DNS'] and detector_type.upper() in ['NETWORK', 'DNS']):
            compatible_rules.append({"id": rule['id']})
    
    if not compatible_rules:
        print(f"  [WARNING] 未找到与 detector_type={detector_type} 兼容的规则")
        print(f"  [INFO] 尝试使用所有规则...")
        compatible_rules = [{"id": r['id']} for r in rules_to_use[:10]]  # 使用前10个规则
    
    if prepackaged:
        print(f"  [OK] 找到 {len(prepackaged)} 个预打包规则，{len(compatible_rules)} 个兼容规则")
        rules = compatible_rules
        use_prepackaged = True
    else:
        print(f"  [OK] 找到 {len(custom)} 个自定义规则，{len(compatible_rules)} 个兼容规则")
        rules = compatible_rules
        use_prepackaged = False
    
    if not rules:
        return False, None, "未找到兼容的规则"
    
    detector_config = {
        "name": detector_name,
        "detector_type": detector_type,
        "enabled": True,
        "schedule": {
            "period": {
                "interval": 5,
                "unit": "MINUTES"
            }
        },
        "inputs": [
            {
                "detector_input": {
                    "description": "ECS Events detector",
                    "indices": ["ecs-events-*"],
                    "pre_packaged_rules": rules if use_prepackaged else [],
                    "custom_rules": rules if not use_prepackaged else [],
                    "input_type": "detector_input"
                }
            }
        ],
        "triggers": []
    }
    
    try:
        resp = client.transport.perform_request(
            'POST',
            '/_plugins/_security_analytics/detectors',
            body=detector_config
        )
        return True, resp, None
    except Exception as e:
        return False, None, str(e)


def main():
    print("=" * 60)
    print("检查并创建 Security Analytics Detector")
    print("=" * 60)
    
    reset_client()
    client = get_client()
    
    # 步骤1: 检查 Security Analytics 是否可用
    print("\n步骤 1: 检查 Security Analytics 插件...")
    print("-" * 60)
    available, resp, error = check_security_analytics_available(client)
    if available:
        print("[OK] Security Analytics 插件可用")
    else:
        print(f"[X] Security Analytics 插件不可用: {error}")
        if "404" in error or "not found" in error.lower():
            print("\n[ERROR] Security Analytics 插件可能未安装或未启用")
            print("[INFO] 请检查 OpenSearch 配置，确保 Security Analytics 插件已启用")
        return 1
    
    # 步骤2: 列出现有 detector
    print("\n步骤 2: 检查现有 detector...")
    print("-" * 60)
    success, detectors, error = list_detectors(client)
    if success:
        print(f"[OK] 找到 {len(detectors)} 个 detector")
        if detectors:
            print("\n现有 Detector:")
            for det in detectors:
                det_id = det.get('_id', 'N/A')
                det_name = det.get('name', 'N/A')
                det_enabled = det.get('enabled', False)
                det_type = det.get('detector_type', 'N/A')
                print(f"  - ID: {det_id}")
                print(f"    名称: {det_name}")
                print(f"    类型: {det_type}")
                print(f"    启用: {det_enabled}")
                print()
        else:
            print("[WARNING] 没有找到 detector")
    else:
        print(f"[X] 查询 detector 失败: {error}")
        return 1
    
    # 步骤3: 如果没有 detector，创建一个
    if not detectors:
        print("\n步骤 3: 创建 detector...")
        print("-" * 60)
        # 尝试不同的 detector_type
        detector_types = ["DNS", "NETWORK", "WINDOWS", "LINUX"]
        create_success = False
        create_resp = None
        create_error = None
        
        for dt in detector_types:
            print(f"\n  尝试 detector_type: {dt}...")
            create_success, create_resp, create_error = create_detector(client, detector_type=dt)
            if create_success:
                print(f"  [OK] 使用 detector_type={dt} 创建成功")
                break
            else:
                print(f"  [X] detector_type={dt} 失败: {create_error}")
        
        if not create_success:
            print(f"\n  [ERROR] 所有 detector_type 都失败")
            print(f"  [INFO] 建议先导入规则:")
            print(f"    uv run python import_sigma_rules.py --auto")
        if create_success:
            detector_id = create_resp.get('_id', 'N/A')
            print(f"[OK] Detector 创建成功")
            print(f"    Detector ID: {detector_id}")
            print(f"    响应: {json.dumps(create_resp, indent=2, ensure_ascii=False)}")
        else:
            print(f"[X] Detector 创建失败: {create_error}")
            return 1
    else:
        print("\n步骤 3: 跳过创建（已有 detector）")
    
    print("\n" + "=" * 60)
    print("检查完成")
    print("=" * 60)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
