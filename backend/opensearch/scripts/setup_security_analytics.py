#!/usr/bin/env python3
"""
自动配置 OpenSearch Security Analytics
创建默认的 detector 用于检测 ecs-events-* 索引
"""

import sys
from pathlib import Path
from datetime import datetime

# 添加 backend 目录到路径，以便从 opensearch 包导入
backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))

from opensearch import get_client
from opensearch.index import INDEX_PATTERNS, get_index_name
from opensearch import initialize_indices, index_exists


def check_security_analytics_available() -> bool:
    """检查 Security Analytics 插件是否可用"""
    client = get_client()
    try:
        # 尝试访问 Security Analytics API（使用 POST 方法搜索 detectors）
        response = client.transport.perform_request(
            'POST',
            '/_plugins/_security_analytics/detectors/_search',
            body={
                "size": 1
            }
        )
        print("[OK] Security Analytics 插件可用")
        return True
    except Exception as e:
        error_str = str(e)
        # 如果是 404，说明插件未安装
        if '404' in error_str or 'not found' in error_str.lower():
            print(f"[ERROR] Security Analytics 插件未安装: {e}")
            print("提示: 请确保 OpenSearch 已安装 security-analytics 插件")
        else:
            # 其他错误可能是 API 版本问题，但插件可能已安装
            print(f"[WARNING] Security Analytics API 调用失败: {e}")
            print("提示: 插件可能已安装，但 API 版本可能不同，继续尝试创建 detector...")
            return True  # 继续尝试，让创建 detector 来验证
        return False


def get_prepackaged_rules(detector_type: str = "dns") -> list:
    """
    获取可用的预打包规则
    
    重要：
    1. detector_type必须是Security Analytics支持的log type：dns, network, windows, linux等
    2. DNS和network是两个不同的log type！如果要用DNS规则，detector_type必须是"dns"
    3. 由于Security Analytics API的term查询可能不工作，使用match_all然后筛选
    """
    client = get_client()
    
    try:
        # 使用match_all查询所有规则，然后筛选（因为term查询可能不工作）
        # 这是官方API，但需要手动筛选预打包规则
        response = client.transport.perform_request(
            'POST',
            '/_plugins/_security_analytics/rules/_search',
            body={
                "query": {"match_all": {}},
                "size": 500  # 获取足够多的规则以便筛选
            }
        )
        
        hits = response.get('hits', {}).get('hits', [])
        rules = []
        
        for hit in hits:
            rule_id = hit.get('_id')
            rule_index = hit.get('_index', '')
            rule_source = hit.get('_source', {})
            rule_category = rule_source.get('category', '').lower()
            
            # 检查：必须是预打包规则（索引名包含pre-packaged）且category匹配detector_type
            is_prepackaged = 'pre-packaged' in rule_index.lower() or 'prepackaged' in rule_index.lower()
            category_matches = rule_category == detector_type.lower()
            
            if rule_id and is_prepackaged and category_matches:
                rules.append({"id": rule_id})
                if len(rules) >= 5:  # 只需要5个规则
                    break
        
        if rules:
            print(f"[OK] 找到 {len(rules)} 个预打包规则（detector_type: {detector_type}, category: {detector_type}）")
        else:
            print(f"[WARNING] 未找到预打包规则（detector_type: {detector_type}）")
        
        return rules
    except Exception as e:
        print(f"[WARNING] 获取预打包规则失败: {e}")
        import traceback
        traceback.print_exc()
        return []


def get_custom_rules(detector_type: str = "dns", max_rules: int = 20) -> dict:
    """获取已导入的自定义规则（我们导入的 Sigma 规则）"""
    client = get_client()
    
    # 根据 detector_type 映射到 category
    # OpenSearch Security Analytics 使用 category 而不是 logType
    category_map = {
        "network": ["dns", "network", "others_web"],
        "windows": ["windows"],
        "linux": ["linux"],
        "macos": ["macos"],
    }
    target_categories = category_map.get(detector_type.lower(), ["dns"])  # 默认使用 dns（我们有12个dns规则）
    
    try:
        prepackaged_rules = []
        custom_rules = []
        
        # 直接查询匹配category的规则，而不是获取所有规则再筛选
        for category in target_categories:
            if len(prepackaged_rules) + len(custom_rules) >= max_rules:
                break
                
            response = client.transport.perform_request(
                'POST',
                '/_plugins/_security_analytics/rules/_search',
                body={
                    "query": {
                        "term": {"category": category}
                    },
                    "size": max_rules
                }
            )
            hits = response.get('hits', {}).get('hits', [])
            
            for hit in hits:
                rule_id = hit.get('_id')
                rule_source = hit.get('_source', {})
                rule_index = hit.get('_index', '')
                
                if rule_id:
                    # 判断是预打包规则还是自定义规则
                    is_prepackaged = ('pre-packaged' in rule_index.lower() or 
                                     'prepackaged' in rule_index.lower() or
                                     rule_source.get('prePackaged', False))
                    
                    rule_obj = {"id": rule_id}
                    if is_prepackaged:
                        if len(prepackaged_rules) < max_rules:
                            prepackaged_rules.append(rule_obj)
                    else:
                        if len(custom_rules) < max_rules:
                            custom_rules.append(rule_obj)
                    
                    if len(prepackaged_rules) + len(custom_rules) >= max_rules:
                        break
        
        # 返回预打包规则和自定义规则
        return {"prepackaged": prepackaged_rules, "custom": custom_rules}
    except Exception as e:
        print(f"[WARNING] 获取自定义规则失败: {e}")
        import traceback
        traceback.print_exc()
        return {"prepackaged": [], "custom": []}


def create_default_detector() -> dict:
    """创建默认的 detector"""
    client = get_client()
    
    # 关键修复：detector_type必须是Security Analytics支持的log type
    # DNS和network是两个不同的log type！如果要用DNS规则，detector_type必须是"dns"
    # 支持的log type：dns, network, windows, linux, macos, ad_ldap, apache_access, cloudtrail, s3等
    
    # 优先尝试dns（因为我们有DNS规则）
    detector_types_to_try = ["dns", "network", "windows", "linux"]
    detector_type = None
    prepackaged_rules = []
    custom_rules = []
    
    for dt in detector_types_to_try:
        print(f"[INFO] 尝试 detector_type: {dt}")
        prepackaged = get_prepackaged_rules(dt)
        if prepackaged:
            detector_type = dt
            prepackaged_rules = prepackaged
            print(f"[OK] 找到 {len(prepackaged)} 个预打包规则")
            break
        else:
            custom_result = get_custom_rules(dt, max_rules=20)
            if isinstance(custom_result, dict):
                found_prepackaged = custom_result.get('prepackaged', [])
                found_custom = custom_result.get('custom', [])
                if found_prepackaged or found_custom:
                    detector_type = dt
                    prepackaged_rules = found_prepackaged
                    custom_rules = found_custom
                    total = len(found_prepackaged) + len(found_custom)
                    print(f"[OK] 找到 {len(found_prepackaged)} 个预打包规则和 {len(found_custom)} 个自定义规则（共 {total} 个）")
                    break
            elif custom_result:
                detector_type = dt
                custom_rules = custom_result
                print(f"[OK] 找到 {len(custom_rules)} 个自定义规则")
                break
    
    if not detector_type:
        detector_type = "dns"  # 默认使用 dns 类型（因为我们有DNS规则）
        print(f"[WARNING] 未找到任何规则，使用默认 detector_type: {detector_type}")
    
    # 如果上面没有找到规则，再尝试一次
    if not prepackaged_rules and not custom_rules:
        print("[INFO] 未找到预打包规则，尝试查找已导入的自定义规则...")
        rules_result = get_custom_rules(detector_type, max_rules=20)
        if isinstance(rules_result, dict):
            prepackaged_rules = rules_result.get('prepackaged', [])
            custom_rules = rules_result.get('custom', [])
            total_found = len(prepackaged_rules) + len(custom_rules)
            if total_found > 0:
                print(f"[OK] 找到 {len(prepackaged_rules)} 个预打包规则和 {len(custom_rules)} 个自定义规则")
            else:
                print("[WARNING] 未找到任何规则（预打包或自定义）")
        else:
            # 兼容旧版本返回列表的情况
            custom_rules = rules_result
            if custom_rules:
                print(f"[OK] 找到 {len(custom_rules)} 个自定义规则")
            else:
                print("[WARNING] 未找到任何规则")
    
    # 构建规则列表
    rules_to_use = prepackaged_rules if prepackaged_rules else custom_rules
    
    # 调试：打印规则信息
    print(f"[DEBUG] Detector类型: {detector_type}")
    print(f"[DEBUG] 预打包规则数量: {len(prepackaged_rules)}")
    print(f"[DEBUG] 自定义规则数量: {len(custom_rules)}")
    if prepackaged_rules:
        print(f"[DEBUG] 预打包规则示例: {prepackaged_rules[:2]}")
    if custom_rules:
        print(f"[DEBUG] 自定义规则示例: {custom_rules[:2]}")
    
    # 关键修复：某些detector_type（如dns, windows, linux）不支持索引模式
    # 必须使用具体的索引名称，而不是模式（如ecs-events-*）
    # 重要：索引名不能包含点号（.），会被doc-level monitor当作pattern拒绝
    # 使用今天的索引名称（格式：ecs-events-2026-01-13，连字符而非点号）
    today = datetime.now()
    specific_index = get_index_name(INDEX_PATTERNS["ECS_EVENTS"], today)
    
    # 确保索引存在（如果不存在则创建）
    if not index_exists(specific_index):
        print(f"[INFO] 索引不存在，正在创建: {specific_index}")
        initialize_indices()
        if not index_exists(specific_index):
            print(f"[ERROR] 无法创建索引: {specific_index}")
            return {
                "success": False,
                "message": f"索引不存在且无法创建: {specific_index}"
            }
        print(f"[OK] 索引已创建: {specific_index}")
    else:
        print(f"[OK] 索引已存在: {specific_index}")
    
    # 根据detector_type决定使用索引模式还是具体索引
    # network类型支持索引模式，dns/windows/linux等需要具体索引
    use_index_pattern = detector_type.lower() == "network"
    
    if use_index_pattern:
        indices = ["ecs-events-*"]
        print(f"[INFO] 使用索引模式: {indices[0]}")
    else:
        indices = [specific_index]
        print(f"[INFO] 使用具体索引: {specific_index} (detector_type={detector_type}不支持索引模式，且索引名不含点号)")
    
    detector_config = {
        "name": "ecs-events-detector",
        "description": "检测 ECS 事件中的可疑行为（主要通过API按需触发，schedule作为备用）",
        "detector_type": detector_type,  # 必须是Security Analytics支持的log type：dns, network, windows, linux等
        "enabled": True,
        # 设置较长的schedule间隔（24小时），主要依赖API手动触发
        # Security Analytics不允许schedule为null，所以设置为备用扫描
        "schedule": {
            "period": {
                "interval": 1,
                "unit": "MINUTES"  # 每1分钟扫描一次（用于测试monitor创建和findings生成）
            }
        },
        "inputs": [
            {
                "detector_input": {
                    "description": f"扫描 ECS 事件索引（detector_type: {detector_type}）",
                    "indices": indices,  # 根据detector_type使用模式或具体索引
                    "pre_packaged_rules": prepackaged_rules if prepackaged_rules else [],
                    "custom_rules": custom_rules if custom_rules else []  # 使用自定义规则（如果预打包规则为空）
                }
            }
        ],
        "triggers": []
    }
    
    # 调试：打印完整配置（只打印关键部分）
    print(f"[DEBUG] Detector配置摘要:")
    print(f"  - name: {detector_config['name']}")
    print(f"  - detector_type: {detector_config['detector_type']}")
    print(f"  - indices: {detector_config['inputs'][0]['detector_input']['indices']}")
    print(f"  - pre_packaged_rules: {len(detector_config['inputs'][0]['detector_input']['pre_packaged_rules'])} 个")
    print(f"  - custom_rules: {len(detector_config['inputs'][0]['detector_input']['custom_rules'])} 个")
    
    try:
        # 先检查是否已存在同名 detector（使用 POST 方法搜索）
        try:
            response = client.transport.perform_request(
                'POST',
                '/_plugins/_security_analytics/detectors/_search',
                body={
                    "size": 100
                }
            )
            detectors = response.get('hits', {}).get('hits', [])
            # 提取 detector 数据
            for hit in detectors:
                detector = hit.get('_source', {})
                if detector.get('name') == 'ecs-events-detector':
                    detector_id = hit.get('_id')
                    # 检查schedule间隔，如果太短（<24小时），更新为24小时
                    schedule = detector.get('schedule', {})
                    schedule_interval = schedule.get('period', {}).get('interval', 24)
                    schedule_unit = schedule.get('period', {}).get('unit', 'HOURS')
                    
                    # 如果schedule间隔小于24小时，更新为24小时（主要依赖API手动触发）
                    if schedule_unit == 'MINUTES' or (schedule_unit == 'HOURS' and schedule_interval < 24):
                        print(f"[INFO] Detector 'ecs-events-detector' 已存在，但schedule间隔较短（{schedule_interval} {schedule_unit}）")
                        print(f"[INFO] 更新schedule为24小时（主要使用API手动触发）...")
                        # 更新detector，设置较长的schedule
                        update_config = {
                            "name": detector_config["name"],
                            "description": detector_config["description"],
                            "detector_type": detector_config["detector_type"],
                            "enabled": detector_config["enabled"],
                            "schedule": detector_config["schedule"],  # 24小时
                            "inputs": detector_config["inputs"],
                            "triggers": detector_config["triggers"]
                        }
                        try:
                            update_resp = client.transport.perform_request(
                                'PUT',
                                f'/_plugins/_security_analytics/detectors/{detector_id}',
                                body=update_config
                            )
                            print(f"[OK] Detector已更新（schedule设置为24小时，主要使用API手动触发）")
                            return {"success": True, "detector_id": detector_id, "message": "已更新（按需触发模式）"}
                        except Exception as update_error:
                            print(f"[WARNING] 更新detector失败: {update_error}")
                            print(f"[INFO] 继续使用现有detector（可以通过API手动触发）")
                            return {"success": True, "detector_id": detector_id, "message": "已存在（可通过API手动触发）"}
                    else:
                        print(f"[INFO] Detector 'ecs-events-detector' 已存在 (ID: {detector_id})")
                        print(f"[INFO] Schedule: {schedule_interval} {schedule_unit}（可通过API手动触发）")
                        return {"success": True, "detector_id": detector_id, "message": "已存在（可通过API手动触发）"}
        except Exception as search_error:
            # 如果搜索失败，继续尝试创建（可能是 API 版本问题）
            print(f"[WARNING] 搜索现有 detectors 失败: {search_error}，继续创建新 detector...")
        
        # 如果没有规则，无法创建 detector
        if not rules_to_use:
            print("[INFO] 未找到任何规则，无法自动创建 detector")
            print("\n解决方案:")
            print("1. 手动在 OpenSearch Dashboards 中创建 detector 和规则")
            print("2. 或者导入 Sigma 规则后，再运行此脚本:")
            print("   uv run python opensearch/import_sigma_rules.py --auto")
            print("3. 参考文档: opensearch/docs/TEST_SECURITY_ANALYTICS.md（阶段 1：配置 Security Analytics）")
            return {
                "success": False,
                "message": "需要至少一个规则才能创建 detector。请手动配置或导入规则。"
            }
        
        # 创建新的 detector
        # 调试：打印完整配置
        print(f"\n[DEBUG] 完整Detector配置:")
        import json
        print(json.dumps(detector_config, indent=2, ensure_ascii=False, default=str)[:1000])
        
        response = client.transport.perform_request(
            'POST',
            '/_plugins/_security_analytics/detectors',
            body=detector_config
        )
        
        detector_id = response.get('_id')
        print(f"[OK] Detector 创建成功 (ID: {detector_id})")
        if prepackaged_rules:
            print(f"     使用了 {len(prepackaged_rules)} 个预打包规则")
        elif custom_rules:
            print(f"     使用了 {len(custom_rules)} 个自定义规则")
        return {
            "success": True,
            "detector_id": detector_id,
            "message": "创建成功"
        }
        
    except Exception as e:
        error_str = str(e)
        if 'no compatible rules' in error_str.lower() or 'no rules' in error_str.lower():
            print(f"[ERROR] 创建 detector 失败: 需要至少一个规则")
            print("\n解决方案:")
            print("1. 手动在 OpenSearch Dashboards 中创建 detector 和规则")
            print("2. 或者导入 Sigma 规则后，再运行此脚本")
            print("3. 参考文档: opensearch/docs/TEST_SECURITY_ANALYTICS.md（阶段 1：配置 Security Analytics）")
        else:
            print(f"[ERROR] 创建 detector 失败: {e}")
        return {
            "success": False,
            "message": str(e)
        }


def list_detectors() -> list:
    """列出所有 detectors"""
    client = get_client()
    try:
        response = client.transport.perform_request(
            'POST',
            '/_plugins/_security_analytics/detectors/_search',
            body={
                "size": 100
            }
        )
        hits = response.get('hits', {}).get('hits', [])
        # 提取 detector 数据
        detectors = []
        for hit in hits:
            detector = hit.get('_source', {})
            detector['_id'] = hit.get('_id')  # 添加 ID
            detectors.append(detector)
        return detectors
    except Exception as e:
        print(f"[ERROR] 获取 detectors 列表失败: {e}")
        return []


def main():
    """主函数"""
    print("=" * 80)
    print("OpenSearch Security Analytics 配置工具")
    print("=" * 80)
    
    # 1. 检查插件是否可用
    print("\n[1/3] 检查 Security Analytics 插件...")
    if not check_security_analytics_available():
        print("\n配置失败：Security Analytics 插件不可用")
        print("请参考 docs/TEST_SECURITY_ANALYTICS.md（阶段 1：配置 Security Analytics）进行手动配置")
        return
    
    # 2. 创建默认 detector
    print("\n[2/3] 创建默认 detector...")
    result = create_default_detector()
    if not result.get("success"):
        print(f"\n配置失败: {result.get('message')}")
        return
    
    # 3. 列出所有 detectors
    print("\n[3/3] 当前所有 detectors:")
    detectors = list_detectors()
    if detectors:
        for detector in detectors:
            status = "启用" if detector.get('enabled') else "禁用"
            detector_id = detector.get('_id') or detector.get('id', 'unknown')
            print(f"  - {detector.get('name')} (ID: {detector_id}, 状态: {status})")
    else:
        print("  没有找到 detectors")
    
    print("\n" + "=" * 80)
    print("配置完成！")
    print("=" * 80)
    print("\nSecurity Analytics 现在会每1分钟自动扫描 ecs-events-* 索引")
    print("检测结果可以通过 run_security_analytics() 函数读取")


if __name__ == "__main__":
    main()
