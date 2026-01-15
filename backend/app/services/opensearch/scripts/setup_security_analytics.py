#!/usr/bin/env python3
"""
自动配置 OpenSearch Security Analytics
创建默认的 detector 用于检测 ecs-events-* 索引
"""

import sys
from pathlib import Path
from datetime import datetime

# 添加 backend 目录到路径，以便从 opensearch 包和 app 模块导入
# 脚本在 backend/app/services/opensearch/scripts/，需要回到 backend/ 才能导入 app 和 opensearch 包
backend_dir = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(backend_dir))

# 使用完整路径导入，避免触发 opensearch/__init__.py 的导入
from app.services.opensearch.internal import get_client, INDEX_PATTERNS, get_index_name, initialize_indices, index_exists


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


def get_custom_rules(detector_type: str = "dns", max_rules: int = 200) -> dict:
    """获取已导入的自定义规则（我们导入的 Sigma 规则）"""
    client = get_client()
    
    # 根据 detector_type 映射到 category
    # OpenSearch Security Analytics 使用 category 而不是 logType
    category_map = {
        "network": ["dns", "network", "others_web"],
        # "windows": ["windows"],  # 不需要windows规则
        "linux": ["linux"],
        "macos": ["macos"],
        "dns": ["dns", "network"],  # dns类型也可以使用network规则
    }
    target_categories = category_map.get(detector_type.lower(), ["dns", "network", "linux"])  # 默认尝试多个category（不包含windows）
    
    try:
        prepackaged_rules = []
        custom_rules = []
        seen_ids = set()  # 用于去重
        
        # 方法1：直接查询所有规则，然后按category筛选（更可靠）
        try:
            # 先查询所有规则索引
            try:
                indices_response = client.indices.get_alias(index="*rules*")
                print(f"[DEBUG] 找到规则相关索引: {list(indices_response.keys())[:5]}")
            except Exception:
                pass
            
            all_rules_response = client.transport.perform_request(
                'POST',
                '/_plugins/_security_analytics/rules/_search',
                body={
                    "query": {"match_all": {}},
                    "size": 5000  # 增加查询数量，确保包含所有规则（包括您导入的1500个规则）
                }
            )
            all_hits = all_rules_response.get('hits', {}).get('hits', [])
            print(f"[DEBUG] 查询到总共 {len(all_hits)} 个规则，开始筛选...")
            
            # 统计自定义规则索引中的规则
            custom_index_rules = [h for h in all_hits if '.opensearch-sap-custom-rules-config' in h.get('_index', '')]
            print(f"[DEBUG] 自定义规则索引中的规则数量: {len(custom_index_rules)}")
            if custom_index_rules:
                # 检查前几个自定义规则的字段
                sample_rule = custom_index_rules[0].get('_source', {})
                print(f"[DEBUG] 自定义规则示例字段: {list(sample_rule.keys())[:10]}")
                print(f"[DEBUG] 自定义规则示例 - category: {sample_rule.get('category')}, logType: {sample_rule.get('logType')}")
            
            # 按category筛选
            for hit in all_hits:
                if len(prepackaged_rules) + len(custom_rules) >= max_rules:
                    break
                    
                rule_id = hit.get('_id')
                if not rule_id or rule_id in seen_ids:
                    continue
                
                rule_source = hit.get('_source', {})
                rule_category = rule_source.get('category', '').lower()
                
                # 检查是否匹配目标category
                if rule_category not in [c.lower() for c in target_categories]:
                    continue
                
                rule_index = hit.get('_index', '')
                
                # 判断是预打包规则还是自定义规则
                # 关键：我们导入的规则都有logType字段，这是最可靠的判断依据
                has_logtype = rule_source.get('logType') is not None
                rule_logtype = rule_source.get('logType', '').lower() if has_logtype else ''
                
                # 预打包规则的索引名通常包含 "pre-packaged" 或 "prepackaged"
                # 但如果规则有logType字段，说明是我们导入的规则（即使存储在预打包索引中）
                is_prepackaged = (
                    ('pre-packaged' in rule_index.lower() or 
                     'prepackaged' in rule_index.lower() or
                     rule_source.get('prePackaged', False) or
                     rule_source.get('pre_packaged', False))
                    and not has_logtype  # 如果有logType字段，不是预打包规则
                )
                
                # 自定义规则判断：
                # 1. 索引名包含 "custom-rules"（最直接的判断）
                # 2. 有logType字段（我们导入的规则都有这个字段）
                # 3. 或者索引名不包含pre-packaged/prepackaged
                is_custom = (
                    'custom-rules' in rule_index.lower() or  # 自定义规则索引
                    has_logtype or  # 有logType字段，说明是我们导入的规则
                    ('security-analytics-rules' in rule_index.lower()) or
                    ('rules' in rule_index.lower() and 'pre-packaged' not in rule_index.lower() and 'prepackaged' not in rule_index.lower())
                )
                
                rule_obj = {"id": rule_id}
                seen_ids.add(rule_id)
                
                if is_prepackaged:
                    if len(prepackaged_rules) < max_rules:
                        prepackaged_rules.append(rule_obj)
                elif is_custom:
                    if len(custom_rules) < max_rules:
                        custom_rules.append(rule_obj)
                # 如果无法判断，默认作为自定义规则（因为用户导入的规则应该都是自定义的）
                else:
                    if len(custom_rules) < max_rules:
                        custom_rules.append(rule_obj)
            
            print(f"[DEBUG] 筛选后: 预打包 {len(prepackaged_rules)} 个, 自定义 {len(custom_rules)} 个")
        except Exception as e:
            print(f"[WARNING] 查询所有规则失败，尝试按category查询: {e}")
            # 方法2：如果方法1失败，回退到按category查询
            for category in target_categories:
                if len(prepackaged_rules) + len(custom_rules) >= max_rules:
                    break
                    
                try:
                    # 先尝试term查询（精确匹配），如果失败则尝试match查询
                    try:
                        response = client.transport.perform_request(
                            'POST',
                            '/_plugins/_security_analytics/rules/_search',
                            body={
                                "query": {
                                    "term": {"category": category}
                                },
                                "size": max_rules * 2
                            }
                        )
                    except Exception:
                        response = client.transport.perform_request(
                            'POST',
                            '/_plugins/_security_analytics/rules/_search',
                            body={
                                "query": {
                                    "match": {"category": category}
                                },
                                "size": max_rules * 2
                            }
                        )
                    hits = response.get('hits', {}).get('hits', [])
                    print(f"[DEBUG] category '{category}' 查询到 {len(hits)} 个规则")
                    
                    for hit in hits:
                        rule_id = hit.get('_id')
                        if not rule_id or rule_id in seen_ids:
                            continue
                        
                        rule_source = hit.get('_source', {})
                        rule_index = hit.get('_index', '')
                        
                        # 判断是预打包规则还是自定义规则
                        # 预打包规则的索引名通常包含 "pre-packaged" 或 "prepackaged"
                        # 自定义规则（我们导入的）的索引名通常是 "security-analytics-rules" 或其他
                        is_prepackaged = (
                            'pre-packaged' in rule_index.lower() or 
                            'prepackaged' in rule_index.lower() or
                            rule_source.get('prePackaged', False) or
                            rule_source.get('pre_packaged', False)
                        )
                        
                        # 如果索引名包含 "security-analytics-rules" 且不是预打包，则认为是自定义规则
                        # 或者如果规则有我们导入时添加的特殊标记
                        is_custom = (
                            not is_prepackaged and (
                                'security-analytics-rules' in rule_index.lower() or
                                rule_source.get('logType') is not None  # 我们导入的规则有logType字段
                            )
                        )
                        
                        rule_obj = {"id": rule_id}
                        seen_ids.add(rule_id)
                        
                        if is_prepackaged:
                            if len(prepackaged_rules) < max_rules:
                                prepackaged_rules.append(rule_obj)
                        elif is_custom:
                            if len(custom_rules) < max_rules:
                                custom_rules.append(rule_obj)
                        # 如果无法判断，默认作为自定义规则（因为用户导入的规则应该都是自定义的）
                        else:
                            if len(custom_rules) < max_rules:
                                custom_rules.append(rule_obj)
                        
                        if len(prepackaged_rules) + len(custom_rules) >= max_rules:
                            break
                except Exception as e:
                    # 如果某个category查询失败，继续下一个
                    print(f"[DEBUG] 查询category '{category}' 失败: {e}")
                    continue
        
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
    # 注意：不包含windows，因为不需要windows规则
    detector_types_to_try = ["dns", "network", "linux"]
    detector_type = None
    prepackaged_rules = []
    custom_rules = []
    
    # 收集所有detector_type的规则信息，然后选择最好的
    candidates = []
    
    for dt in detector_types_to_try:
        print(f"[INFO] 尝试 detector_type: {dt}")
        prepackaged = get_prepackaged_rules(dt)
        custom_result = get_custom_rules(dt, max_rules=500)  # 增加max_rules以获取更多规则
        
        # 合并预打包规则和自定义规则
        found_prepackaged = prepackaged if prepackaged else []
        found_custom = []
        
        if isinstance(custom_result, dict):
            found_prepackaged.extend(custom_result.get('prepackaged', []))
            found_custom = custom_result.get('custom', [])
        elif custom_result:
            found_custom = custom_result if isinstance(custom_result, list) else []
        
        # 去重（避免重复添加相同的规则）
        seen_ids = set()
        unique_prepackaged = []
        for rule in found_prepackaged:
            rule_id = rule.get('id') if isinstance(rule, dict) else rule
            if rule_id and rule_id not in seen_ids:
                seen_ids.add(rule_id)
                unique_prepackaged.append(rule if isinstance(rule, dict) else {"id": rule})
        
        unique_custom = []
        for rule in found_custom:
            rule_id = rule.get('id') if isinstance(rule, dict) else rule
            if rule_id and rule_id not in seen_ids:
                seen_ids.add(rule_id)
                unique_custom.append(rule if isinstance(rule, dict) else {"id": rule})
        
        total = len(unique_prepackaged) + len(unique_custom)
        if total > 0:
            candidates.append({
                "detector_type": dt,
                "prepackaged": unique_prepackaged,
                "custom": unique_custom,
                "total": total,
                "custom_count": len(unique_custom)
            })
            print(f"[OK] 找到 {len(unique_prepackaged)} 个预打包规则和 {len(unique_custom)} 个自定义规则（共 {total} 个）")
    
    # 选择最佳candidate：优先选择自定义规则最多的，其次选择总数最多的
    if candidates:
        # 按自定义规则数量降序排序，如果相同则按总数排序
        candidates.sort(key=lambda x: (x["custom_count"], x["total"]), reverse=True)
        best = candidates[0]
        detector_type = best["detector_type"]
        prepackaged_rules = best["prepackaged"]
        custom_rules = best["custom"]
        print(f"\n[INFO] 选择 detector_type: {detector_type} (自定义规则: {best['custom_count']} 个, 总计: {best['total']} 个)")
    
    if not detector_type:
        detector_type = "dns"  # 默认使用 dns 类型（因为我们有DNS规则）
        print(f"[WARNING] 未找到任何规则，使用默认 detector_type: {detector_type}")
    
    # 如果上面没有找到规则，再尝试一次
    if not prepackaged_rules and not custom_rules:
        print("[INFO] 未找到预打包规则，尝试查找已导入的自定义规则...")
        rules_result = get_custom_rules(detector_type, max_rules=500)  # 增加规则数量
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


def create_multiple_detectors() -> dict:
    """创建多个detector，每个对应一种类型，以覆盖所有规则"""
    print("\n" + "=" * 80)
    print("创建多个 Detector（覆盖所有规则类型）")
    print("=" * 80)
    
    # 注意：不包含windows，因为不需要windows规则
    detector_types = ["dns", "network", "linux"]
    created_detectors = []
    failed_detectors = []
    
    for dt in detector_types:
        print(f"\n[创建 {dt} detector]")
        print("-" * 80)
        
        # 为每种类型创建detector
        result = create_detector_for_type(dt)
        if result.get("success"):
            detector_id = result.get("detector_id")
            detector_name = result.get("detector_name", f"ecs-events-detector-{dt}")
            rules_count = result.get("rules_count", 0)
            created_detectors.append({
                "type": dt,
                "id": detector_id,
                "name": detector_name,
                "rules": rules_count
            })
            print(f"✅ {dt} detector 创建成功 (ID: {detector_id}, 规则: {rules_count} 个)")
        else:
            failed_detectors.append({
                "type": dt,
                "reason": result.get("message", "未知错误")
            })
            print(f"❌ {dt} detector 创建失败: {result.get('message')}")
    
    return {
        "success": len(created_detectors) > 0,
        "created": created_detectors,
        "failed": failed_detectors
    }


def create_or_update_detector_from_rules(rule_ids: list, detector_type: str = None, detector_name: str = "ecs-events-detector") -> dict:
    """
    根据规则ID列表创建或更新detector
    
    Args:
        rule_ids: 规则ID列表
        detector_type: detector类型（如果为None，会自动检测）
        detector_name: detector名称
    
    Returns:
        包含success、detector_id等信息的字典
    """
    client = get_client()
    
    if not rule_ids:
        return {
            "success": False,
            "message": "没有规则，无法创建detector"
        }
    
    # 限制规则数量（避免detector配置过大）
    rules_to_use = rule_ids[:100]  # 增加到100个规则
    
    # 如果没有指定detector_type，尝试从规则中推断
    if detector_type is None:
        # 查询规则以确定类型
        try:
            response = client.transport.perform_request(
                'POST',
                '/_plugins/_security_analytics/rules/_search',
                body={
                    "query": {
                        "ids": {"values": rules_to_use[:10]}  # 只查询前10个规则
                    },
                    "size": 10
                }
            )
            hits = response.get('hits', {}).get('hits', [])
            if hits:
                # 统计最常见的category
                categories = {}
                for hit in hits:
                    category = hit.get('_source', {}).get('category', '').lower()
                    if category:
                        categories[category] = categories.get(category, 0) + 1
                
                if categories:
                    # 选择最常见的category作为detector_type
                    detector_type = max(categories.items(), key=lambda x: x[1])[0]
                    print(f"[INFO] 从规则推断detector_type: {detector_type}")
        except Exception as e:
            print(f"[WARNING] 无法推断detector_type: {e}")
        
        # 如果推断失败，使用默认值
        if not detector_type:
            detector_type = "dns"  # 默认使用dns类型
    
    # 准备索引
    today = datetime.now()
    specific_index = get_index_name(INDEX_PATTERNS["ECS_EVENTS"], today)
    
    # 确保索引存在
    if not index_exists(specific_index):
        print(f"[INFO] 索引不存在，正在创建: {specific_index}")
        initialize_indices()
    
    # 根据detector_type决定使用索引模式还是具体索引
    use_index_pattern = detector_type.lower() == "network"
    
    if use_index_pattern:
        indices = ["ecs-events-*"]
    else:
        indices = [specific_index]
    
    detector_config = {
        "name": detector_name,
        "description": f"检测 ECS 事件中的可疑行为（自动创建，使用 {len(rules_to_use)} 个规则）",
        "detector_type": detector_type,
        "enabled": True,
        "schedule": {
            "period": {
                "interval": 1,
                "unit": "MINUTES"
            }
        },
        "inputs": [
            {
                "detector_input": {
                    "description": f"扫描 ECS 事件索引（detector_type: {detector_type}）",
                    "indices": indices,
                    "custom_rules": [{"id": rule_id} for rule_id in rules_to_use]
                }
            }
        ],
        "triggers": []
    }
    
    try:
        # 检查是否已存在
        response = client.transport.perform_request(
            'POST',
            '/_plugins/_security_analytics/detectors/_search',
            body={
                "query": {
                    "match": {"name": detector_name}
                },
                "size": 10
            }
        )
        hits = response.get('hits', {}).get('hits', [])
        if hits:
            detector_id = hits[0].get('_id')
            print(f"[INFO] Detector 已存在 (ID: {detector_id})，尝试更新...")
            # 更新现有detector
            update_response = client.transport.perform_request(
                'PUT',
                f'/_plugins/_security_analytics/detectors/{detector_id}',
                body=detector_config
            )
            print(f"[OK] Detector 更新成功")
            return {
                "success": True,
                "detector_id": detector_id,
                "detector_name": detector_name,
                "detector_type": detector_type,
                "rules_count": len(rules_to_use),
                "message": "更新成功"
            }
        
        # 创建新detector
        response = client.transport.perform_request(
            'POST',
            '/_plugins/_security_analytics/detectors',
            body=detector_config
        )
        detector_id = response.get('_id')
        print(f"[OK] Detector 创建成功 (ID: {detector_id})")
        print(f"     使用了 {len(rules_to_use)} 个规则")
        return {
            "success": True,
            "detector_id": detector_id,
            "detector_name": detector_name,
            "detector_type": detector_type,
            "rules_count": len(rules_to_use),
            "message": "创建成功"
        }
        
    except Exception as e:
        error_str = str(e)
        print(f"[ERROR] 创建/更新detector失败: {e}")
        return {
            "success": False,
            "message": str(e)
        }


def create_detector_for_type(detector_type: str) -> dict:
    """为特定类型创建detector"""
    client = get_client()
    
    print(f"[INFO] 查找 {detector_type} 类型的规则...")
    
    # 先查询所有规则，看看实际的category分布（调试用）
    try:
        all_rules_response = client.transport.perform_request(
            'POST',
            '/_plugins/_security_analytics/rules/_search',
            body={
                "query": {"match_all": {}},
                "size": 2000  # 增加查询数量
            }
        )
        all_hits = all_rules_response.get('hits', {}).get('hits', [])
        category_stats = {}
        custom_category_stats = {}  # 单独统计自定义规则
        for hit in all_hits:
            rule_source = hit.get('_source', {})
            category = rule_source.get('category', 'unknown')
            rule_index = hit.get('_index', '')
            is_prepackaged = (
                'pre-packaged' in rule_index.lower() or 
                'prepackaged' in rule_index.lower() or
                rule_source.get('prePackaged', False)
            )
            is_custom = not is_prepackaged and (
                'security-analytics-rules' in rule_index.lower() or
                rule_source.get('logType') is not None
            )
            
            key = f"{category} ({'预打包' if is_prepackaged else '自定义' if is_custom else '未知'})"
            category_stats[key] = category_stats.get(key, 0) + 1
            
            # 单独统计自定义规则（不包含windows）
            if is_custom or (not is_prepackaged and category in ['network', 'linux', 'dns']):
                custom_category_stats[category] = custom_category_stats.get(category, 0) + 1
        
        print(f"[DEBUG] 所有规则category统计（前10个）:")
        for cat, count in sorted(category_stats.items(), key=lambda x: -x[1])[:10]:
            print(f"  - {cat}: {count} 个")
        
        if custom_category_stats:
            print(f"[DEBUG] 自定义规则category统计:")
            for cat, count in sorted(custom_category_stats.items(), key=lambda x: -x[1]):
                print(f"  - {cat}: {count} 个")
        
        # 显示索引名统计（帮助诊断）
        index_stats = {}
        for hit in all_hits[:100]:  # 只检查前100个
            rule_index = hit.get('_index', 'unknown')
            index_stats[rule_index] = index_stats.get(rule_index, 0) + 1
        
        print(f"[DEBUG] 规则索引名统计（前5个）:")
        for idx, count in sorted(index_stats.items(), key=lambda x: -x[1])[:5]:
            print(f"  - {idx}: {count} 个")
    except Exception as e:
        print(f"[DEBUG] 查询所有规则失败: {e}")
    
    # 获取该类型的规则（包括预打包和自定义）
    prepackaged = get_prepackaged_rules(detector_type)
    custom_result = get_custom_rules(detector_type, max_rules=500)  # 增加规则数量（最多500个）
    
    # 合并规则
    prepackaged_rules = prepackaged if prepackaged else []
    custom_rules = []
    
    if isinstance(custom_result, dict):
        # 合并预打包规则（避免重复）
        for rule in custom_result.get('prepackaged', []):
            rule_id = rule.get('id') if isinstance(rule, dict) else rule
            # 检查是否已经在prepackaged列表中
            if not any(r.get('id') == rule_id if isinstance(r, dict) else r == rule_id 
                      for r in prepackaged_rules):
                prepackaged_rules.append(rule if isinstance(rule, dict) else {"id": rule})
        custom_rules = custom_result.get('custom', [])
    
    # 去重
    seen_ids = set()
    unique_prepackaged = []
    for rule in prepackaged_rules:
        rule_id = rule.get('id') if isinstance(rule, dict) else rule
        if rule_id and rule_id not in seen_ids:
            seen_ids.add(rule_id)
            unique_prepackaged.append(rule if isinstance(rule, dict) else {"id": rule})
    
    unique_custom = []
    for rule in custom_rules:
        rule_id = rule.get('id') if isinstance(rule, dict) else rule
        if rule_id and rule_id not in seen_ids:
            seen_ids.add(rule_id)
            unique_custom.append(rule if isinstance(rule, dict) else {"id": rule})
    
    print(f"[DEBUG] {detector_type} 类型规则统计:")
    print(f"  - 预打包规则: {len(unique_prepackaged)} 个")
    print(f"  - 自定义规则: {len(unique_custom)} 个")
    print(f"  - 总计: {len(unique_prepackaged) + len(unique_custom)} 个")
    
    # 如果没有规则，跳过
    if not unique_prepackaged and not unique_custom:
        return {
            "success": False,
            "message": f"未找到 {detector_type} 类型的规则（预打包或自定义）"
        }
    
    # 准备索引
    from datetime import datetime
    today = datetime.now()
    specific_index = get_index_name(INDEX_PATTERNS["ECS_EVENTS"], today)
    
    if not index_exists(specific_index):
        initialize_indices()
    
    # 根据detector_type决定使用索引模式还是具体索引
    # 注意：doc-level monitor不支持索引模式，所以所有类型都使用具体索引
    # 之前的代码中network类型使用索引模式会导致错误
    use_index_pattern = False  # 禁用索引模式，所有类型都使用具体索引
    indices = [specific_index]  # 统一使用具体索引
    
    detector_config = {
        "name": f"ecs-events-detector-{detector_type}",
        "description": f"检测 ECS 事件中的 {detector_type} 类型可疑行为",
        "detector_type": detector_type,
        "enabled": True,
        "schedule": {
            "period": {
                "interval": 1,
                "unit": "MINUTES"
            }
        },
        "inputs": [
            {
                "detector_input": {
                    "description": f"扫描 ECS 事件索引（detector_type: {detector_type}）",
                    "indices": indices,
                    "pre_packaged_rules": unique_prepackaged[:100],  # 限制数量避免过大
                    "custom_rules": unique_custom[:100]
                }
            }
        ],
        "triggers": []
    }
    
    try:
        # 检查是否已存在
        response = client.transport.perform_request(
            'POST',
            '/_plugins/_security_analytics/detectors/_search',
            body={
                "query": {
                    "match": {"name": detector_config["name"]}
                },
                "size": 10
            }
        )
        hits = response.get('hits', {}).get('hits', [])
        if hits:
            detector_id = hits[0].get('_id')
            print(f"[INFO] Detector 已存在 (ID: {detector_id})，跳过创建")
            return {
                "success": True,
                "detector_id": detector_id,
                "detector_name": detector_config["name"],
                "rules_count": len(unique_prepackaged) + len(unique_custom)
            }
        
        # 创建新detector
        response = client.transport.perform_request(
            'POST',
            '/_plugins/_security_analytics/detectors',
            body=detector_config
        )
        detector_id = response.get('_id')
        
        return {
            "success": True,
            "detector_id": detector_id,
            "detector_name": detector_config["name"],
            "rules_count": len(unique_prepackaged) + len(unique_custom)
        }
    except Exception as e:
        return {
            "success": False,
            "message": str(e)
        }


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description="OpenSearch Security Analytics 配置工具")
    parser.add_argument(
        "--multiple",
        action="store_true",
        help="创建多个detector（每个类型一个），覆盖所有规则"
    )
    args = parser.parse_args()
    
    print("=" * 80)
    print("OpenSearch Security Analytics 配置工具")
    print("=" * 80)
    
    # 1. 检查插件是否可用
    print("\n[1/3] 检查 Security Analytics 插件...")
    if not check_security_analytics_available():
        print("\n配置失败：Security Analytics 插件不可用")
        print("请参考 docs/TEST_SECURITY_ANALYTICS.md（阶段 1：配置 Security Analytics）进行手动配置")
        return
    
    # 2. 创建detector(s)
    if args.multiple:
        print("\n[2/3] 创建多个 detector（覆盖所有类型）...")
        result = create_multiple_detectors()
        if not result.get("success"):
            print("\n配置失败: 没有成功创建任何detector")
            return
    else:
        print("\n[2/3] 创建默认 detector...")
        result = create_default_detector()
        if not result.get("success"):
            print(f"\n配置失败: {result.get('message')}")
            print("\n提示: 可以使用 --multiple 参数创建多个detector（每个类型一个）")
            return
    
    # 3. 列出所有 detectors
    print("\n[3/3] 当前所有 detectors:")
    detectors = list_detectors()
    if detectors:
        for detector in detectors:
            status = "启用" if detector.get('enabled') else "禁用"
            detector_id = detector.get('_id') or detector.get('id', 'unknown')
            detector_type = detector.get('detector_type', 'unknown')
            print(f"  - {detector.get('name')} (ID: {detector_id}, 类型: {detector_type}, 状态: {status})")
    else:
        print("  没有找到 detectors")
    
    print("\n" + "=" * 80)
    print("配置完成！")
    print("=" * 80)
    if args.multiple:
        print("\n已创建多个detector，覆盖所有规则类型")
        print("每个detector会扫描相同的索引，但使用不同类型的规则")
    else:
        print("\nSecurity Analytics 现在会每1分钟自动扫描 ecs-events-* 索引")
        print("检测结果可以通过 run_security_analytics() 函数读取")
        print("\n提示: 可以使用 --multiple 参数创建多个detector（每个类型一个）")


if __name__ == "__main__":
    main()
