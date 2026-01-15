#!/usr/bin/env python3
"""
创建针对 Findings 的 Correlation Rules

这些规则在 raw-findings-* 索引中查询 findings，而不是在 ecs-events-* 中查询 events。
这样 dashboard 才能显示 correlations。

功能：
1. 创建多个简单的 correlation rules，针对 findings
2. 确保能找到一些 correlations 供 dashboard 显示
"""

import sys
from pathlib import Path
from datetime import datetime, timezone

backend_dir = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(backend_dir))

from app.services.opensearch.internal import get_client, get_index_name, INDEX_PATTERNS

# Correlation Rules API
CORRELATION_RULES_API = "/_plugins/_security_analytics/correlation/rules"
CORRELATION_TIME_WINDOW_MINUTES = 30


def create_findings_correlation_rule(
    rule_name: str,
    description: str,
    queries: list,
    tags: list = None,
    time_window_minutes: int = CORRELATION_TIME_WINDOW_MINUTES
) -> dict:
    """
    创建针对 findings 的 correlation rule
    
    参数：
    - rule_name: 规则名称
    - description: 规则描述
    - queries: 查询列表，每个查询应该针对 raw-findings-* 索引
    - tags: 标签列表
    - time_window_minutes: 时间窗口（分钟）
    
    返回: {
        "success": bool,
        "rule_id": str,
        "message": str
    }
    """
    client = get_client()
    
    # 使用 raw-findings-* 索引模式（dashboard 期望在这里查找 correlations）
    findings_index_pattern = f"{INDEX_PATTERNS['RAW_FINDINGS']}-*"
    
    # 构建 correlate 查询
    correlate_queries = []
    for i, query in enumerate(queries):
        correlate_queries.append({
            "index": findings_index_pattern,
            "category": query.get("category", "process"),  # 默认使用 process
            "query": query.get("query_string", "")
        })
    
    correlation_rule = {
        "name": rule_name,
        "description": description,
        "tags": tags or [],
        "correlate": correlate_queries
    }
    
    try:
        # 检查是否已存在同名规则
        rule_id = None
        try:
            search_response = client.transport.perform_request(
                'POST',
                f"{CORRELATION_RULES_API}/_search",
                body={
                    "query": {
                        "match": {
                            "name": rule_name
                        }
                    },
                    "size": 10
                }
            )
            
            if isinstance(search_response, dict):
                hits = search_response.get("hits", {}).get("hits", [])
                for hit in hits:
                    rule_source = hit.get("_source", {})
                    if rule_source.get("name") == rule_name:
                        rule_id = hit.get("_id")
                        print(f"[INFO] 找到已存在的规则 (ID: {rule_id})，将更新")
                        break
        except Exception as e:
            print(f"[WARNING] 查询现有规则失败: {e}")
        
        # 创建或更新规则
        if rule_id:
            try:
                client.transport.perform_request(
                    'PUT',
                    f"{CORRELATION_RULES_API}/{rule_id}",
                    body=correlation_rule
                )
                print(f"[OK] 规则更新成功: {rule_name} (ID: {rule_id})")
                return {"success": True, "rule_id": rule_id, "message": "更新成功"}
            except Exception as e:
                print(f"[WARNING] 更新规则失败: {e}，尝试创建新规则")
        
        # 创建新规则
        create_response = client.transport.perform_request(
            'POST',
            CORRELATION_RULES_API,
            body=correlation_rule
        )
        
        rule_id = None
        if isinstance(create_response, dict):
            rule_id = create_response.get('_id') or create_response.get('id') or create_response.get('rule_id')
        elif isinstance(create_response, str):
            rule_id = create_response
        
        if rule_id:
            print(f"[OK] 规则创建成功: {rule_name} (ID: {rule_id})")
            return {"success": True, "rule_id": rule_id, "message": "创建成功"}
        else:
            print(f"[WARNING] 创建成功但无法提取 rule_id: {create_response}")
            return {"success": True, "rule_id": None, "message": "创建成功（但无法获取 rule_id）"}
            
    except Exception as e:
        error_msg = str(e)
        print(f"[ERROR] 创建规则失败 {rule_name}: {error_msg}")
        import traceback
        traceback.print_exc()
        return {"success": False, "rule_id": None, "message": f"创建失败: {error_msg}"}


def create_all_findings_correlation_rules():
    """创建所有针对 findings 的 correlation rules"""
    
    rules_to_create = [
        {
            "name": "Multiple High Severity Findings",
            "description": "检测同一主机上短时间内出现多个高严重性findings",
            "queries": [
                {
                    "category": "process",
                    "query_string": "event.severity:>=50 AND _exists_:host.name"
                },
                {
                    "category": "process",
                    "query_string": "event.severity:>=50 AND _exists_:host.name"
                }
            ],
            "tags": ["attack.execution", "attack.t1059"]
        },
        {
            "name": "Any Two Findings Same Host",
            "description": "检测同一主机上的任意两个findings（最简单的关联规则）",
            "queries": [
                {
                    "category": "process",
                    "query_string": "_exists_:host.name AND _exists_:event.severity"
                },
                {
                    "category": "network",
                    "query_string": "_exists_:host.name AND _exists_:event.severity"
                }
            ],
            "tags": ["simple", "attack.detection"]
        },
        {
            "name": "Any Findings with Threat Tags",
            "description": "检测带有ATT&CK标签的findings关联",
            "queries": [
                {
                    "category": "process",
                    "query_string": "_exists_:threat.tactic OR _exists_:threat.technique"
                },
                {
                    "category": "network",
                    "query_string": "_exists_:threat.tactic OR _exists_:threat.technique"
                }
            ],
            "tags": ["threat", "mitre-attack"]
        },
        {
            "name": "Network Scan Followed by Exploitation",
            "description": "检测端口扫描后跟进的利用行为",
            "queries": [
                {
                    "category": "network",
                    "query_string": "(tags:attack.discovery OR tags:attack.t1046 OR event.category:network) AND event.severity:>=50"
                },
                {
                    "category": "process",
                    "query_string": "(tags:attack.execution OR tags:attack.t1059 OR event.category:process) AND event.severity:>=50"
                }
            ],
            "tags": ["attack.discovery", "attack.execution", "attack.t1046", "attack.t1059"]
        },
        {
            "name": "Privilege Escalation Chain",
            "description": "检测权限提升攻击链：可疑进程 -> 高权限操作",
            "queries": [
                {
                    "category": "process",
                    "query_string": "(tags:attack.privilege_escalation OR tags:attack.t1078 OR tags:attack.t1548 OR threat.tactic:privilege_escalation) AND event.severity:>=50"
                },
                {
                    "category": "file",
                    "query_string": "(file.path:/etc/passwd OR file.path:/etc/shadow OR file.path:/etc/sudoers OR threat.tactic:privilege_escalation) AND event.severity:>=50"
                }
            ],
            "tags": ["attack.privilege_escalation", "attack.t1078", "attack.t1548"]
        },
        {
            "name": "Data Exfiltration Pattern",
            "description": "检测数据泄露模式：大量文件访问 -> 网络传输",
            "queries": [
                {
                    "category": "file",
                    "query_string": "(tags:attack.collection OR tags:attack.t1005) AND event.category:file AND event.action:file_read"
                },
                {
                    "category": "network",
                    "query_string": "(tags:attack.exfiltration OR tags:attack.t1041) AND event.category:network AND network.direction:outbound"
                }
            ],
            "tags": ["attack.collection", "attack.exfiltration", "attack.t1005", "attack.t1041"]
        },
        {
            "name": "Persistence Mechanism",
            "description": "检测持久化机制：服务创建 -> 启动项修改",
            "queries": [
                {
                    "category": "process",
                    "query_string": "(process.command_line:*crontab* OR process.command_line:*systemctl*) AND event.category:process"
                },
                {
                    "category": "file",
                    "query_string": "(file.path:*rc.local* OR file.path:*autostart* OR file.path:/etc/systemd/system/*) AND event.category:file"
                }
            ],
            "tags": ["attack.persistence", "attack.t1543", "attack.t1547"]
        },
        {
            "name": "Command and Control Detection",
            "description": "检测C2通信：异常DNS查询 -> 异常网络连接",
            "queries": [
                {
                    "category": "dns",
                    "query_string": "(tags:attack.command_and_control OR tags:attack.t1071) AND event.category:dns"
                },
                {
                    "category": "network",
                    "query_string": "(tags:attack.command_and_control OR tags:attack.t1071) AND event.category:network AND network.direction:outbound"
                }
            ],
            "tags": ["attack.command_and_control", "attack.t1071"]
        },
        {
            "name": "Defense Evasion Attempts",
            "description": "检测防御规避尝试：日志清除 -> 进程隐藏",
            "queries": [
                {
                    "category": "file",
                    "query_string": "(tags:attack.defense_evasion OR tags:attack.t1070) AND event.category:file"
                },
                {
                    "category": "process",
                    "query_string": "(tags:attack.defense_evasion OR tags:attack.t1562) AND event.category:process"
                }
            ],
            "tags": ["attack.defense_evasion", "attack.t1070", "attack.t1562"]
        },
        {
            "name": "Credential Access Pattern",
            "description": "检测凭据访问模式：可疑文件访问 -> 认证异常",
            "queries": [
                {
                    "category": "file",
                    "query_string": "(file.path:*passwd* OR file.path:*shadow* OR file.path:*credential*) AND event.category:file"
                },
                {
                    "category": "authentication",
                    "query_string": "(tags:attack.credential_access OR tags:attack.t1003) AND event.category:authentication"
                }
            ],
            "tags": ["attack.credential_access", "attack.t1003"]
        },
        {
            "name": "Lateral Movement via Network",
            "description": "检测横向移动：远程连接 -> 可疑进程执行",
            "queries": [
                {
                    "category": "network",
                    "query_string": "(tags:attack.lateral_movement OR tags:attack.t1021) AND event.category:network AND network.direction:outbound"
                },
                {
                    "category": "process",
                    "query_string": "(tags:attack.execution OR tags:attack.t1059) AND event.category:process AND _exists_:host.name"
                }
            ],
            "tags": ["attack.lateral_movement", "attack.t1021", "attack.t1059"]
        },
        {
            "name": "Impact Attack Pattern",
            "description": "检测影响攻击：服务停止 -> 数据操作",
            "queries": [
                {
                    "category": "process",
                    "query_string": "(tags:attack.impact OR tags:attack.t1489) AND event.category:process"
                },
                {
                    "category": "file",
                    "query_string": "(tags:attack.impact OR tags:attack.t1565) AND event.category:file AND event.action:file_modify"
                }
            ],
            "tags": ["attack.impact", "attack.t1489", "attack.t1565"]
        },
        {
            "name": "Same Host Multiple Threats",
            "description": "检测同一主机上的多个威胁findings",
            "queries": [
                {
                    "category": "process",
                    "query_string": "event.severity:>=50 AND _exists_:host.name"
                },
                {
                    "category": "network",
                    "query_string": "event.severity:>=50 AND _exists_:host.name"
                }
            ],
            "tags": ["multi-threat", "attack.detection"]
        },
        {
            "name": "Same IP Multiple Findings",
            "description": "检测来自同一IP的多个findings",
            "queries": [
                {
                    "category": "network",
                    "query_string": "_exists_:source.ip AND event.severity:>=40"
                },
                {
                    "category": "network",
                    "query_string": "_exists_:source.ip AND event.severity:>=40"
                }
            ],
            "tags": ["network-threat", "attack.detection"]
        },
        {
            "name": "Threat Tactic Correlation",
            "description": "检测不同ATT&CK战术的findings关联",
            "queries": [
                {
                    "category": "process",
                    "query_string": "(_exists_:threat.tactic OR _exists_:threat.technique OR _exists_:tags) AND event.severity:>=40"
                },
                {
                    "category": "network",
                    "query_string": "(_exists_:threat.tactic OR _exists_:threat.technique OR _exists_:tags) AND event.severity:>=40"
                }
            ],
            "tags": ["attack.correlation", "mitre-attack"]
        },
        {
            "name": "Any Findings with Tags",
            "description": "检测带有tags的findings关联（最简单的规则）",
            "queries": [
                {
                    "category": "process",
                    "query_string": "_exists_:tags AND event.severity:>=40"
                },
                {
                    "category": "network",
                    "query_string": "_exists_:tags AND event.severity:>=40"
                }
            ],
            "tags": ["simple", "tags"]
        },
        {
            "name": "Any Two Findings",
            "description": "检测任意两个findings（最宽松的规则，确保能找到correlations）",
            "queries": [
                {
                    "category": "process",
                    "query_string": "_exists_:event.severity"
                },
                {
                    "category": "network",
                    "query_string": "_exists_:event.severity"
                }
            ],
            "tags": ["simple", "any"]
        },
        {
            "name": "Critical Severity Chain",
            "description": "检测严重性为critical的findings链",
            "queries": [
                {
                    "category": "process",
                    "query_string": "event.severity:>=80 AND _exists_:host.name"
                },
                {
                    "category": "network",
                    "query_string": "event.severity:>=80 AND _exists_:host.name"
                }
            ],
            "tags": ["critical", "attack.detection"]
        }
    ]
    
    print("=" * 80)
    print("创建针对 Findings 的 Correlation Rules")
    print("=" * 80)
    print(f"\n将创建 {len(rules_to_create)} 个 correlation rules（针对 raw-findings-* 索引）\n")
    
    results = []
    successful = 0
    failed = 0
    
    for i, rule_config in enumerate(rules_to_create, 1):
        print(f"[{i}/{len(rules_to_create)}] 创建规则: {rule_config['name']}")
        result = create_findings_correlation_rule(
            rule_name=rule_config['name'],
            description=rule_config['description'],
            queries=rule_config['queries'],
            tags=rule_config.get('tags', [])
        )
        
        results.append({
            "name": rule_config['name'],
            "success": result.get("success", False),
            "rule_id": result.get("rule_id"),
            "message": result.get("message", "")
        })
        
        if result.get("success"):
            successful += 1
        else:
            failed += 1
        print()
    
    print("=" * 80)
    print("创建完成")
    print("=" * 80)
    print(f"  成功: {successful} 个")
    print(f"  失败: {failed} 个")
    print(f"  总计: {len(rules_to_create)} 个")
    
    if failed > 0:
        print("\n失败的规则:")
        for r in results:
            if not r['success']:
                print(f"  - {r['name']}: {r['message']}")
    
    return {
        "success": failed == 0,
        "results": results,
        "successful": successful,
        "failed": failed
    }


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="创建针对 Findings 的 Correlation Rules")
    parser.add_argument(
        "--yes",
        action="store_true",
        help="自动确认（不需要交互）"
    )
    
    args = parser.parse_args()
    
    create_all_findings_correlation_rules()
