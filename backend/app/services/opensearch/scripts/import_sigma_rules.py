#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sigma 规则智能导入脚本

功能：
1. 自动筛选适合 ECS 格式的 Sigma 规则
2. 按类别组织规则（进程、网络、文件等）
3. 批量导入规则到 OpenSearch Security Analytics
4. 创建或更新 detector

使用方法:
    python import_sigma_rules.py [选项]

选项:
    --category CAT     按类别导入（process/network/file/auth）
    --attack-id ID     导入特定 ATT&CK 技术ID的规则（如 T1055）
    --file FILE        导入单个规则文件
    --list             列出所有可用的规则类别
    --dry-run          仅显示将要导入的规则，不实际导入
    --auto             自动模式：导入推荐的规则集并创建 detector
"""

import argparse
import os
import sys
import yaml
from pathlib import Path
from typing import List, Optional, Dict, Any
from datetime import date, datetime
import httpx
from urllib3.exceptions import InsecureRequestWarning

# 禁用 SSL 警告
import urllib3
import warnings
urllib3.disable_warnings(InsecureRequestWarning)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# 设置输出为无缓冲模式，确保实时输出
if sys.stdout.isatty():
    sys.stdout.reconfigure(line_buffering=True)

# 添加 backend 目录到 sys.path，确保可导入 `app.*`
backend_dir = Path(__file__).resolve().parents[4]
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

# 延迟导入 opensearch 模块（仅在需要时）
def get_client():
    """延迟导入 get_client"""
    try:
        from app.services.opensearch import get_client as _get_client
        return _get_client()
    except ImportError as e:
        print("\n[ERROR] 无法导入 opensearch 模块")
        print("提示: 请使用 uv run 运行此脚本:")
        print("     cd backend && uv run python app/services/opensearch/scripts/import_sigma_rules.py [选项]")
        print("\n或者确保已安装依赖:")
        print("     uv sync")
        raise

# OpenSearch 配置
#
# Prefer the backend-wide variables from docs/ENV_CONFIG.md:
# - OPENSEARCH_NODE / OPENSEARCH_USERNAME / OPENSEARCH_PASSWORD
# Keep compatibility with earlier script-specific vars:
# - OPENSEARCH_URL / OPENSEARCH_USER
OPENSEARCH_NODE = os.getenv("OPENSEARCH_NODE") or os.getenv("OPENSEARCH_URL") or "https://localhost:9200"
OPENSEARCH_USERNAME = (
    os.getenv("OPENSEARCH_USERNAME") or os.getenv("OPENSEARCH_USER") or "admin"
)
OPENSEARCH_PASSWORD = os.getenv("OPENSEARCH_PASSWORD", "OpenSearch@2024!Dev")

def test_opensearch_connection() -> bool:
    """测试OpenSearch连接"""
    try:
        client = httpx.Client(
            auth=(OPENSEARCH_USERNAME, OPENSEARCH_PASSWORD),
            verify=False,
            timeout=httpx.Timeout(10.0, connect=5.0),
            follow_redirects=True
        )
        try:
            response = client.get(f"{OPENSEARCH_NODE}/", follow_redirects=True)
            if response.status_code == 200:
                return True
            else:
                print(f"警告: OpenSearch返回状态码 {response.status_code}")
                return False
        finally:
            client.close()
    except httpx.ConnectError as e:
        print(f"\n[错误] 无法连接到 OpenSearch: {OPENSEARCH_NODE}")
        print(f"  错误详情: {e}")
        print(f"  请检查:")
        print(f"    1) OpenSearch服务是否运行: docker ps | findstr opensearch")
        print(f"    2) URL是否正确: {OPENSEARCH_NODE}")
        print(f"    3) 网络连接是否正常")
        return False
    except httpx.TimeoutException as e:
        print(f"\n[错误] 连接超时: {OPENSEARCH_NODE}")
        print(f"  提示: OpenSearch可能未启动或响应缓慢")
        return False
    except Exception as e:
        print(f"\n[错误] 连接测试失败: {type(e).__name__}: {e}")
        return False

# Sigma 规则目录（git submodule）
# repo: backend/app/services/opensearch/sigma-rules
SIGMA_RULES_DIR = Path(__file__).resolve().parents[1] / "sigma-rules"

# ECS 字段映射（Sigma 字段 -> ECS 字段）
SIGMA_TO_ECS_MAPPING = {
    # 进程相关
    "CommandLine": "process.command_line",
    "Image": "process.executable",
    "OriginalFileName": "process.executable",
    "ProcessId": "process.pid",
    "ParentCommandLine": "process.parent.command_line",
    "ParentImage": "process.parent.executable",
    "ParentProcessId": "process.parent.pid",
    # 网络相关
    "DestinationIp": "destination.ip",
    "DestinationPort": "destination.port",
    "SourceIp": "source.ip",
    "SourcePort": "source.port",
    "QueryName": "dns.question.name",
    # 文件相关
    "TargetFilename": "file.path",
    "FileName": "file.name",
    # 用户相关
    "TargetUserName": "user.name",
    "SubjectUserName": "user.name",
    # 主机相关
    "Computer": "host.name",
    "Hostname": "host.name",
}

# 推荐的规则类别和路径
RECOMMENDED_CATEGORIES = {
    "process": {
        "paths": [
            "rules/windows/process_creation",
            "rules/linux/process_creation",
        ],
        "description": "进程创建相关规则（检测可疑进程执行）",
        "max_rules": 50,  # 限制导入数量，避免过多
    },
    "network": {
        "paths": [
            "rules/network",
        ],
        "description": "网络流量相关规则（检测可疑网络连接）",
        "max_rules": 30,
    },
    "file": {
        "paths": [
            "rules/windows/file_event",
            "rules/linux/file_event",
        ],
        "description": "文件操作相关规则（检测可疑文件访问）",
        "max_rules": 30,
    },
    "auth": {
        "paths": [
            "rules/windows/builtin/security",
            "rules/identity",
        ],
        "description": "认证相关规则（检测可疑登录）",
        "max_rules": 20,
    },
}


def find_sigma_rules(
    category: Optional[str] = None,
    attack_id: Optional[str] = None,
    max_rules: Optional[int] = None
) -> List[Path]:
    """查找 Sigma 规则文件"""
    rules = []
    rules_dir = SIGMA_RULES_DIR
    
    if not rules_dir.exists():
        print(f"错误: Sigma 规则目录不存在: {rules_dir}")
        print("请先初始化 Sigma 规则 submodule：")
        print("  git submodule update --init --recursive")
        print("或手动克隆到该目录：")
        print("  backend/app/services/opensearch/sigma-rules")
        return []
    
    search_paths = []
    if category and category in RECOMMENDED_CATEGORIES:
        # 使用推荐的类别路径
        category_info = RECOMMENDED_CATEGORIES[category]
        for rel_path in category_info["paths"]:
            full_path = rules_dir / rel_path
            if full_path.exists():
                search_paths.append(full_path)
        if not search_paths:
            print(f"警告: 类别 '{category}' 的路径不存在")
            return []
    elif category:
        # 自定义类别路径
        category_path = rules_dir / "rules" / category
        if category_path.exists():
            search_paths = [category_path]
        else:
            print(f"警告: 类别 '{category}' 不存在")
            return []
    else:
        # 默认搜索主要类别
        for cat_info in RECOMMENDED_CATEGORIES.values():
            for rel_path in cat_info["paths"]:
                full_path = rules_dir / rel_path
                if full_path.exists():
                    search_paths.append(full_path)
    
    # 收集规则文件（优化：使用rglob但提前停止）
    for search_path in search_paths:
        if not search_path.exists():
            continue
        
        try:
            # 使用rglob扫描，但提前停止
            # 限制扫描深度，避免扫描整个目录树
            max_depth = 5  # 最多扫描5层深度
            depth = 0
            for rule_file in search_path.rglob("*.yml"):
                # 计算深度（简单方法：数路径分隔符）
                relative_path = rule_file.relative_to(search_path)
                depth = len(relative_path.parts) - 1
                if depth > max_depth:
                    continue
                
                # 跳过deprecated目录
                if "deprecated" in str(rule_file):
                    continue
                
                # 如果已经达到限制，停止扫描
                if max_rules and len(rules) >= max_rules:
                    break
                
                if attack_id:
                    # 检查规则是否包含指定的 ATT&CK ID
                    try:
                        with open(rule_file, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            if f"attack.{attack_id.lower()}" in content.lower():
                                rules.append(rule_file)
                    except Exception:
                        pass
                else:
                    rules.append(rule_file)
            
            # 如果已经达到限制，停止扫描其他路径
            if max_rules and len(rules) >= max_rules:
                break
                
        except Exception as e:
            print(f"警告: 扫描路径失败 {search_path}: {e}", flush=True)
            continue
    
    # 最终限制数量（双重保险）
    if max_rules and len(rules) > max_rules:
        rules = rules[:max_rules]
    
    return rules


def analyze_rule_compatibility(rule_file: Path) -> Dict[str, Any]:
    """分析规则与 ECS 格式的兼容性"""
    try:
        with open(rule_file, 'r', encoding='utf-8') as f:
            rule_data = yaml.safe_load(f)
        
        if not rule_data:
            return {"compatible": False, "reason": "无法解析 YAML"}
        
        # 检查规则状态
        status = rule_data.get("status", "stable")
        if status == "deprecated":
            return {"compatible": False, "reason": "规则已废弃"}
        
        # 检查 logsource
        logsource = rule_data.get("logsource", {})
        product = logsource.get("product", "").lower()
        category = logsource.get("category", "").lower()
        
        # 检查 detection 字段
        detection = rule_data.get("detection", {})
        if not detection:
            return {"compatible": False, "reason": "没有 detection 字段"}
        
        # 检查是否使用了可映射的字段
        detection_str = str(detection)
        has_mappable_fields = False
        for sigma_field in SIGMA_TO_ECS_MAPPING.keys():
            if sigma_field.lower() in detection_str.lower():
                has_mappable_fields = True
                break
        
        # 提取 ATT&CK 标签
        tags = rule_data.get("tags", [])
        attack_tags = [tag for tag in tags if isinstance(tag, str) and tag.startswith("attack.")]
        
        return {
            "compatible": True,
            "has_mappable_fields": has_mappable_fields,
            "product": product,
            "category": category,
            "attack_tags": attack_tags,
            "title": rule_data.get("title", "Unknown"),
            "status": status,
        }
    except Exception as e:
        return {"compatible": False, "reason": f"解析错误: {e}"}


def serialize_dates(obj):
    """将日期对象转换为字符串，用于 JSON 序列化"""
    if isinstance(obj, (date, datetime)):
        return obj.isoformat()
    elif isinstance(obj, dict):
        return {k: serialize_dates(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [serialize_dates(item) for item in obj]
    return obj


def import_rule(rule_file: Path, dry_run: bool = False) -> bool:
    """导入单个 Sigma 规则到 OpenSearch"""
    if dry_run:
        print(f"[DRY RUN] 将导入: {rule_file.relative_to(SIGMA_RULES_DIR)}")
        return True
    
    try:
        # 读取并解析 YAML 规则文件
        with open(rule_file, 'r', encoding='utf-8') as f:
            rule_data = yaml.safe_load(f)
        
        if not rule_data:
            print(f"✗ 导入失败: {rule_file.name} (无法解析 YAML)")
            return False
        
        # 序列化日期字段（date 和 modified）
        rule_data = serialize_dates(rule_data)
        
        # 确定 category 和 logType（从 logsource 或文件路径推断）
        logsource = rule_data.get("logsource", {})
        product = logsource.get("product", "").lower()
        logsource_category = logsource.get("category", "").lower()
        
        # 映射 product 到 category 和 logType
        # OpenSearch Security Analytics 需要 logType 字段来匹配 detector_type
        product_to_logtype = {
            "windows": "windows",
            "linux": "linux",
            "macos": "macos",
        }
        
        # 如果从路径推断
        rule_path_str = str(rule_file)
        if "windows" in rule_path_str.lower():
            category = "windows"
            log_type = "windows"
        elif "linux" in rule_path_str.lower():
            category = "linux"
            log_type = "linux"
        elif "macos" in rule_path_str.lower():
            category = "macos"
            log_type = "macos"
        elif "network" in rule_path_str.lower() or "net" in rule_path_str.lower() or logsource_category == "dns":
            category = "network"
            log_type = "network"
        else:
            # 从product推断
            log_type = product_to_logtype.get(product, "network")
            category = log_type
        
        # 添加 logType 字段到规则数据（OpenSearch Security Analytics 需要这个字段）
        if "logType" not in rule_data:
            rule_data["logType"] = log_type
        
        # 使用 POST 方法创建规则（不是 _upload 端点）
        url = f"{OPENSEARCH_NODE}/_plugins/_security_analytics/rules"
        params = {"category": category}
        
        # 配置httpx客户端，处理HTTPS连接问题
        try:
            # 创建客户端，禁用SSL验证并配置连接池
            client = httpx.Client(
                auth=(OPENSEARCH_USERNAME, OPENSEARCH_PASSWORD),
                verify=False,  # 禁用SSL验证（开发环境）
                timeout=httpx.Timeout(30.0, connect=10.0),  # 连接超时10秒，总超时30秒
                follow_redirects=True,  # 跟随重定向
                limits=httpx.Limits(
                    max_keepalive_connections=5,
                    max_connections=10,
                    keepalive_expiry=5.0
                )
            )
            try:
                response = client.post(url, params=params, json=rule_data)
            finally:
                client.close()  # 确保关闭连接
        except httpx.ConnectError as e:
            print(f"✗ 连接错误: {rule_file.name} - 无法连接到 {OPENSEARCH_NODE}")
            print(f"  错误详情: {e}")
            print(f"  请检查:")
            print(f"    1) OpenSearch服务是否运行 (docker ps)")
            print(f"    2) URL是否正确 ({OPENSEARCH_NODE})")
            print(f"    3) 防火墙/网络是否允许连接")
            return False
        except httpx.TimeoutException as e:
            print(f"✗ 超时错误: {rule_file.name} - 连接超时")
            print(f"  错误详情: {e}")
            print(f"  提示: OpenSearch可能响应缓慢，请检查服务状态")
            return False
        except httpx.HTTPStatusError as e:
            print(f"✗ HTTP状态错误: {rule_file.name} - {e.response.status_code}")
            print(f"  响应: {e.response.text[:300]}")
            return False
        except httpx.HTTPError as e:
            print(f"✗ HTTP错误: {rule_file.name} - {e}")
            return False
        except Exception as e:
            print(f"✗ 未知错误: {rule_file.name} - {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
            return False
        
        if response.status_code in [200, 201]:
            print(f"✓ 成功导入: {rule_file.name} (category: {category})")
            return True
        else:
            print(f"✗ 导入失败: {rule_file.name} (状态码: {response.status_code})")
            print(f"  响应: {response.text[:300]}")
            return False
    except yaml.YAMLError as e:
        print(f"✗ 导入错误: {rule_file.name} - YAML 解析失败: {e}")
        return False
    except Exception as e:
        print(f"✗ 导入错误: {rule_file.name} - {e}")
        import traceback
        traceback.print_exc()
        return False


def list_categories():
    """列出所有可用的规则类别"""
    print("\n推荐的规则类别:")
    print("-" * 70)
    for cat_name, cat_info in RECOMMENDED_CATEGORIES.items():
        print(f"\n{cat_name}:")
        print(f"  描述: {cat_info['description']}")
        print(f"  路径: {', '.join(cat_info['paths'])}")
        print(f"  最大规则数: {cat_info['max_rules']}")
    
    # 列出实际存在的目录
    rules_dir = SIGMA_RULES_DIR / "rules"
    if rules_dir.exists():
        print("\n实际存在的规则目录:")
        print("-" * 70)
        for item in sorted(rules_dir.iterdir()):
            if item.is_dir() and not item.name.startswith('.'):
                rule_count = len(list(item.rglob("*.yml")))
                print(f"  {item.name:30s} ({rule_count} 个规则)")


def get_imported_rules() -> List[str]:
    """获取已导入的规则 ID"""
    try:
        client = get_client()  # 这里会调用延迟导入的函数
        # 使用 match_all 查询，避免 bool query 错误
        response = client.transport.perform_request(
            'POST',
            '/_plugins/_security_analytics/rules/_search',
            body={
                "query": {
                    "match_all": {}
                },
                "size": 1000
            }
        )
        hits = response.get('hits', {}).get('hits', [])
        rule_ids = [hit.get('_id') for hit in hits if hit.get('_id')]
        return rule_ids
    except ImportError:
        # 如果无法导入 opensearch 模块，重新抛出让调用者处理
        raise
    except Exception as e:
        print(f"警告: 无法获取已导入规则列表: {e}")
        return []


def create_or_update_detector(rule_ids: List[str]) -> bool:
    """创建或更新 detector"""
    if not rule_ids:
        print("警告: 没有规则，无法创建 detector")
        return False
    
    client = get_client()  # 这里会调用延迟导入的函数
    
    # 只使用前20个规则（避免 detector 配置过大）
    rules_to_use = rule_ids[:20]
    
    detector_config = {
        "name": "ecs-events-detector",
        "description": "检测 ECS 事件中的可疑行为（自动创建）",
        "detector_type": "network",  # 使用 network 类型（适合 ECS 事件）
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
                    "description": "扫描所有 ecs-events 索引",
                    "indices": ["ecs-events-*"],
                    "custom_rules": [{"id": rule_id} for rule_id in rules_to_use]
                }
            }
        ],
        "triggers": []
    }
    
    try:
        # 检查是否已存在
        try:
            response = client.transport.perform_request(
                'POST',
                '/_plugins/_security_analytics/detectors/_search',
                body={"size": 100}
            )
            detectors = response.get('hits', {}).get('hits', [])
            for hit in detectors:
                detector = hit.get('_source', {})
                if detector.get('name') == 'ecs-events-detector':
                    detector_id = hit.get('_id')
                    print(f"[INFO] Detector 已存在 (ID: {detector_id})，尝试更新...")
                    # 更新现有 detector
                    update_response = client.transport.perform_request(
                        'PUT',
                        f'/_plugins/_security_analytics/detectors/{detector_id}',
                        body=detector_config
                    )
                    print(f"[OK] Detector 更新成功")
                    return True
        except Exception as e:
            print(f"[WARNING] 检查现有 detector 失败: {e}，尝试创建新 detector...")
        
        # 创建新 detector
        response = client.transport.perform_request(
            'POST',
            '/_plugins/_security_analytics/detectors',
            body=detector_config
        )
        detector_id = response.get('_id')
        print(f"[OK] Detector 创建成功 (ID: {detector_id})")
        print(f"     使用了 {len(rules_to_use)} 个规则")
        return True
        
    except Exception as e:
        print(f"[ERROR] 创建/更新 detector 失败: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="将 Sigma 规则导入到 OpenSearch Security Analytics",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--category", help="按类别导入（process/network/file/auth）")
    parser.add_argument("--attack-id", help="导入特定 ATT&CK 技术ID的规则（如 T1055）")
    parser.add_argument("--file", help="导入单个规则文件")
    parser.add_argument("--list", action="store_true", help="列出所有可用的规则类别")
    parser.add_argument("--dry-run", action="store_true", help="仅显示将要导入的规则，不实际导入")
    parser.add_argument("--auto", action="store_true", help="自动模式：导入推荐的规则集并创建 detector")
    
    args = parser.parse_args()
    
    # 如果不是dry-run模式，先测试连接
    if not args.dry_run and not args.list:
        print("测试 OpenSearch 连接...")
        if not test_opensearch_connection():
            print("\n连接失败，退出。")
            sys.exit(1)
        print("✓ 连接成功\n")
    
    if args.list:
        list_categories()
        return
    
    if args.file:
        rule_file = Path(args.file)
        if not rule_file.exists():
            print(f"错误: 文件不存在: {rule_file}")
            sys.exit(1)
        import_rule(rule_file, args.dry_run)
        return
    
    # 自动模式
    if args.auto:
        print("=" * 80)
        print("自动导入模式：导入推荐的规则集")
        print("=" * 80)
        
        all_rules = []
        for category in ["process", "network", "file"]:
            print(f"\n查找 {category} 类别规则...")
            cat_info = RECOMMENDED_CATEGORIES[category]
            rules = find_sigma_rules(category=category, max_rules=cat_info["max_rules"])
            print(f"  找到 {len(rules)} 个规则")
            all_rules.extend(rules)
        
        if not all_rules:
            print("\n错误: 未找到任何规则")
            return
        
        print(f"\n总共找到 {len(all_rules)} 个规则")
        
        if args.dry_run:
            print("\n[DRY RUN 模式] 将导入以下规则:\n", flush=True)
            import sys
            display_count = min(20, len(all_rules))
            for i in range(display_count):
                rule = all_rules[i]
                try:
                    rule_str = str(rule)
                    sigma_dir_str = str(SIGMA_RULES_DIR)
                    if rule_str.startswith(sigma_dir_str):
                        rel_path = rule_str[len(sigma_dir_str)+1:]
                        rel_path = rel_path.replace('\\', '/')  # 统一使用正斜杠
                        print(f"  {i+1}. {rel_path}", flush=True)
                    else:
                        print(f"  {i+1}. {rule.name}", flush=True)
                except Exception:
                    print(f"  {i+1}. {rule.name}", flush=True)
            if len(all_rules) > display_count:
                print(f"  ... 还有 {len(all_rules) - display_count} 个规则", flush=True)
            print()  # 空行
            sys.stdout.flush()
        else:
            print(f"\n开始导入 {len(all_rules)} 个规则...\n")
            success = 0
            failed = 0
            
            for i, rule in enumerate(all_rules, 1):
                print(f"[{i}/{len(all_rules)}] ", end="")
                if import_rule(rule, args.dry_run):
                    success += 1
                else:
                    failed += 1
            
            print(f"\n导入完成: 成功 {success}, 失败 {failed}")
            
            if success > 0:
                print("\n创建/更新 detector...")
                try:
                    imported_rules = get_imported_rules()
                    if imported_rules:
                        print(f"[DEBUG] 找到 {len(imported_rules)} 个已导入规则，尝试创建detector...")
                        create_or_update_detector(imported_rules)
                    else:
                        print("[WARNING] 无法获取已导入规则列表")
                        print("  可能原因: OpenSearch连接问题或规则查询失败")
                        print("  解决方案: 规则已导入，可以手动创建detector")
                        print("\n手动创建 detector 的方法:")
                        print("1. 使用 setup_security_analytics.py:")
                        print("   uv run python opensearch/setup_security_analytics.py")
                        print("2. 或通过 OpenSearch Dashboards:")
                        print("   http://localhost:5601 → Security Analytics → Detectors → Create detector")
                except Exception as e:
                    error_str = str(e)
                    print(f"[WARNING] 无法自动创建 detector")
                    print(f"  错误类型: {type(e).__name__}")
                    print(f"  错误信息: {error_str[:200]}")
                    
                    if 'connection' in error_str.lower() or 'connect' in error_str.lower():
                        print(f"\n  问题: 无法连接到 OpenSearch")
                        print(f"  解决方案: 检查 OpenSearch 服务是否运行")
                        print(f"           检查 URL: {OPENSEARCH_NODE}")
                    
                    print("\n规则已成功导入，但需要手动创建 detector:")
                    print("1. 使用 setup_security_analytics.py:")
                    print("   uv run python opensearch/setup_security_analytics.py")
                    print("2. 或通过 OpenSearch Dashboards:")
                    print("   http://localhost:5601 → Security Analytics → Detectors → Create detector")
        
        return
    
    # 查找规则
    max_rules = None
    if args.category and args.category in RECOMMENDED_CATEGORIES:
        max_rules = RECOMMENDED_CATEGORIES[args.category]["max_rules"]
    
    rules = find_sigma_rules(
        category=args.category,
        attack_id=args.attack_id,
        max_rules=max_rules
    )
    
    if not rules:
        print("未找到匹配的规则")
        return
    
    print(f"找到 {len(rules)} 个规则", flush=True)
    if args.dry_run:
        print("\n[DRY RUN 模式] 将导入以下规则:\n", flush=True)
        import sys
        # 只显示前20个，避免输出太多
        display_count = min(20, len(rules))
        for i in range(display_count):
            rule = rules[i]
            try:
                # 使用字符串操作计算相对路径，避免Path.relative_to可能的问题
                rule_str = str(rule)
                sigma_dir_str = str(SIGMA_RULES_DIR)
                if rule_str.startswith(sigma_dir_str):
                    rel_path = rule_str[len(sigma_dir_str)+1:]  # +1 跳过路径分隔符
                    # 统一使用反斜杠，避免Windows路径问题
                    rel_path = rel_path.replace('\\', '/')
                    print(f"  {i+1}. {rel_path}", flush=True)
                else:
                    print(f"  {i+1}. {rule.name}", flush=True)
            except Exception as e:
                # 如果路径计算失败，直接打印文件名
                print(f"  {i+1}. {rule.name}", flush=True)
        
        if len(rules) > display_count:
            print(f"  ... 还有 {len(rules) - display_count} 个规则")
            sys.stdout.flush()
        
        print()  # 空行
        sys.stdout.flush()
    else:
        print(f"\n开始导入 {len(rules)} 个规则...\n")
        success = 0
        failed = 0
        
        for i, rule in enumerate(rules, 1):
            print(f"[{i}/{len(rules)}] ", end="")
            if import_rule(rule, args.dry_run):
                success += 1
            else:
                failed += 1
        
        print(f"\n导入完成: 成功 {success}, 失败 {failed}")


if __name__ == "__main__":
    main()
