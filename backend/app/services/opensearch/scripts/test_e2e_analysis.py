#!/usr/bin/env python3
"""
端到端测试脚本：从Docker容器启动到验证analysis函数

功能：
1. 检查并启动Docker容器（OpenSearch）
2. 等待OpenSearch就绪
3. 运行run_data_analysis()函数
4. 验证：
   - 规则和detector自动设置功能
   - 威胁信息提取（ATT&CK Tactic）
   - 检测和去重功能
"""

import sys
import time
import subprocess
import requests
from pathlib import Path
from datetime import datetime
import os

# 添加 backend 目录到路径，以便从 opensearch 包和 app 模块导入
# 脚本在 backend/app/services/opensearch/scripts/，需要回到 backend/ 才能导入 app 和 opensearch 包
backend_dir = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(backend_dir))

# 设置环境变量（如果需要）
import os
if "OPENSEARCH_INITIAL_ADMIN_PASSWORD" not in os.environ:
    os.environ["OPENSEARCH_INITIAL_ADMIN_PASSWORD"] = "OpenSearch@2024!Dev"

# 使用internal模块导入内部接口（scripts应该使用internal）
from app.services.opensearch.internal import get_client, INDEX_PATTERNS, get_index_name
from app.services.opensearch import store_events
from app.services.opensearch.analysis import (
    run_data_analysis,
    _check_and_setup_rules_detectors,
    _convert_security_analytics_finding_to_ecs,
)


def check_docker_running():
    """检查Docker是否运行"""
    try:
        result = subprocess.run(
            ["docker", "ps"],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False


def check_opensearch_container():
    """检查OpenSearch容器是否运行"""
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", "name=opensearch", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=5
        )
        return "opensearch" in result.stdout
    except Exception:
        return False


def start_opensearch_container():
    """启动OpenSearch容器"""
    print("[1] 启动OpenSearch容器...")
    
    compose_file = backend_dir.parent / "docker-compose.yml"
    if not compose_file.exists():
        print(f"[ERROR] 找不到docker-compose.yml: {compose_file}")
        return False
    
    try:
        result = subprocess.run(
            ["docker", "compose", "-f", str(compose_file), "up", "-d", "opensearch"],
            cwd=str(compose_file.parent),
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode == 0:
            print("[OK] OpenSearch容器启动命令执行成功")
            return True
        else:
            print(f"[ERROR] 启动失败: {result.stderr}")
            return False
    except Exception as e:
        print(f"[ERROR] 启动容器时出错: {e}")
        return False


def wait_for_opensearch(max_wait_seconds=120):
    """等待OpenSearch就绪"""
    print(f"\n[2] 等待OpenSearch就绪（最多等待{max_wait_seconds}秒）...")
    
    # 从环境变量或默认值获取密码
    password = os.getenv("OPENSEARCH_INITIAL_ADMIN_PASSWORD", "OpenSearch@2024!Dev")
    
    start_time = time.time()
    while time.time() - start_time < max_wait_seconds:
        try:
            # 尝试连接OpenSearch
            response = requests.get(
                "https://localhost:9200/_cluster/health",
                auth=("admin", password),
                verify=False,  # 忽略SSL证书验证（开发环境）
                timeout=5
            )
            
            if response.status_code == 200:
                health = response.json()
                status = health.get("status", "unknown")
                print(f"[OK] OpenSearch已就绪，集群状态: {status}")
                return True
        except Exception as e:
            elapsed = int(time.time() - start_time)
            if elapsed % 10 == 0:
                print(f"    等待中... ({elapsed}/{max_wait_seconds}秒)")
            time.sleep(2)
    
    print(f"[ERROR] OpenSearch在{max_wait_seconds}秒内未就绪")
    return False


def test_rules_detectors_setup():
    """测试规则和detector自动设置功能"""
    print("\n" + "=" * 80)
    print("[3] 测试规则和detector自动设置功能")
    print("=" * 80)
    
    try:
        result = _check_and_setup_rules_detectors()
        
        if result:
            print("\n[OK] 规则和detector已就绪")
        else:
            print("\n[WARNING] 规则或detector未就绪（可能需要手动设置）")
        
        return result
    except Exception as e:
        print(f"[ERROR] 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_tactic_extraction():
    """测试威胁信息提取（ATT&CK Tactic）"""
    print("\n" + "=" * 80)
    print("[4] 测试威胁信息提取（ATT&CK Tactic）")
    print("=" * 80)
    
    # 创建一个测试finding（模拟Security Analytics返回的格式）
    test_finding = {
        "id": "test-finding-001",
        "timestamp": datetime.now().isoformat(),
        "detector": {
            "id": "test-detector-001",
            "name": "Test Detector"
        },
        "queries": [
            {
                "name": "Test Rule",
                "tags": ["attack.t1546.013"]  # Technique ID: T1546.013 -> Persistence (TA0003)
            }
        ],
        "severity": 50,
        "description": "Test finding for tactic extraction"
    }
    
    try:
        ecs_finding = _convert_security_analytics_finding_to_ecs(test_finding)
        
        threat = ecs_finding.get("threat", {})
        tactic = threat.get("tactic", {})
        tactic_id = tactic.get("id", "N/A")
        tactic_name = tactic.get("name", "N/A")
        technique = threat.get("technique", {})
        technique_id = technique.get("id", "N/A") if technique else "N/A"
        
        print(f"\n测试Finding转换结果:")
        print(f"  Tactic ID: {tactic_id}")
        print(f"  Tactic Name: {tactic_name}")
        print(f"  Technique ID: {technique_id}")
        
        # 验证提取结果
        if tactic_id == "TA0003" and tactic_name == "Persistence":
            print("\n[OK] Tactic提取正确！")
            print(f"     Technique T1546.013 正确映射到 Tactic TA0003 (Persistence)")
            return True
        elif tactic_id == "TA0000" or tactic_name == "Unknown":
            print("\n[WARNING] Tactic未提取（使用默认值）")
            print("    这可能是正常的，如果Security Analytics没有提供正确的tags")
            return False
        else:
            print(f"\n[INFO] Tactic已提取: {tactic_id} ({tactic_name})")
            return True
            
    except Exception as e:
        print(f"[ERROR] 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def check_and_create_test_events():
    """检查是否有原始事件数据，如果没有则创建测试数据"""
    print("\n" + "=" * 80)
    print("[4.5] 检查原始事件数据（ECS Events）")
    print("=" * 80)
    
    client = get_client()
    today = datetime.now()
    
    # 检查ECS Events索引
    events_index = get_index_name(INDEX_PATTERNS["ECS_EVENTS"], today)
    event_count = 0
    
    if client.indices.exists(index=events_index):
        try:
            stats = client.count(index=events_index)
            event_count = stats.get('count', 0)
        except:
            pass
    
    print(f"\n当前ECS Events数量: {event_count}")
    
    if event_count == 0:
        print("\n[WARNING] 没有原始事件数据，Security Analytics无法检测异常")
        print("[INFO] 尝试创建测试事件数据...")
        
        try:
            # 导入create_matching_events模块
            scripts_dir = Path(__file__).parent
            create_events_script = scripts_dir / "create_matching_events.py"
            
            if create_events_script.exists():
                import subprocess
                import os
                env = os.environ.copy()
                env['PYTHONIOENCODING'] = 'utf-8'
                
                result = subprocess.run(
                    [sys.executable, str(create_events_script)],
                    cwd=str(scripts_dir),
                    capture_output=False,
                    timeout=60,
                    env=env
                )
                
                if result.returncode == 0:
                    print("[OK] 测试事件数据创建成功")
                    # 再次检查事件数量
                    if client.indices.exists(index=events_index):
                        try:
                            stats = client.count(index=events_index)
                            event_count = stats.get('count', 0)
                            print(f"[INFO] 当前ECS Events数量: {event_count}")
                        except:
                            pass
                else:
                    print("[WARNING] 测试事件数据创建可能失败")
            else:
                print(f"[WARNING] 找不到create_matching_events.py脚本: {create_events_script}")
        except Exception as e:
            print(f"[WARNING] 创建测试事件数据失败: {e}")
            print("[INFO] 可以手动运行: uv run python create_matching_events.py")
    else:
        print(f"[OK] 已有 {event_count} 个原始事件数据")
    
    return event_count > 0


def test_run_data_analysis():
    """测试运行完整分析流程"""
    print("\n" + "=" * 80)
    print("[5] 测试运行完整分析流程（run_data_analysis）")
    print("=" * 80)
    
    client = get_client()
    today = datetime.now()
    
    # 检查Raw Findings索引（之前）
    raw_index = get_index_name(INDEX_PATTERNS["RAW_FINDINGS"], today)
    raw_count_before = 0
    if client.indices.exists(index=raw_index):
        try:
            stats = client.count(index=raw_index)
            raw_count_before = stats.get('count', 0)
        except:
            pass
    
    # 检查Canonical Findings索引（之前）
    canonical_index = get_index_name(INDEX_PATTERNS["CANONICAL_FINDINGS"], today)
    canonical_count_before = 0
    if client.indices.exists(index=canonical_index):
        try:
            stats = client.count(index=canonical_index)
            canonical_count_before = stats.get('count', 0)
        except:
            pass
    
    print(f"\n当前状态:")
    print(f"  Raw Findings: {raw_count_before}")
    print(f"  Canonical Findings: {canonical_count_before}")
    
    try:
        print(f"\n开始运行分析...")
        result = run_data_analysis(trigger_scan=True, force_scan=False)
        
        print("\n" + "-" * 80)
        print("分析结果")
        print("-" * 80)
        
        detection = result.get("detection", {})
        deduplication = result.get("deduplication", {})
        
        print(f"\n检测阶段:")
        print(f"  成功: {detection.get('success', False)}")
        print(f"  Findings总数: {detection.get('findings_count', 0)}")
        print(f"  新Findings: {detection.get('new_findings_count', 0)}")
        print(f"  存储成功: {detection.get('stored', 0)}")
        print(f"  存储失败: {detection.get('failed', 0)}")
        print(f"  重复跳过: {detection.get('duplicated', 0)}")
        print(f"  扫描请求: {detection.get('scan_requested', False)}")
        print(f"  扫描完成: {detection.get('scan_completed', False)}")
        print(f"  数据来源: {detection.get('source', 'unknown')}")
        
        print(f"\n去重阶段:")
        print(f"  原始Findings: {deduplication.get('total', 0)}")
        print(f"  合并数量: {deduplication.get('merged', 0)}")
        print(f"  Canonical Findings: {deduplication.get('canonical', 0)}")
        print(f"  错误: {deduplication.get('errors', 0)}")
        
        # 检查索引变化
        raw_count_after = 0
        if client.indices.exists(index=raw_index):
            try:
                stats = client.count(index=raw_index)
                raw_count_after = stats.get('count', 0)
            except:
                pass
        
        canonical_count_after = 0
        if client.indices.exists(index=canonical_index):
            try:
                stats = client.count(index=canonical_index)
                canonical_count_after = stats.get('count', 0)
            except:
                pass
        
        print(f"\n索引变化:")
        print(f"  Raw Findings: {raw_count_before} -> {raw_count_after} (新增: {raw_count_after - raw_count_before})")
        print(f"  Canonical Findings: {canonical_count_before} -> {canonical_count_after} (新增: {canonical_count_after - canonical_count_before})")
        
        # 验证结果
        success = True
        if not detection.get('success', False):
            print("\n[WARNING] 检测阶段未成功")
            success = False
        
        if detection.get('findings_count', 0) == 0:
            print("\n[INFO] 没有findings（可能是正常的，如果没有检测到异常）")
        
        if deduplication.get('canonical', 0) > 0:
            print("\n[OK] 生成了Canonical Findings")
        
        return success
        
    except Exception as e:
        print(f"[ERROR] 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def check_findings_tactic():
    """检查findings中的tactic提取情况"""
    print("\n" + "=" * 80)
    print("[6] 检查findings中的tactic提取情况")
    print("=" * 80)
    
    client = get_client()
    today = datetime.now()
    raw_index = get_index_name(INDEX_PATTERNS["RAW_FINDINGS"], today)
    
    if not client.indices.exists(index=raw_index):
        print("\n[INFO] Raw Findings索引不存在，跳过检查")
        return True
    
    try:
        response = client.search(
            index=raw_index,
            body={
                "size": 20,
                "sort": [{"@timestamp": {"order": "desc"}}]
            }
        )
        hits = response.get('hits', {}).get('hits', [])
        
        if not hits:
            print("\n[INFO] 没有Raw Findings，跳过检查")
            return True
        
        print(f"\n检查前{min(10, len(hits))}个findings的tactic提取情况:")
        print("-" * 80)
        
        tactic_stats = {}
        unknown_count = 0
        
        for i, hit in enumerate(hits[:10], 1):
            finding = hit.get('_source', {})
            finding_id = finding.get('event', {}).get('id', 'N/A')[:30]
            
            threat = finding.get('threat', {})
            tactic = threat.get('tactic', {})
            tactic_id = tactic.get('id', 'N/A')
            tactic_name = tactic.get('name', 'N/A')
            
            rule_name = finding.get('rule', {}).get('name', 'N/A')
            
            print(f"\n[{i}] Finding ID: {finding_id}...")
            print(f"    规则: {rule_name}")
            print(f"    Tactic ID: {tactic_id}")
            print(f"    Tactic Name: {tactic_name}")
            
            if tactic_id == "TA0000" or tactic_name == "Unknown":
                unknown_count += 1
                print(f"    [WARNING] Tactic未提取（使用默认值）")
            else:
                print(f"    [OK] Tactic已提取")
                tactic_stats[tactic_id] = tactic_stats.get(tactic_id, 0) + 1
        
        print("\n" + "-" * 80)
        print("统计信息")
        print("-" * 80)
        
        if tactic_stats:
            print(f"\nTactic分布:")
            for tactic_id, count in sorted(tactic_stats.items(), key=lambda x: -x[1]):
                print(f"  {tactic_id}: {count} 个findings")
        
        print(f"\n未提取Tactic的findings: {unknown_count}/{len(hits)}")
        
        if unknown_count == 0:
            print("\n[OK] 所有findings的tactic都已正确提取！")
        elif unknown_count < len(hits) / 2:
            print(f"\n[INFO] 大部分findings的tactic已提取（{len(hits) - unknown_count}/{len(hits)}）")
        else:
            print(f"\n[WARNING] 有较多findings的tactic未提取（{unknown_count}/{len(hits)}）")
        
        return True
        
    except Exception as e:
        print(f"[ERROR] 检查失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """主函数"""
    print("=" * 80)
    print("端到端测试：从Docker容器启动到验证analysis函数")
    print("=" * 80)
    
    # Step 1: 检查Docker
    if not check_docker_running():
        print("\n[ERROR] Docker未运行，请先启动Docker")
        return 1
    
    # Step 2: 检查或启动OpenSearch容器
    if not check_opensearch_container():
        print("\n[INFO] OpenSearch容器未运行，尝试启动...")
        if not start_opensearch_container():
            print("\n[ERROR] 无法启动OpenSearch容器")
            return 1
        time.sleep(5)  # 等待容器启动
    else:
        print("\n[OK] OpenSearch容器已在运行")
    
    # Step 3: 等待OpenSearch就绪
    if not wait_for_opensearch():
        print("\n[ERROR] OpenSearch未就绪")
        return 1
    
    # Step 4: 测试规则和detector自动设置
    test_rules_detectors_setup()
    
    # Step 5: 测试威胁信息提取
    test_tactic_extraction()
    
    # Step 5.5: 检查并创建测试事件数据（如果需要）
    has_events = check_and_create_test_events()
    if not has_events:
        print("\n[WARNING] 没有原始事件数据，分析可能无法生成findings")
        print("[INFO] 建议：先运行 create_matching_events.py 创建测试数据")
    
    # Step 6: 测试运行完整分析
    test_run_data_analysis()
    
    # Step 7: 检查findings中的tactic提取
    check_findings_tactic()
    
    print("\n" + "=" * 80)
    print("测试完成")
    print("=" * 80)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
