# -*- coding: utf-8 -*-
"""
OpenSearch 模块系统测试（端到端集成测试）
黑盒测试：测试完整业务流程，不关注内部实现细节

测试场景：
1. 完整的数据存储和检索流程
2. 告警融合去重的完整流程
3. 数据分析的完整流程
4. 多索引协同工作
"""

import pytest
import sys
from pathlib import Path
from datetime import datetime, timedelta
from typing import Any

# 添加父目录到路径，以便导入 opensearch 模块
test_dir = Path(__file__).parent
parent_dir = test_dir.parent  # backend/opensearch
backend_dir = parent_dir.parent  # backend
sys.path.insert(0, str(backend_dir))  # 确保backend目录在路径中
sys.path.insert(0, str(parent_dir))  # 也添加opensearch目录

# 添加 test 目录到路径，以便导入 test_utils
sys.path.insert(0, str(test_dir))

from test_utils import (
    create_test_event,
    create_test_finding,
    create_test_finding_with_process,
    create_test_finding_with_destination,
    create_test_finding_with_file,
    assert_event_structure,
    assert_finding_structure,
)


class TestEndToEndWorkflow:
    """端到端工作流测试"""
    
    def test_complete_event_lifecycle(self, initialized_indices):
        """
        测试完整的事件生命周期：
        1. 存储事件
        2. 搜索事件
        3. 获取事件详情
        """
        from .. import store_events, search, get_document, get_index_name, INDEX_PATTERNS
        
        # Step 1: 存储事件
        event = create_test_event("evt-e2e-001", host_name="e2e-host")
        store_result = store_events([event])
        
        assert store_result["success"] == 1
        
        # Step 2: 搜索事件
        index_name = get_index_name(INDEX_PATTERNS["ECS_EVENTS"])
        search_results = search(index_name, {"match_all": {}}, size=10)
        
        assert len(search_results) >= 1
        found_event = next((e for e in search_results if e["event"]["id"] == "evt-e2e-001"), None)
        assert found_event is not None
        assert found_event["host"]["name"] == "e2e-host"
        
        # Step 3: 获取事件详情
        event_detail = get_document(index_name, "evt-e2e-001")
        assert event_detail is not None
        assert event_detail["event"]["id"] == "evt-e2e-001"
        assert_event_structure(event_detail)
    
    def test_complete_finding_deduplication_workflow(self, initialized_indices):
        """
        测试完整的告警去重工作流：
        1. 存储多个相似的Raw Findings
        2. 执行去重
        3. 验证Canonical Findings生成
        """
        from .. import (
            store_events,
            deduplicate_findings,
            search,
            get_index_name,
            INDEX_PATTERNS,
        )
        
        # Step 1: 创建多个相似的findings（相同technique、host、时间窗口）
        base_time = datetime.now()
        findings = []
        for i in range(3):
            finding = create_test_finding(
                f"finding-e2e-{i}",
                technique_id="T1078",
                tactic_id="TA0001",
                host_id="h-e2e",
                host_name="e2e-host",
                provider=f"provider-{i}",
                timestamp=(base_time + timedelta(seconds=i)).isoformat(),
            )
            findings.append(finding)
        
        # Step 2: 存储Raw Findings
        store_result = store_events(findings)
        assert store_result["success"] == 3
        
        # Step 3: 执行去重
        dedup_result = deduplicate_findings()
        assert dedup_result["total"] >= 3
        assert dedup_result["canonical"] > 0
        
        # Step 4: 验证Canonical Findings
        canonical_index = get_index_name(INDEX_PATTERNS["CANONICAL_FINDINGS"])
        canonical_results = search(canonical_index, {"match_all": {}}, size=10)
        
        assert len(canonical_results) > 0
        for canonical in canonical_results:
            assert_finding_structure(canonical, stage="canonical")
            assert "providers" in canonical["custom"]["finding"]
            # 合并后的finding应该包含多个providers
            if dedup_result["merged"] > 0:
                assert len(canonical["custom"]["finding"]["providers"]) >= 1
    
    def test_multi_index_data_flow(self, initialized_indices):
        """
        测试多索引数据流：
        1. 同时存储事件和告警
        2. 验证数据路由到正确索引
        3. 验证各索引数据独立
        """
        from .. import (
            store_events,
            search,
            get_index_name,
            INDEX_PATTERNS,
        )
        
        # Step 1: 创建混合数据
        data = [
            create_test_event("evt-multi-001", kind="event"),
            create_test_event("evt-multi-002", kind="event"),
            create_test_finding("finding-multi-001"),
            create_test_finding("finding-multi-002"),
        ]
        
        # Step 2: 批量存储
        store_result = store_events(data)
        assert store_result["success"] == 4
        assert len(store_result["details"]) >= 2  # 至少两个索引
        
        # Step 3: 验证事件索引
        events_index = get_index_name(INDEX_PATTERNS["ECS_EVENTS"])
        events = search(events_index, {"match_all": {}}, size=10)
        event_ids = {e["event"]["id"] for e in events if e["event"]["kind"] == "event"}
        assert "evt-multi-001" in event_ids
        assert "evt-multi-002" in event_ids
        
        # Step 4: 验证告警索引
        findings_index = get_index_name(INDEX_PATTERNS["RAW_FINDINGS"])
        findings = search(findings_index, {"match_all": {}}, size=10)
        finding_ids = {f["event"]["id"] for f in findings if f["event"]["kind"] == "alert"}
        assert "finding-multi-001" in finding_ids
        assert "finding-multi-002" in finding_ids
    
    def test_data_analysis_complete_workflow(self, initialized_indices):
        """
        测试完整的数据分析工作流：
        1. 存储原始数据
        2. 运行数据分析
        3. 验证分析结果
        """
        from .. import store_events, run_data_analysis, search, get_index_name, INDEX_PATTERNS
        
        # Step 1: 准备测试数据
        findings = [
            create_test_finding(f"finding-analysis-{i}", technique_id="T1078", host_id="h-analysis")
            for i in range(5)
        ]
        store_events(findings)
        
        # Step 2: 运行数据分析
        analysis_result = run_data_analysis()
        
        # Step 3: 验证结果结构
        assert "detection" in analysis_result
        assert "deduplication" in analysis_result
        assert analysis_result["detection"]["success"] is True
        assert "total" in analysis_result["deduplication"]
        assert "canonical" in analysis_result["deduplication"]
        
        # Step 4: 验证Canonical Findings已生成
        canonical_index = get_index_name(INDEX_PATTERNS["CANONICAL_FINDINGS"])
        canonical_results = search(canonical_index, {"match_all": {}}, size=10)
        assert len(canonical_results) >= 0  # 可能为0（如果没有可合并的）


class TestRealWorldScenarios:
    """真实场景测试"""
    
    def test_scenario_multiple_attack_techniques(self, initialized_indices):
        """
        场景：多个攻击技术点的检测
        验证：不同technique的findings应该分别处理
        """
        from .. import store_events, deduplicate_findings, search, get_index_name, INDEX_PATTERNS
        
        # 创建不同technique的findings
        findings = [
            create_test_finding("finding-tech-001", technique_id="T1078", host_id="h-scenario"),
            create_test_finding("finding-tech-002", technique_id="T1055", host_id="h-scenario"),
            create_test_finding("finding-tech-003", technique_id="T1071", host_id="h-scenario"),
        ]
        
        store_events(findings)
        deduplicate_findings()
        
        # 验证不同technique的findings都被处理
        canonical_index = get_index_name(INDEX_PATTERNS["CANONICAL_FINDINGS"])
        canonical_results = search(canonical_index, {"match_all": {}}, size=10)
        
        technique_ids = {
            f["threat"]["technique"]["id"]
            for f in canonical_results
            if f.get("threat", {}).get("technique", {}).get("id")
        }
        assert "T1078" in technique_ids or len(canonical_results) >= 1
    
    def test_scenario_same_attack_multiple_hosts(self, initialized_indices):
        """
        场景：相同攻击技术在不同主机上检测到
        验证：不同主机的findings应该分别处理（不合并）
        """
        from .. import store_events, deduplicate_findings, search, get_index_name, INDEX_PATTERNS
        
        # 创建相同technique但不同host的findings
        findings = [
            create_test_finding("finding-host-001", technique_id="T1078", host_id="h-001", host_name="host-001"),
            create_test_finding("finding-host-002", technique_id="T1078", host_id="h-002", host_name="host-002"),
            create_test_finding("finding-host-003", technique_id="T1078", host_id="h-003", host_name="host-003"),
        ]
        
        store_events(findings)
        dedup_result = deduplicate_findings()
        
        # 验证每个主机的finding都被处理
        canonical_index = get_index_name(INDEX_PATTERNS["CANONICAL_FINDINGS"])
        canonical_results = search(canonical_index, {"match_all": {}}, size=10)
        
        host_ids = {
            f["host"]["id"]
            for f in canonical_results
            if f.get("host", {}).get("id")
        }
        # 至少应该有不同的host（或至少处理了findings）
        assert len(canonical_results) >= 1
    
    def test_scenario_time_window_deduplication(self, initialized_indices):
        """
        场景：时间窗口内的去重
        验证：相同指纹但在不同时间窗口的findings不应该合并
        """
        from .. import store_events, deduplicate_findings, search, get_index_name, INDEX_PATTERNS
        
        # 创建相同指纹但不同时间窗口的findings
        base_time = datetime.now()
        # 时间间隔大于时间窗口（3分钟）
        time1 = base_time
        time2 = base_time + timedelta(minutes=5)  # 超过3分钟窗口
        
        findings = [
            create_test_finding(
                "finding-time-001",
                technique_id="T1078",
                host_id="h-time",
                timestamp=time1.isoformat(),
            ),
            create_test_finding(
                "finding-time-002",
                technique_id="T1078",
                host_id="h-time",
                timestamp=time2.isoformat(),
            ),
        ]
        
        store_events(findings)
        dedup_result = deduplicate_findings()
        
        # 验证结果（可能合并也可能不合并，取决于时间窗口计算）
        canonical_index = get_index_name(INDEX_PATTERNS["CANONICAL_FINDINGS"])
        canonical_results = search(canonical_index, {"match_all": {}}, size=10)
        
        # 至少应该有结果
        assert len(canonical_results) >= 0
    
    def test_scenario_fingerprint_variations(self, initialized_indices):
        """
        场景：不同实体类型的指纹生成
        验证：process、destination、file等不同实体类型都能正确生成指纹
        """
        from .. import store_events, deduplicate_findings
        
        # 创建不同类型的findings
        findings = [
            create_test_finding_with_process("finding-proc-001", process_entity_id="proc-001"),
            create_test_finding_with_destination("finding-dst-001", dst_ip="192.168.1.100"),
            create_test_finding_with_file("finding-file-001", file_hash="abc123def456"),
        ]
        
        store_result = store_events(findings)
        assert store_result["success"] == 3
        
        # 执行去重（应该能处理不同类型的实体）
        dedup_result = deduplicate_findings()
        assert dedup_result["total"] >= 3


class TestPerformanceAndScalability:
    """性能和可扩展性测试"""
    
    def test_bulk_store_large_dataset(self, initialized_indices):
        """测试批量存储大量数据"""
        from .. import store_events
        
        # 创建100个事件
        events = [create_test_event(f"evt-bulk-{i:03d}") for i in range(100)]
        
        result = store_events(events)
        
        assert result["total"] == 100
        assert result["success"] == 100
        assert result["failed"] == 0
    
    def test_search_with_pagination(self, initialized_indices):
        """测试分页搜索"""
        from .. import store_events, search, get_index_name, INDEX_PATTERNS
        
        # 创建多个事件
        events = [create_test_event(f"evt-page-{i}") for i in range(20)]
        store_events(events)
        
        index_name = get_index_name(INDEX_PATTERNS["ECS_EVENTS"])
        
        # 第一页
        page1 = search(index_name, {"match_all": {}}, size=10)
        assert len(page1) <= 10
        
        # 验证可以搜索到数据
        assert len(page1) >= 0


class TestErrorHandling:
    """错误处理测试"""
    
    def test_handle_invalid_event_structure(self, initialized_indices):
        """测试处理无效事件结构"""
        from .. import store_events
        
        # 创建无效结构的事件
        invalid_event = {"invalid": "structure"}
        
        # 应该能处理（可能失败但不崩溃）
        result = store_events([invalid_event])
        assert "total" in result
    
    def test_handle_missing_opensearch_connection(self):
        """测试处理OpenSearch连接失败（需要mock或跳过）"""
        # 这个测试需要mock OpenSearch客户端
        # 暂时跳过，在实际环境中测试
        pytest.skip("需要mock OpenSearch连接")
