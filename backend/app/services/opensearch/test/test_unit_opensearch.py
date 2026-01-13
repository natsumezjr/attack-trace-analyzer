# -*- coding: utf-8 -*-
"""
OpenSearch 模块单元测试
黑盒测试：只关注输入输出，不关注内部实现

测试覆盖：
1. 客户端操作（client.py）
2. 索引管理（index.py）
3. 存储功能（storage.py）
4. 数据分析（analysis.py）
"""

import pytest
import sys
from pathlib import Path
from datetime import datetime
from typing import Any

# 添加父目录到路径，以便导入 opensearch 模块
test_dir = Path(__file__).parent
parent_dir = test_dir.parent
sys.path.insert(0, str(parent_dir))

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


# ========== 客户端操作测试 ==========

class TestClientOperations:
    """测试客户端基础操作"""
    
    def test_get_client(self, opensearch_client):
        """测试获取客户端"""
        from .. import get_client
        client = get_client()
        assert client is not None
        assert client == opensearch_client  # 单例模式
    
    def test_index_exists(self, initialized_indices):
        """测试检查索引是否存在"""
        from .. import index_exists, get_index_name, INDEX_PATTERNS
        today = datetime.now()
        index_name = get_index_name(INDEX_PATTERNS["ECS_EVENTS"], today)
        
        # 索引应该存在（已初始化）
        assert index_exists(index_name) is True
        
        # 不存在的索引应该返回 False
        assert index_exists("non-existent-index-12345") is False
    
    def test_search_empty_index(self, initialized_indices):
        """测试搜索空索引"""
        from .. import search, get_index_name, INDEX_PATTERNS
        today = datetime.now()
        index_name = get_index_name(INDEX_PATTERNS["ECS_EVENTS"], today)
        
        results = search(index_name, {"match_all": {}}, size=10)
        assert isinstance(results, list)
        assert len(results) == 0
    
    def test_get_document_not_exists(self, initialized_indices):
        """测试获取不存在的文档"""
        from .. import get_document, get_index_name, INDEX_PATTERNS
        today = datetime.now()
        index_name = get_index_name(INDEX_PATTERNS["ECS_EVENTS"], today)
        
        doc = get_document(index_name, "non-existent-id")
        assert doc is None


# ========== 索引管理测试 ==========

class TestIndexManagement:
    """测试索引管理功能"""
    
    def test_get_index_name(self):
        """测试生成索引名（带日期后缀）"""
        from ...index import get_index_name, INDEX_PATTERNS
        
        today = datetime.now()
        index_name = get_index_name(INDEX_PATTERNS["ECS_EVENTS"], today)
        
        assert index_name.startswith("ecs-events-")
        assert today.strftime("%Y.%m.%d") in index_name
    
    def test_get_index_name_default_date(self):
        """测试生成索引名（使用默认日期）"""
        from ...index import get_index_name, INDEX_PATTERNS
        
        index_name = get_index_name(INDEX_PATTERNS["ECS_EVENTS"])
        
        assert index_name.startswith("ecs-events-")
        assert datetime.now().strftime("%Y.%m.%d") in index_name
    
    def test_hash_token(self):
        """测试token哈希生成"""
        from ...index import hash_token
        
        token = "test-token-123"
        hash1 = hash_token(token)
        hash2 = hash_token(token)
        
        # 相同输入应该产生相同输出
        assert hash1 == hash2
        # 哈希应该是64字符的十六进制字符串
        assert len(hash1) == 64
        assert all(c in "0123456789abcdef" for c in hash1)
    
    def test_initialize_indices(self, clean_test_indices):
        """测试初始化所有索引"""
        from .. import initialize_indices, index_exists, get_index_name, INDEX_PATTERNS
        
        initialize_indices()
        
        today = datetime.now()
        # 检查所有索引是否创建成功
        assert index_exists(get_index_name(INDEX_PATTERNS["ECS_EVENTS"], today))
        assert index_exists(get_index_name(INDEX_PATTERNS["RAW_FINDINGS"], today))
        assert index_exists(get_index_name(INDEX_PATTERNS["CANONICAL_FINDINGS"], today))
        assert index_exists(get_index_name(INDEX_PATTERNS["ATTACK_CHAINS"], today))
        assert index_exists(INDEX_PATTERNS["CLIENT_REGISTRY"])


# ========== 存储功能测试 ==========

class TestStorageOperations:
    """测试存储功能（黑盒测试）"""
    
    def test_route_to_index_event(self):
        """测试事件路由到ecs-events索引"""
        from ...storage import route_to_index
        
        event = create_test_event("evt-001", kind="event")
        index_name = route_to_index(event)
        
        assert "ecs-events" in index_name
    
    def test_route_to_index_raw_finding(self):
        """测试原始告警路由到raw-findings索引"""
        from ...storage import route_to_index
        
        finding = create_test_finding("finding-001")
        index_name = route_to_index(finding)
        
        assert "raw-findings" in index_name
    
    def test_route_to_index_canonical_finding(self):
        """测试规范告警路由到canonical-findings索引"""
        from ...storage import route_to_index
        
        finding = create_test_finding("finding-001")
        finding["event"]["dataset"] = "finding.canonical"
        index_name = route_to_index(finding)
        
        assert "canonical-findings" in index_name
    
    def test_store_single_event(self, initialized_indices):
        """测试存储单个事件"""
        from .. import store_events
        
        event = create_test_event("evt-unit-001")
        result = store_events([event])
        
        assert result["total"] == 1
        assert result["success"] == 1
        assert result["failed"] == 0
        assert result["duplicated"] == 0
    
    def test_store_multiple_events(self, initialized_indices):
        """测试批量存储多个事件"""
        from .. import store_events
        
        events = [
            create_test_event("evt-unit-002"),
            create_test_event("evt-unit-003"),
            create_test_finding("finding-unit-001"),
            create_test_finding("finding-unit-002"),
        ]
        
        result = store_events(events)
        
        assert result["total"] == 4
        assert result["success"] == 4
        assert result["failed"] == 0
        assert result["duplicated"] == 0
        assert len(result["details"]) > 0
    
    def test_store_duplicate_event(self, initialized_indices):
        """测试存储重复事件（去重）"""
        from .. import store_events
        
        event = create_test_event("evt-unit-duplicate")
        
        # 第一次存储
        result1 = store_events([event])
        assert result1["success"] == 1
        assert result1["duplicated"] == 0
        
        # 第二次存储相同事件
        result2 = store_events([event])
        assert result2["success"] == 0
        assert result2["duplicated"] == 1
    
    def test_store_empty_list(self, initialized_indices):
        """测试存储空列表"""
        from .. import store_events
        
        result = store_events([])
        
        assert result["total"] == 0
        assert result["success"] == 0
        assert result["failed"] == 0
        assert result["duplicated"] == 0
    
    def test_store_event_without_id(self, initialized_indices):
        """测试存储没有event.id的事件（应该失败或使用自动ID）"""
        from .. import store_events
        
        event = create_test_event("evt-no-id")
        del event["event"]["id"]
        
        # 根据实现，可能失败或使用自动生成的ID
        result = store_events([event])
        # 这里只验证函数不会抛出异常
        assert "total" in result


# ========== 数据分析测试 ==========

class TestAnalysisOperations:
    """测试数据分析功能（黑盒测试）"""
    
    def test_generate_fingerprint_basic(self):
        """测试生成基本指纹"""
        from ...analysis import generate_fingerprint
        
        finding = create_test_finding("finding-001", technique_id="T1078", host_id="h-001")
        fingerprint = generate_fingerprint(finding)
        
        assert "T1078" in fingerprint
        assert "h-001" in fingerprint
        assert "|" in fingerprint  # 分隔符
    
    def test_generate_fingerprint_with_process(self):
        """测试生成带进程的指纹"""
        from ...analysis import generate_fingerprint
        
        finding = create_test_finding_with_process("finding-002", process_entity_id="proc-001")
        fingerprint = generate_fingerprint(finding)
        
        assert "proc-001" in fingerprint
    
    def test_generate_fingerprint_with_destination(self):
        """测试生成带目标IP的指纹"""
        from ...analysis import generate_fingerprint
        
        finding = create_test_finding_with_destination("finding-003", dst_ip="192.168.1.100")
        fingerprint = generate_fingerprint(finding)
        
        assert "192.168.1.100" in fingerprint
    
    def test_generate_fingerprint_with_file(self):
        """测试生成带文件哈希的指纹"""
        from ...analysis import generate_fingerprint
        
        finding = create_test_finding_with_file("finding-004", file_hash="abc123")
        fingerprint = generate_fingerprint(finding)
        
        assert "abc123" in fingerprint
    
    def test_extract_provider_from_custom(self):
        """测试从custom字段提取provider"""
        from ...analysis import extract_provider
        
        finding = create_test_finding("finding-005")
        finding["custom"]["finding"]["providers"] = ["wazuh", "falco"]
        
        provider = extract_provider(finding)
        assert provider == "wazuh"  # 应该取第一个
    
    def test_extract_provider_from_rule_id(self):
        """测试从rule.id推断provider"""
        from ...analysis import extract_provider
        
        finding = create_test_finding("finding-006")
        finding["rule"]["id"] = "wazuh-rule-001"
        # 移除 custom.finding.providers，确保从 rule.id 推断
        if "custom" in finding and "finding" in finding["custom"]:
            finding["custom"]["finding"].pop("providers", None)
        
        provider = extract_provider(finding)
        assert provider == "wazuh"
    
    def test_merge_findings_single(self):
        """测试合并单个finding（应该直接转换）"""
        from ...analysis import merge_findings
        
        finding = create_test_finding("finding-007")
        merged = merge_findings([finding])
        
        assert merged["custom"]["finding"]["stage"] == "canonical"
        assert "providers" in merged["custom"]["finding"]
    
    def test_merge_findings_multiple(self):
        """测试合并多个findings"""
        from ...analysis import merge_findings
        
        findings = [
            create_test_finding("finding-008", provider="wazuh"),
            create_test_finding("finding-009", provider="falco"),
        ]
        # 设置相同的technique和host，使它们可以合并
        for f in findings:
            f["threat"]["technique"]["id"] = "T1078"
            f["host"]["id"] = "h-001"
        
        merged = merge_findings(findings)
        
        assert merged["custom"]["finding"]["stage"] == "canonical"
        providers = merged["custom"]["finding"]["providers"]
        assert len(providers) >= 2  # 应该包含多个provider
    
    def test_merge_findings_empty_list(self):
        """测试合并空列表（应该抛出异常）"""
        from ...analysis import merge_findings
        
        with pytest.raises(ValueError, match="无法合并空数组"):
            merge_findings([])
    
    def test_deduplicate_findings_empty(self, initialized_indices):
        """测试去重空索引"""
        from .. import deduplicate_findings
        
        result = deduplicate_findings()
        
        assert result["total"] == 0
        assert result["merged"] == 0
        assert result["canonical"] == 0
        assert result["errors"] == 0
    
    def test_deduplicate_findings_with_data(self, initialized_indices):
        """测试去重有数据的索引"""
        from .. import store_events, deduplicate_findings
        
        # 创建多个相似的findings（相同technique和host）
        findings = []
        for i in range(3):
            finding = create_test_finding(
                f"finding-dedup-{i}",
                technique_id="T1078",
                host_id="h-dedup",
                timestamp=datetime.now().isoformat(),  # 相同时间窗口
            )
            findings.append(finding)
        
        # 存储findings
        store_events(findings)
        
        # 执行去重
        result = deduplicate_findings()
        
        assert result["total"] >= 3
        assert result["canonical"] > 0
    
    def test_run_security_analytics(self, initialized_indices):
        """测试运行Security Analytics（当前为MVP版本）"""
        from .. import run_security_analytics
        
        result = run_security_analytics()
        
        assert "success" in result
        assert "message" in result
        # MVP版本应该返回提示信息
        assert result["success"] is True
    
    def test_run_data_analysis(self, initialized_indices):
        """测试运行完整数据分析流程"""
        from .. import run_data_analysis
        
        result = run_data_analysis()
        
        assert "detection" in result
        assert "deduplication" in result
        assert "success" in result["detection"]
        assert "total" in result["deduplication"]


# ========== 边界条件测试 ==========

class TestEdgeCases:
    """测试边界条件和异常情况"""
    
    def test_store_event_missing_required_fields(self, initialized_indices):
        """测试存储缺少必需字段的事件"""
        from .. import store_events
        
        # 创建缺少必需字段的事件
        event = {"@timestamp": datetime.now().isoformat()}
        
        # 根据实现，可能失败或使用默认值
        result = store_events([event])
        # 只验证函数不会崩溃
        assert "total" in result
    
    def test_search_with_complex_query(self, initialized_indices):
        """测试复杂查询"""
        from .. import search, get_index_name, INDEX_PATTERNS
        
        index_name = get_index_name(INDEX_PATTERNS["ECS_EVENTS"])
        
        # 复杂查询：范围查询 + 匹配查询
        query = {
            "bool": {
                "must": [
                    {"match": {"host.name": "test-host"}},
                ],
                "filter": [
                    {"range": {"@timestamp": {"gte": "2024-01-01"}}},
                ],
            }
        }
        
        results = search(index_name, query, size=10)
        assert isinstance(results, list)
    
    def test_fingerprint_with_missing_fields(self):
        """测试生成缺少字段的指纹"""
        from ...analysis import generate_fingerprint
        
        # 创建缺少关键字段的finding
        finding = {
            "@timestamp": datetime.now().isoformat(),
            "threat": {"technique": {"id": "T1078"}},
        }
        
        fingerprint = generate_fingerprint(finding)
        # 应该能处理缺失字段，使用"unknown"作为默认值
        assert "unknown" in fingerprint or "T1078" in fingerprint
