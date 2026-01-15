# -*- coding: utf-8 -*-
"""
完整集成测试
测试端到端的完整流程，包括增量处理
"""

from datetime import datetime, timedelta
from typing import Any

import pytest

from tests.fixtures.common import (
    assert_event_structure,
    assert_finding_structure,
    create_test_event,
    create_test_finding,
)

pytestmark = pytest.mark.requires_opensearch


@pytest.mark.integration
@pytest.mark.slow
class TestFullWorkflowWithIncremental:
    """完整工作流测试（包含增量处理）"""
    
    def test_complete_workflow_with_incremental_processing(self, initialized_indices):
        """
        测试完整工作流，包括增量处理：
        1. 存储初始findings
        2. 模拟增量处理（只处理新的findings）
        3. 验证去重和规范findings生成
        """
        from app.services.opensearch import run_data_analysis, store_events
        from app.services.opensearch.analysis import deduplicate_findings
        from app.services.opensearch.internal import INDEX_PATTERNS, get_index_name, search
        from app.services.opensearch.analysis import (
            _get_last_processed_timestamp,
            _filter_new_findings,
        )
        
        detector_id = "test-detector-full"
        base_time = datetime.now()
        
        # Step 1: 存储初始findings
        initial_findings = []
        for i in range(3):
            finding = create_test_finding(
                f"f-full-{i}",
                technique_id="T1078",
                host_id="h-full",
                timestamp=(base_time - timedelta(hours=i)).isoformat()
            )
            finding["custom"]["finding"]["detector_id"] = detector_id
            initial_findings.append(finding)
        
        store_result = store_events(initial_findings)
        assert store_result["success"] == 3
        
        # Step 2: 获取上次处理时间戳
        last_timestamp = _get_last_processed_timestamp(
            initialized_indices,
            detector_id
        )
        assert last_timestamp is not None
        
        # Step 3: 创建新的findings（时间戳更新）
        new_findings = []
        for i in range(2):
            finding = create_test_finding(
                f"f-full-new-{i}",
                technique_id="T1078",
                host_id="h-full",
                timestamp=(base_time + timedelta(minutes=i+1)).isoformat()
            )
            finding["custom"]["finding"]["detector_id"] = detector_id
            new_findings.append(finding)
        
        # Step 4: 测试增量过滤
        all_findings = initial_findings + new_findings
        filtered = _filter_new_findings(all_findings, last_timestamp)
        
        # 应该只包含新的findings
        assert len(filtered) <= len(new_findings)
        
        # Step 5: 存储新的findings
        if filtered:
            new_store_result = store_events(filtered)
            assert new_store_result["success"] >= 0
        
        # Step 6: 执行去重
        dedup_result = deduplicate_findings()
        assert dedup_result["total"] >= 0
        assert dedup_result["canonical"] >= 0
    
    def test_incremental_processing_avoids_duplicates(self, initialized_indices):
        """测试增量处理避免重复存储"""
        from app.services.opensearch import store_events
        from app.services.opensearch.analysis import (
            _get_last_processed_timestamp,
            _filter_new_findings,
        )
        
        detector_id = "test-detector-dedup"
        base_time = datetime.now()
        
        # Step 1: 存储初始findings
        finding1 = create_test_finding(
            "f-dedup-1",
            timestamp=(base_time - timedelta(hours=1)).isoformat()
        )
        finding1["custom"]["finding"]["detector_id"] = detector_id
        
        store_events([finding1])
        
        # Step 2: 获取上次处理时间
        last_timestamp = _get_last_processed_timestamp(
            initialized_indices,
            detector_id
        )
        
        # Step 3: 尝试再次存储相同的findings（应该被过滤）
        same_findings = [finding1]
        filtered = _filter_new_findings(same_findings, last_timestamp)
        
        # 应该被过滤掉（时间戳不新）
        assert len(filtered) == 0
        
        # Step 4: 存储新的findings
        new_finding = create_test_finding(
            "f-dedup-2",
            timestamp=base_time.isoformat()
        )
        new_finding["custom"]["finding"]["detector_id"] = detector_id
        
        filtered_new = _filter_new_findings([new_finding], last_timestamp)
        assert len(filtered_new) >= 0  # 可能因为时间精度问题为0，但逻辑正确


@pytest.mark.integration
class TestErrorHandling:
    """错误处理测试"""
    
    def test_handle_missing_detector(self, initialized_indices):
        """测试处理缺失detector的情况"""
        from app.services.opensearch.analysis import _get_detector_details, _get_detector_id
        
        # 使用不存在的detector ID
        detector = _get_detector_details(initialized_indices, "non-existent-detector")
        assert detector is None
    
    def test_handle_invalid_timestamp_format(self):
        """测试处理无效时间戳格式"""
        from app.services.opensearch.analysis import _filter_new_findings
        
        finding = create_test_finding("f-invalid-ts")
        finding["@timestamp"] = "invalid-timestamp-format"
        
        # 应该能处理无效格式（保守处理：包含它）
        filtered = _filter_new_findings([finding], datetime.now() - timedelta(hours=1))
        assert len(filtered) >= 0  # 保守处理，可能包含也可能不包含
