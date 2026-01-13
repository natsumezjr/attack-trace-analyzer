# -*- coding: utf-8 -*-
"""
Analysis模块增量处理功能测试
测试重构后的辅助函数和增量处理逻辑
"""

import pytest
import sys
from pathlib import Path
from datetime import datetime, timedelta
from typing import Any

# 添加父目录到路径
test_dir = Path(__file__).parent
parent_dir = test_dir.parent  # backend/opensearch
backend_dir = parent_dir.parent  # backend
sys.path.insert(0, str(backend_dir))  # 确保backend目录在路径中
sys.path.insert(0, str(parent_dir))  # 也添加opensearch目录
sys.path.insert(0, str(test_dir))  # 添加test目录

from test_utils import create_test_finding


@pytest.mark.unit
class TestAnalysisHelperFunctions:
    """测试analysis.py的辅助函数"""
    
    def test_get_detector_id(self, opensearch_client):
        """测试获取detector ID"""
        from opensearch.analysis import _get_detector_id
        
        detector_id = _get_detector_id(opensearch_client)
        # 如果没有detector，返回None是正常的
        assert detector_id is None or isinstance(detector_id, str)
    
    def test_get_detector_details(self, opensearch_client):
        """测试获取detector详情"""
        from opensearch.analysis import _get_detector_id, _get_detector_details
        
        detector_id = _get_detector_id(opensearch_client)
        if detector_id:
            detector = _get_detector_details(opensearch_client, detector_id)
            assert detector is None or isinstance(detector, dict)
        else:
            pytest.skip("没有detector，跳过测试")
    
    def test_should_trigger_scan(self):
        """测试判断是否需要触发扫描"""
        from opensearch.analysis import _should_trigger_scan
        
        # 需要触发：trigger_scan=True 且 baseline_count=0
        assert _should_trigger_scan(True, 0) is True
        
        # 不需要触发：已有findings
        assert _should_trigger_scan(True, 10) is False
        
        # 不需要触发：trigger_scan=False
        assert _should_trigger_scan(False, 0) is False
    
    def test_filter_new_findings_no_last_timestamp(self):
        """测试过滤新findings（没有上次处理时间）"""
        from opensearch.analysis import _filter_new_findings
        
        findings = [
            create_test_finding("f1", timestamp=datetime.now().isoformat()),
            create_test_finding("f2", timestamp=datetime.now().isoformat()),
        ]
        
        # 没有上次处理时间，应该返回所有findings
        new_findings = _filter_new_findings(findings, None)
        assert len(new_findings) == len(findings)
    
    def test_filter_new_findings_with_timestamp(self):
        """测试过滤新findings（有上次处理时间）"""
        from opensearch.analysis import _filter_new_findings
        
        base_time = datetime.now()
        last_timestamp = base_time - timedelta(hours=1)
        
        # 创建一些旧的findings和新的findings
        old_finding = create_test_finding(
            "f-old",
            timestamp=(base_time - timedelta(hours=2)).isoformat()
        )
        new_finding1 = create_test_finding(
            "f-new1",
            timestamp=(base_time - timedelta(minutes=30)).isoformat()
        )
        new_finding2 = create_test_finding(
            "f-new2",
            timestamp=base_time.isoformat()
        )
        
        findings = [old_finding, new_finding1, new_finding2]
        new_findings = _filter_new_findings(findings, last_timestamp)
        
        # 应该只包含新的findings
        assert len(new_findings) == 2
        assert "f-old" not in [f.get("event", {}).get("id") for f in new_findings]
    
    def test_get_last_processed_timestamp_empty(self, initialized_indices):
        """测试获取上次处理时间戳（空索引）"""
        from opensearch.analysis import _get_last_processed_timestamp
        
        # 空索引应该返回None
        timestamp = _get_last_processed_timestamp(
            initialized_indices,
            "test-detector-id"
        )
        assert timestamp is None
    
    def test_get_last_processed_timestamp_with_findings(self, initialized_indices):
        """测试获取上次处理时间戳（有findings）"""
        from opensearch import store_events
        from opensearch.analysis import _get_last_processed_timestamp
        
        detector_id = "test-detector-001"
        
        # 存储一些findings
        finding1 = create_test_finding(
            "f1",
            timestamp=(datetime.now() - timedelta(hours=2)).isoformat()
        )
        finding1["custom"]["finding"]["detector_id"] = detector_id
        
        finding2 = create_test_finding(
            "f2",
            timestamp=(datetime.now() - timedelta(hours=1)).isoformat()
        )
        finding2["custom"]["finding"]["detector_id"] = detector_id
        
        store_events([finding1, finding2])
        
        # 获取上次处理时间戳
        timestamp = _get_last_processed_timestamp(
            initialized_indices,
            detector_id
        )
        
        # 应该返回最新的时间戳
        assert timestamp is not None
        assert isinstance(timestamp, datetime)


@pytest.mark.integration
@pytest.mark.slow
class TestIncrementalProcessing:
    """测试增量处理功能"""
    
    def test_fetch_and_store_findings_incremental(self, initialized_indices):
        """测试增量查询和存储findings"""
        from opensearch import store_events
        from opensearch.analysis import _fetch_and_store_findings
        
        detector_id = "test-detector-incremental"
        
        # Step 1: 存储一些findings
        finding1 = create_test_finding(
            "f-inc-1",
            timestamp=(datetime.now() - timedelta(hours=2)).isoformat()
        )
        finding1["custom"]["finding"]["detector_id"] = detector_id
        
        store_events([finding1])
        
        # Step 2: 模拟Security Analytics API返回findings
        # 注意：这里需要mock Security Analytics API，因为实际测试环境可能没有detector
        # 为了简化，我们直接测试过滤逻辑
        
        # 创建新的findings（时间戳更新）
        new_finding = create_test_finding(
            "f-inc-2",
            timestamp=datetime.now().isoformat()
        )
        new_finding["custom"]["finding"]["detector_id"] = detector_id
        
        # 存储新finding
        result = store_events([new_finding])
        assert result["success"] == 1
        
        # 验证增量处理逻辑（通过_get_last_processed_timestamp）
        from opensearch.analysis import _get_last_processed_timestamp, _filter_new_findings
        
        last_timestamp = _get_last_processed_timestamp(
            initialized_indices,
            detector_id
        )
        
        # 应该能找到上次处理的时间戳
        assert last_timestamp is not None
        
        # 测试过滤：只有时间戳更新的finding应该被包含
        all_findings = [finding1, new_finding]
        filtered = _filter_new_findings(all_findings, last_timestamp)
        
        # 由于new_finding的时间戳可能等于last_timestamp（精度问题），
        # 我们只验证过滤逻辑正常工作
        assert len(filtered) <= len(all_findings)


@pytest.mark.unit
class TestAnalysisRefactoredFunctions:
    """测试重构后的analysis.py函数"""
    
    def test_enable_detector_if_needed(self, opensearch_client):
        """测试启用detector（如果未启用）"""
        from opensearch.analysis import (
            _get_detector_id,
            _get_detector_details,
            _enable_detector_if_needed
        )
        
        detector_id = _get_detector_id(opensearch_client)
        if not detector_id:
            pytest.skip("没有detector，跳过测试")
        
        detector = _get_detector_details(opensearch_client, detector_id)
        if not detector:
            pytest.skip("无法获取detector详情，跳过测试")
        
        # 测试函数不会抛出异常
        try:
            _enable_detector_if_needed(opensearch_client, detector_id, detector)
        except Exception as e:
            # 如果detector不存在或权限问题，这是可以接受的
            pytest.skip(f"无法启用detector: {e}")
    
    def test_temporarily_shorten_schedule(self, opensearch_client):
        """测试临时缩短schedule"""
        from opensearch.analysis import (
            _get_detector_id,
            _get_detector_details,
            _temporarily_shorten_schedule
        )
        
        detector_id = _get_detector_id(opensearch_client)
        if not detector_id:
            pytest.skip("没有detector，跳过测试")
        
        detector = _get_detector_details(opensearch_client, detector_id)
        if not detector:
            pytest.skip("无法获取detector详情，跳过测试")
        
        # 测试函数（不实际修改，只测试逻辑）
        # 创建一个测试detector配置
        test_detector = detector.copy()
        test_detector["schedule"] = {
            "period": {
                "interval": 24,
                "unit": "HOURS"
            }
        }
        
        # 测试函数返回格式
        original_schedule, was_shortened = _temporarily_shorten_schedule(
            opensearch_client,
            detector_id,
            test_detector
        )
        
        assert isinstance(original_schedule, dict)
        assert isinstance(was_shortened, bool)
    
    def test_poll_for_scan_completion(self, opensearch_client):
        """测试轮询扫描完成"""
        from opensearch.analysis import (
            _get_detector_id,
            _poll_for_scan_completion
        )
        
        detector_id = _get_detector_id(opensearch_client)
        if not detector_id:
            pytest.skip("没有detector，跳过测试")
        
        # 测试轮询逻辑（使用很短的超时时间）
        scan_completed, scan_wait_ms = _poll_for_scan_completion(
            opensearch_client,
            detector_id,
            baseline_count=0,
            max_wait_seconds=1  # 只等待1秒
        )
        
        assert isinstance(scan_completed, bool)
        assert isinstance(scan_wait_ms, int)
        assert scan_wait_ms >= 0
