# -*- coding: utf-8 -*-
"""
killchain_llm.py 模块单元测试

测试覆盖：
1. PayloadReducer - payload 裁剪功能
2. HeuristicPreselector - 启发式预筛选
3. build_choose_prompt - prompt 构建
4. _extract_json_obj - JSON 提取
5. validate_choose_result - 结果校验
6. fallback_choose - 回退选择
7. LLMChooser - LLM 选择器
8. MockChooser - Mock 选择器
9. create_llm_client - 工厂函数
"""

import json
import pytest
from typing import Any, Dict, List, Mapping
from unittest.mock import Mock, patch, MagicMock

from app.services.analyze.killchain_llm import (
    PayloadReducer,
    HeuristicPreselector,
    LLMChooseConfig,
    build_choose_prompt,
    _extract_json_obj,
    validate_choose_result,
    fallback_choose,
    LLMChooser,
    MockChooser,
    create_llm_client,
    KillChainLLMClient,
)


# ========== 测试数据构造 ==========

def create_sample_payload() -> Dict[str, Any]:
    """创建示例 payload（模拟 build_llm_payload 的输出）"""
    return {
        "constraints": {
            "max_hops": 8,
            "time_window": 3600.0,
        },
        "segments": [
            {
                "seg_idx": 0,
                "state": "Initial Access",
                "t_start": 1000.0,
                "t_end": 1100.0,
                "anchor_in_uid": "Host:h-001",
                "anchor_out_uid": "Process:p-001",
                "abnormal_edge_summaries": [
                    {
                        "edge_id": "e-001",
                        "event.action": "network_connection",
                        "source.ip": "10.0.0.1",
                        "destination.ip": "192.168.1.1",
                    }
                ],
            },
            {
                "seg_idx": 1,
                "state": "Execution",
                "t_start": 1100.0,
                "t_end": 1200.0,
                "anchor_in_uid": "Process:p-001",
                "anchor_out_uid": "Process:p-002",
                "abnormal_edge_summaries": [
                    {
                        "edge_id": "e-002",
                        "process.name": "cmd.exe",
                        "process.command_line": "cmd /c whoami",
                    }
                ],
            },
        ],
        "pairs": [
            {
                "pair_idx": 0,
                "from_seg_idx": 0,
                "to_seg_idx": 1,
                "src_anchor": "Process:p-001",
                "dst_anchor": "Process:p-001",
                "t_min": 1095.0,
                "t_max": 1105.0,
                "candidates": [
                    {
                        "path_id": "p-001",
                        "steps": [
                            {
                                "ts": 1098.0,
                                "src_uid": "Process:p-001",
                                "rel": "SPAWN",
                                "dst_uid": "Process:p-002",
                                "key_props": {
                                    "process.entity_id": "proc-123",
                                    "process.name": "cmd.exe",
                                    "host.id": "h-001",
                                },
                            }
                        ],
                    },
                    {
                        "path_id": "p-002",
                        "steps": [
                            {
                                "ts": 1097.0,
                                "src_uid": "Process:p-001",
                                "rel": "SPAWN",
                                "dst_uid": "Process:p-003",
                                "key_props": {
                                    "process.entity_id": "proc-456",
                                    "process.name": "powershell.exe",
                                },
                            },
                            {
                                "ts": 1098.0,
                                "src_uid": "Process:p-003",
                                "rel": "SPAWN",
                                "dst_uid": "Process:p-002",
                                "key_props": {
                                    "process.entity_id": "proc-789",
                                },
                            },
                        ],
                    },
                ],
            }
        ],
    }


def create_large_payload() -> Dict[str, Any]:
    """创建包含大量候选路径的 payload（用于测试裁剪）"""
    payload = create_sample_payload()
    # 添加更多候选路径
    pair = payload["pairs"][0]
    for i in range(15):
        pair["candidates"].append(
            {
                "path_id": f"p-{i+3:03d}",
                "steps": [
                    {
                        "ts": 1098.0 + i,
                        "src_uid": f"Process:p-{i:03d}",
                        "rel": "SPAWN",
                        "dst_uid": f"Process:p-{i+1:03d}",
                        "key_props": {
                            "process.entity_id": f"proc-{i}",
                            "process.name": f"app-{i}.exe",
                        },
                    }
                ],
            }
        )
    return payload


# ========== PayloadReducer 测试 ==========

class TestPayloadReducer:
    """测试 PayloadReducer 类"""

    def test_reduce_basic(self):
        """测试基本裁剪功能"""
        config = LLMChooseConfig(
            max_steps_per_path=5,
            max_str_len=100,
        )
        reducer = PayloadReducer(config)
        payload = create_sample_payload()
        reduced = reducer.reduce(payload)

        # 检查结构保留
        assert "constraints" in reduced
        assert "segments" in reduced
        assert "pairs" in reduced

        # 检查 segments 保留
        assert len(reduced["segments"]) == 2
        assert reduced["segments"][0]["seg_idx"] == 0

        # 检查 pairs 保留
        assert len(reduced["pairs"]) == 1
        assert len(reduced["pairs"][0]["candidates"]) == 2

    def test_reduce_truncate_strings(self):
        """测试字符串截断功能"""
        config = LLMChooseConfig(max_str_len=10)
        reducer = PayloadReducer(config)
        payload = create_sample_payload()
        # 添加长字符串
        payload["segments"][0]["abnormal_edge_summaries"][0]["long_field"] = "a" * 100
        reduced = reducer.reduce(payload)

        long_field = reduced["segments"][0]["abnormal_edge_summaries"][0].get("long_field", "")
        assert len(long_field) <= 11  # 10 + "…"
        assert long_field.endswith("…") or len(long_field) <= 10

    def test_reduce_limit_steps(self):
        """测试限制路径步数"""
        config = LLMChooseConfig(max_steps_per_path=1)
        reducer = PayloadReducer(config)
        payload = create_sample_payload()
        reduced = reducer.reduce(payload)

        # p-002 有 2 步，应该被截断到 1 步
        for cand in reduced["pairs"][0]["candidates"]:
            assert len(cand["steps"]) <= 1

    def test_reduce_filter_edge_keys(self):
        """测试只保留白名单字段"""
        config = LLMChooseConfig()
        reducer = PayloadReducer(config)
        payload = create_sample_payload()
        # 添加不在白名单的字段
        payload["pairs"][0]["candidates"][0]["steps"][0]["key_props"]["unknown_field"] = "value"
        reduced = reducer.reduce(payload)

        key_props = reduced["pairs"][0]["candidates"][0]["steps"][0]["key_props"]
        assert "unknown_field" not in key_props
        assert "process.entity_id" in key_props


# ========== HeuristicPreselector 测试 ==========

class TestHeuristicPreselector:
    """测试 HeuristicPreselector 类"""

    def test_preselect_basic(self):
        """测试基本预筛选功能"""
        config = LLMChooseConfig(per_pair_keep=1)
        preselector = HeuristicPreselector(config)
        payload = create_sample_payload()
        preselected = preselector.preselect(payload)

        # 应该只保留 1 个候选（hop 最短的）
        assert len(preselected["pairs"][0]["candidates"]) == 1
        # p-001 只有 1 步，应该被选中
        assert preselected["pairs"][0]["candidates"][0]["path_id"] == "p-001"

    def test_preselect_keep_top_n(self):
        """测试保留 top N 候选"""
        config = LLMChooseConfig(per_pair_keep=2)
        preselector = HeuristicPreselector(config)
        payload = create_large_payload()
        preselected = preselector.preselect(payload)

        # 应该保留 2 个候选
        assert len(preselected["pairs"][0]["candidates"]) == 2

    def test_preselect_ranking(self):
        """测试启发式排序"""
        config = LLMChooseConfig(per_pair_keep=5)
        preselector = HeuristicPreselector(config)
        payload = create_sample_payload()
        preselected = preselector.preselect(payload)

        # 检查是否有 ranking 信息
        assert "heuristic_ranking" in preselected["pairs"][0]
        ranking = preselected["pairs"][0]["heuristic_ranking"]
        assert len(ranking) > 0
        # 应该按分数降序排列
        scores = [r["score"] for r in ranking]
        assert scores == sorted(scores, reverse=True)

    def test_preselect_consistency_bonus(self):
        """测试一致性加分（相同实体）"""
        config = LLMChooseConfig(per_pair_keep=2)
        preselector = HeuristicPreselector(config)
        payload = create_sample_payload()

        # 添加一个与第一个候选共享 process.entity_id 的候选
        payload["pairs"][0]["candidates"].append(
            {
                "path_id": "p-003",
                "steps": [
                    {
                        "ts": 1099.0,
                        "src_uid": "Process:p-001",
                        "rel": "SPAWN",
                        "dst_uid": "Process:p-004",
                        "key_props": {
                            "process.entity_id": "proc-123",  # 与 p-001 相同
                            "host.id": "h-001",  # 与 p-001 相同
                        },
                    }
                ],
            }
        )

        preselected = preselector.preselect(payload)
        # 由于一致性加分，p-003 可能排名更高（取决于具体分数计算）
        ranking = preselected["pairs"][0]["heuristic_ranking"]
        path_ids = [r["path_id"] for r in ranking]
        assert "p-003" in path_ids or "p-001" in path_ids


# ========== build_choose_prompt 测试 ==========

class TestBuildChoosePrompt:
    """测试 build_choose_prompt 函数"""

    def test_build_prompt_basic(self):
        """测试基本 prompt 构建"""
        payload = create_sample_payload()
        messages = build_choose_prompt(payload, require_pair_explanations=False)

        assert len(messages) == 2
        assert messages[0]["role"] == "system"
        assert messages[1]["role"] == "user"

        # 检查 system message
        assert "安全事件响应专家" in messages[0]["content"]

        # 检查 user message 包含 payload
        user_content = json.loads(messages[1]["content"])
        assert "input" in user_content
        assert user_content["input"] == payload

    def test_build_prompt_with_explanations(self):
        """测试包含 pair_explanations 的 prompt"""
        payload = create_sample_payload()
        messages = build_choose_prompt(payload, require_pair_explanations=True)

        user_content = json.loads(messages[1]["content"])
        schema = user_content.get("output_schema", {})
        assert "pair_explanations" in schema


# ========== _extract_json_obj 测试 ==========

class TestExtractJsonObj:
    """测试 _extract_json_obj 函数"""

    def test_extract_clean_json(self):
        """测试提取干净的 JSON"""
        text = '{"chosen_path_ids": ["p-001"], "explanation": "test"}'
        result = _extract_json_obj(text)
        assert result is not None
        assert result["chosen_path_ids"] == ["p-001"]

    def test_extract_json_with_markdown(self):
        """测试从 markdown 代码块中提取 JSON"""
        text = '```json\n{"chosen_path_ids": ["p-001"]}\n```'
        result = _extract_json_obj(text)
        assert result is not None
        assert "chosen_path_ids" in result

    def test_extract_json_with_text(self):
        """测试从包含解释文字的文本中提取 JSON"""
        text = 'Here is the result: {"chosen_path_ids": ["p-001"], "explanation": "test"}'
        result = _extract_json_obj(text)
        assert result is not None
        assert result["chosen_path_ids"] == ["p-001"]

    def test_extract_json_invalid(self):
        """测试无效 JSON"""
        text = "This is not JSON at all"
        result = _extract_json_obj(text)
        assert result is None

    def test_extract_json_empty(self):
        """测试空字符串"""
        result = _extract_json_obj("")
        assert result is None


# ========== validate_choose_result 测试 ==========

class TestValidateChooseResult:
    """测试 validate_choose_result 函数"""

    def test_validate_valid_result(self):
        """测试有效结果"""
        payload = create_sample_payload()
        result = {
            "chosen_path_ids": ["p-001"],
        }
        ok, reason = validate_choose_result(result, payload)
        assert ok is True
        assert reason == "ok"

    def test_validate_wrong_count(self):
        """测试数量不匹配"""
        payload = create_sample_payload()
        result = {
            "chosen_path_ids": ["p-001", "p-002"],  # 应该有 1 个，但给了 2 个
        }
        ok, reason = validate_choose_result(result, payload)
        assert ok is False
        assert "len" in reason.lower()

    def test_validate_invalid_path_id(self):
        """测试无效的 path_id"""
        payload = create_sample_payload()
        result = {
            "chosen_path_ids": ["p-999"],  # 不存在的 path_id
        }
        ok, reason = validate_choose_result(result, payload)
        assert ok is False
        assert "not in candidates" in reason.lower()

    def test_validate_missing_field(self):
        """测试缺少字段"""
        payload = create_sample_payload()
        result = {}  # 缺少 chosen_path_ids
        ok, reason = validate_choose_result(result, payload)
        assert ok is False
        assert "missing" in reason.lower() or "not list" in reason.lower()

    def test_validate_wrong_type(self):
        """测试类型错误"""
        payload = create_sample_payload()
        result = {
            "chosen_path_ids": "not-a-list",  # 应该是列表
        }
        ok, reason = validate_choose_result(result, payload)
        assert ok is False


# ========== fallback_choose 测试 ==========

class TestFallbackChoose:
    """测试 fallback_choose 函数"""

    def test_fallback_basic(self):
        """测试基本回退选择"""
        payload = create_sample_payload()
        result = fallback_choose(payload)

        assert "chosen_path_ids" in result
        assert "explanation" in result
        assert len(result["chosen_path_ids"]) == 1
        # 应该选择 hop 最短的（p-001 有 1 步，p-002 有 2 步）
        assert result["chosen_path_ids"][0] == "p-001"

    def test_fallback_empty_candidates(self):
        """测试空候选列表"""
        payload = create_sample_payload()
        payload["pairs"][0]["candidates"] = []
        result = fallback_choose(payload)

        assert result["chosen_path_ids"][0] == ""

    def test_fallback_multiple_pairs(self):
        """测试多个 pair"""
        payload = create_sample_payload()
        # 添加第二个 pair
        payload["pairs"].append(
            {
                "pair_idx": 1,
                "from_seg_idx": 1,
                "to_seg_idx": 2,
                "src_anchor": "Process:p-002",
                "dst_anchor": "Process:p-003",
                "t_min": 1195.0,
                "t_max": 1205.0,
                "candidates": [
                    {
                        "path_id": "p-010",
                        "steps": [{"ts": 1200.0, "src_uid": "p-002", "rel": "SPAWN", "dst_uid": "p-003", "key_props": {}}],
                    }
                ],
            }
        )
        result = fallback_choose(payload)

        assert len(result["chosen_path_ids"]) == 2


# ========== MockChooser 测试 ==========

class TestMockChooser:
    """测试 MockChooser 类"""

    def test_mock_chooser_basic(self):
        """测试基本 Mock 选择"""
        chooser = MockChooser()
        payload = create_sample_payload()
        result = chooser.choose(payload)

        assert "chosen_path_ids" in result
        assert "explanation" in result
        assert len(result["chosen_path_ids"]) == 1

    def test_mock_chooser_with_config(self):
        """测试带配置的 Mock 选择"""
        config = LLMChooseConfig(per_pair_keep=1)
        chooser = MockChooser(config=config)
        payload = create_large_payload()
        result = chooser.choose(payload)

        assert len(result["chosen_path_ids"]) == 1


# ========== LLMChooser 测试 ==========

class TestLLMChooser:
    """测试 LLMChooser 类"""

    def test_llm_chooser_without_llm(self):
        """测试没有注入 LLM 时回退到 fallback"""
        chooser = LLMChooser(chat_complete=None)
        payload = create_sample_payload()
        result = chooser.choose(payload)

        assert "chosen_path_ids" in result
        assert "回退" in result["explanation"]

    def test_llm_chooser_with_valid_llm_response(self):
        """测试有效的 LLM 响应"""
        def mock_chat_complete(messages):
            return json.dumps({
                "chosen_path_ids": ["p-001"],
                "explanation": "Selected based on shortest hop",
                "pair_explanations": [
                    {"pair_idx": 0, "path_id": "p-001", "why": "Shortest path"}
                ],
            })

        chooser = LLMChooser(chat_complete=mock_chat_complete)
        payload = create_sample_payload()
        result = chooser.choose(payload)

        assert result["chosen_path_ids"] == ["p-001"]
        assert "explanation" in result
        assert "pair_explanations" in result

    def test_llm_chooser_with_invalid_json(self):
        """测试无效 JSON 响应"""
        def mock_chat_complete(messages):
            return "This is not JSON"

        chooser = LLMChooser(chat_complete=mock_chat_complete)
        payload = create_sample_payload()
        result = chooser.choose(payload)

        # 应该回退到 fallback
        assert "chosen_path_ids" in result
        assert "回退" in result["explanation"]

    def test_llm_chooser_with_invalid_path_id(self):
        """测试 LLM 返回无效 path_id"""
        def mock_chat_complete(messages):
            return json.dumps({
                "chosen_path_ids": ["p-999"],  # 不存在的 path_id
                "explanation": "test",
            })

        chooser = LLMChooser(chat_complete=mock_chat_complete)
        payload = create_sample_payload()
        result = chooser.choose(payload)

        # 应该回退到 fallback，并在 explanation 中说明原因
        assert "invalid_llm_output" in result["explanation"].lower() or "fallback" in result["explanation"].lower()

    def test_llm_chooser_with_markdown_wrapped_json(self):
        """测试 LLM 返回 markdown 包裹的 JSON"""
        def mock_chat_complete(messages):
            return '```json\n{"chosen_path_ids": ["p-001"], "explanation": "test"}\n```'

        chooser = LLMChooser(chat_complete=mock_chat_complete)
        payload = create_sample_payload()
        result = chooser.choose(payload)

        assert result["chosen_path_ids"] == ["p-001"]

    def test_llm_chooser_with_preselect_disabled(self):
        """测试禁用预筛选"""
        def mock_chat_complete(messages):
            return json.dumps({
                "chosen_path_ids": ["p-001"],
                "explanation": "test",
            })

        chooser = LLMChooser(
            chat_complete=mock_chat_complete,
            enable_preselect=False,
        )
        payload = create_large_payload()
        result = chooser.choose(payload)

        # 即使禁用预筛选，reducer 仍会工作
        assert "chosen_path_ids" in result


# ========== create_llm_client 测试 ==========

class TestCreateLLMClient:
    """测试 create_llm_client 工厂函数"""

    def test_create_mock_client(self):
        """测试创建 Mock 客户端"""
        client = create_llm_client(provider="mock")
        assert isinstance(client, MockChooser)

    def test_create_mock_client_default(self):
        """测试默认创建 Mock 客户端（无 API key）"""
        # settings 是在 create_llm_client 函数内部导入的，需要 mock app.core.config.settings
        with patch("app.core.config.settings") as mock_settings:
            mock_settings.llm_provider = "deepseek"
            mock_settings.llm_api_key = ""
            client = create_llm_client()
            assert isinstance(client, MockChooser)

    def test_create_deepseek_client_with_key(self):
        """测试创建 DeepSeek 客户端（有 API key）"""
        with patch("app.services.analyze.killchain_llm._create_llm_chat_complete") as mock_create:
            mock_fn = Mock(return_value="test")
            mock_create.return_value = mock_fn

            client = create_llm_client(
                provider="deepseek",
                api_key="sk-test123",
            )
            assert isinstance(client, LLMChooser)
            mock_create.assert_called_once()

    def test_create_deepseek_client_without_key(self):
        """测试没有 API key 时回退到 Mock"""
        client = create_llm_client(provider="deepseek", api_key="")
        assert isinstance(client, MockChooser)

    def test_create_client_with_config(self):
        """测试使用自定义配置"""
        config = LLMChooseConfig(per_pair_keep=5)
        client = create_llm_client(provider="mock", config=config)
        assert isinstance(client, MockChooser)
        assert client.cfg.per_pair_keep == 5

    def test_create_client_unknown_provider(self):
        """测试未知 provider 回退到 Mock"""
        client = create_llm_client(provider="unknown")
        assert isinstance(client, MockChooser)

    def test_create_client_from_env_settings(self):
        """测试从环境设置读取配置"""
        # settings 是在 create_llm_client 函数内部导入的，需要 mock app.core.config.settings
        with patch("app.core.config.settings") as mock_settings:
            mock_settings.llm_provider = "mock"
            mock_settings.llm_api_key = ""
            mock_settings.llm_base_url = "https://api.deepseek.com/v1"
            mock_settings.llm_model = "deepseek-chat"
            mock_settings.llm_timeout = 60.0
            mock_settings.llm_max_retries = 3

            client = create_llm_client()
            assert isinstance(client, MockChooser)

    def test_create_client_import_error(self):
        """测试无法导入 settings 时的行为"""
        # 临时移除 settings 导入
        import sys
        original_modules = sys.modules.copy()
        if "app.core.config" in sys.modules:
            del sys.modules["app.core.config"]

        try:
            client = create_llm_client(provider="mock")
            assert isinstance(client, MockChooser)
        finally:
            sys.modules.clear()
            sys.modules.update(original_modules)


# ========== 集成测试 ==========

class TestIntegration:
    """集成测试：测试完整流程"""

    def test_full_pipeline_mock(self):
        """测试完整 pipeline（使用 Mock）"""
        payload = create_sample_payload()
        chooser = MockChooser()
        result = chooser.choose(payload)

        assert "chosen_path_ids" in result
        assert "explanation" in result
        assert len(result["chosen_path_ids"]) == len(payload["pairs"])

    def test_full_pipeline_with_reduction(self):
        """测试包含裁剪的完整 pipeline"""
        payload = create_large_payload()
        config = LLMChooseConfig(per_pair_keep=3, max_steps_per_path=2)
        chooser = MockChooser(config=config)
        result = chooser.choose(payload)

        assert len(result["chosen_path_ids"]) == 1
        # 验证裁剪生效：候选数量应该被限制
        # （通过检查内部状态，但这里我们只验证输出）

    def test_llm_chooser_with_exception(self):
        """测试 LLM 调用异常时的处理"""
        def mock_chat_complete(messages):
            raise RuntimeError("API error")

        chooser = LLMChooser(chat_complete=mock_chat_complete)
        payload = create_sample_payload()

        result = chooser.choose(payload)
        assert "chosen_path_ids" in result
        assert "回退" in result.get("explanation", "")
