from __future__ import annotations

"""
Phase C (LLM choose) design & reference implementation.

目标：
- 接受 killchain.build_llm_payload(...) 生成的 payload（或同结构）
- 做二次瘦身（PayloadReducer）：结构化摘要 + 可回溯引用（edge_id/path_id）
- （可选）启发式预筛（HeuristicPreselector）：减少噪声，提升 LLM 稳定性
- 调用 LLM 选择每个 pair 的 path_id，并返回全链解释
- 严格校验输出；失败则 fallback 并给出 trace

对外接口保持与 killchain.py 兼容：
    llm_client.choose(payload: dict) -> dict
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Tuple
import json
import re


# ---------------------------------------------------------------------
# Public interface (compatible with killchain.py)
# ---------------------------------------------------------------------

class KillChainLLMClient(Protocol):
    """killchain.py 期望的 LLM client 接口。"""
    def choose(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        ...


@dataclass(slots=True)
class LLMChooseConfig:
    """
    choose 的配置项：
    - per_pair_keep: 每个 pair 最多保留多少候选给 LLM（先预筛）
    - max_steps_per_path: 每条候选路径最多给多少 step（token 控制）
    - max_str_len: 文本字段截断长度
    - require_pair_explanations: 是否要求逐 pair 解释（可视化更友好）
    """
    per_pair_keep: int = 8
    max_steps_per_path: int = 10
    max_str_len: int = 200
    require_pair_explanations: bool = True


# ---------------------------------------------------------------------
# Payload reduction (2nd-stage slimming)
# ---------------------------------------------------------------------

DEFAULT_EDGE_KEYS_KEEP: Tuple[str, ...] = (
    "edge_id",
    "ts",
    "src_uid",
    "dst_uid",
    "rel",
    # 常用解释字段（都应已被 killchain 侧 summarize 过）
    "event.id",
    "event.dataset",
    "event.action",
    "rule.name",
    "threat.tactic.name",
    "threat.technique.name",
    "host.id",
    "host.name",
    "user.name",
    "process.entity_id",
    "process.name",
    "process.command_line",
    "source.ip",
    "destination.ip",
    "dns.question.name",
    "domain.name",
)

def _truncate(v: Any, max_len: int) -> Any:
    if isinstance(v, str) and len(v) > max_len:
        return v[:max_len] + "…"
    return v

class PayloadReducer:
    """将 build_llm_payload 的大 payload 再裁剪到更适合 LLM 的大小。"""

    def __init__(self, config: LLMChooseConfig):
        self.cfg = config

    def reduce(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "constraints": dict(payload.get("constraints", {})),
            "segments": [],
            "pairs": [],
        }

        # 1) segments：保留段摘要（已是 topN abnormal summaries）
        for s in payload.get("segments", []) or []:
            out["segments"].append(
                {
                    "seg_idx": s.get("seg_idx"),
                    "state": s.get("state"),
                    "t_start": s.get("t_start"),
                    "t_end": s.get("t_end"),
                    "anchor_in_uid": s.get("anchor_in_uid"),
                    "anchor_out_uid": s.get("anchor_out_uid"),
                    # 段内异常摘要本身也可能大：这里对每条摘要字段截断
                    "abnormal_edge_summaries": [
                        {k: _truncate(v, self.cfg.max_str_len) for k, v in (e or {}).items()}
                        for e in (s.get("abnormal_edge_summaries") or [])
                    ],
                }
            )

        # 2) pairs：候选路径 steps 裁剪（只保留必要字段 + 控制步数）
        for p in payload.get("pairs", []) or []:
            reduced_candidates: List[Dict[str, Any]] = []
            for c in p.get("candidates", []) or []:
                steps = c.get("steps", []) or []
                steps = steps[: self.cfg.max_steps_per_path]  # 限制步数

                slim_steps: List[Dict[str, Any]] = []
                for st in steps:
                    # key_props 是一个 dict（来自 summarize_edge），这里再裁剪字段
                    kp = st.get("key_props") or {}
                    if isinstance(kp, Mapping):
                        kp2 = {k: _truncate(kp.get(k), self.cfg.max_str_len) for k in DEFAULT_EDGE_KEYS_KEEP if k in kp}
                    else:
                        kp2 = {}

                    slim_steps.append(
                        {
                            "ts": st.get("ts"),
                            "src_uid": st.get("src_uid"),
                            "rel": st.get("rel"),
                            "dst_uid": st.get("dst_uid"),
                            "key_props": kp2,
                        }
                    )

                reduced_candidates.append(
                    {
                        "path_id": c.get("path_id"),
                        "steps": slim_steps,
                    }
                )

            out["pairs"].append(
                {
                    "pair_idx": p.get("pair_idx"),
                    "from_seg_idx": p.get("from_seg_idx"),
                    "to_seg_idx": p.get("to_seg_idx"),
                    "src_anchor": p.get("src_anchor"),
                    "dst_anchor": p.get("dst_anchor"),
                    "t_min": p.get("t_min"),
                    "t_max": p.get("t_max"),
                    "candidates": reduced_candidates,
                }
            )

        return out


# ---------------------------------------------------------------------
# Heuristic preselection (optional, but recommended)
# ---------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class ScoredCandidate:
    path_id: str
    score: float
    reasons: Tuple[str, ...] = ()

class HeuristicPreselector:
    """
    轻量启发式：
    - hop 越短越好（更可能是真因果链）
    - 若连续出现 process.entity_id / host.id / user.name，给加分
    目的：减少 LLM 噪声，提高稳定性（不是替代 LLM，而是筛掉明显不靠谱的）。
    """

    def __init__(self, config: LLMChooseConfig):
        self.cfg = config

    def _extract_tokens_from_steps(self, steps: Sequence[Mapping[str, Any]]) -> Dict[str, set]:
        proc_ids: set = set()
        host_ids: set = set()
        user_names: set = set()
        ips: set = set()
        domains: set = set()

        for st in steps:
            kp = st.get("key_props") or {}
            if isinstance(kp, Mapping):
                if kp.get("process.entity_id"):
                    proc_ids.add(kp["process.entity_id"])
                if kp.get("host.id"):
                    host_ids.add(kp["host.id"])
                if kp.get("user.name"):
                    user_names.add(kp["user.name"])
                if kp.get("source.ip"):
                    ips.add(kp["source.ip"])
                if kp.get("destination.ip"):
                    ips.add(kp["destination.ip"])
                if kp.get("dns.question.name"):
                    domains.add(kp["dns.question.name"])
                if kp.get("domain.name"):
                    domains.add(kp["domain.name"])

        return {"proc": proc_ids, "host": host_ids, "user": user_names, "ip": ips, "domain": domains}

    def preselect(self, reduced_payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        对 reduced_payload 的每个 pair.candidates 做预排序并截断到 per_pair_keep。
        返回结构仍为 payload，但 candidates 被裁剪。
        """
        out = dict(reduced_payload)
        out_pairs: List[Dict[str, Any]] = []

        # 维护“全链上下文”token集合：鼓励一致性
        global_tokens = {"proc": set(), "host": set(), "user": set(), "ip": set(), "domain": set()}

        for p in reduced_payload.get("pairs", []) or []:
            cands = p.get("candidates", []) or []
            scored: List[ScoredCandidate] = []

            for c in cands:
                steps = c.get("steps", []) or []
                hop = len(steps)

                tokens = self._extract_tokens_from_steps(steps)

                # base: shorter is better
                score = 10.0 / (1.0 + hop)
                reasons = [f"hop={hop}"]

                # consistency bonus: overlap with global tokens
                overlap = 0
                for k in global_tokens:
                    if global_tokens[k] and tokens[k]:
                        overlap += len(global_tokens[k].intersection(tokens[k]))
                if overlap:
                    score += 0.5 * overlap
                    reasons.append(f"overlap={overlap}")

                scored.append(ScoredCandidate(path_id=c.get("path_id", ""), score=score, reasons=tuple(reasons)))

            # sort high->low and keep top
            scored.sort(key=lambda x: x.score, reverse=True)
            keep_ids = {x.path_id for x in scored[: self.cfg.per_pair_keep] if x.path_id}

            new_cands = [c for c in cands if c.get("path_id") in keep_ids]

            # 更新全链 token（用最优候选的 tokens 作为滚动上下文）
            if new_cands:
                best_steps = new_cands[0].get("steps", []) or []
                best_tokens = self._extract_tokens_from_steps(best_steps)
                for k in global_tokens:
                    global_tokens[k].update(best_tokens[k])

            p2 = dict(p)
            p2["candidates"] = new_cands
            p2["heuristic_ranking"] = [
                {"path_id": x.path_id, "score": x.score, "reasons": list(x.reasons)}
                for x in scored[: max(self.cfg.per_pair_keep, 5)]
                if x.path_id
            ]
            out_pairs.append(p2)

        out["pairs"] = out_pairs
        return out


# ---------------------------------------------------------------------
# Prompt builder & response parsing
# ---------------------------------------------------------------------

def build_choose_prompt(payload: Mapping[str, Any], *, require_pair_explanations: bool) -> List[Dict[str, str]]:
    """
    返回 chat messages（OpenAI/兼容 ChatCompletion 风格）。
    你们可在接入真实 LLM 时直接复用。
    """
    schema_hint = {
        "chosen_path_ids": ["p-... (one per pair, in pair order)"],
        "explanation": "global explanation, 3-8 sentences",
        "pair_explanations": [
            {"pair_idx": 0, "path_id": "p-...", "why": "1-2 sentences"},
        ] if require_pair_explanations else [],
    }

    system = (
        "You are a senior incident responder. "
        "Given an attack timeline segmented by MITRE ATT&CK tactics, "
        "choose exactly ONE candidate path for EACH adjacent segment pair. "
        "Your choices must be globally consistent (entities/process/host continuity) and time-consistent. "
        "Return STRICT JSON only (no markdown)."
    )

    user = {
        "task": "Choose one path_id per pair to form the most plausible killchain connections.",
        "output_schema": schema_hint,
        "input": payload,
        "rules": [
            "Must choose exactly one path_id for each pair, in the same order as pairs[]",
            "Chosen path_id must exist in that pair's candidates",
            "Prefer paths that maintain entity continuity across pairs (same process.entity_id/host.id/user.name when plausible)",
            "If multiple plausible, prefer simpler (shorter hop) and more semantically aligned with segment abnormal summaries",
        ],
    }

    return [
        {"role": "system", "content": system},
        {"role": "user", "content": json.dumps(user, ensure_ascii=False)},
    ]


_JSON_OBJ_RE = re.compile(r"\{.*\}", re.S)

def _extract_json_obj(text: str) -> Optional[Dict[str, Any]]:
    """
    尝试从模型输出中提取 JSON 对象（即使模型夹带解释文字也尽量救回来）。
    """
    text = text.strip()
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass

    m = _JSON_OBJ_RE.search(text)
    if not m:
        return None
    try:
        obj = json.loads(m.group(0))
        if isinstance(obj, dict):
            return obj
    except Exception:
        return None
    return None


def validate_choose_result(raw: Mapping[str, Any], payload: Mapping[str, Any]) -> Tuple[bool, str]:
    """
    校验 LLM 输出：
    - chosen_path_ids 数量必须等于 pairs 数量
    - 每个 chosen_path_id 必须属于对应 pair.candidates
    """
    pairs = payload.get("pairs", []) or []
    chosen = raw.get("chosen_path_ids")

    if not isinstance(chosen, list) or not all(isinstance(x, str) for x in chosen):
        return False, "chosen_path_ids missing or not list[str]"

    if len(chosen) != len(pairs):
        return False, f"chosen_path_ids len={len(chosen)} != pairs len={len(pairs)}"

    for i, pid in enumerate(chosen):
        cands = pairs[i].get("candidates", []) or []
        cand_ids = {c.get("path_id") for c in cands}
        if pid not in cand_ids:
            return False, f"chosen_path_id not in candidates at pair_idx={i}"

    return True, "ok"


def fallback_choose(payload: Mapping[str, Any]) -> Dict[str, Any]:
    """
    fallback：每个 pair 选 hop 最短的一条。
    payload 需为 reduced/preselected 后的结构（candidates.steps 已裁剪）。
    """
    chosen_ids: List[str] = []
    for p in payload.get("pairs", []) or []:
        cands = p.get("candidates", []) or []
        if not cands:
            chosen_ids.append("")
            continue
        best = min(cands, key=lambda c: len(c.get("steps", []) or []))
        chosen_ids.append(best.get("path_id", ""))

    return {
        "chosen_path_ids": chosen_ids,
        "explanation": "fallback: selected shortest-hop path per pair (LLM unavailable or invalid).",
        "pair_explanations": [],
    }


# ---------------------------------------------------------------------
# Main chooser implementation
# ---------------------------------------------------------------------

class LLMChooser(KillChainLLMClient):
    """
    可注入真实 LLM 调用的 chooser。
    你们只需提供 chat_complete(messages)->str 的函数即可（例如 OpenAI SDK wrapper）。
    """

    def __init__(
        self,
        *,
        chat_complete: Optional[Any] = None,
        config: Optional[LLMChooseConfig] = None,
        enable_preselect: bool = True,
    ) -> None:
        self.cfg = config or LLMChooseConfig()
        self.chat_complete = chat_complete  # callable(messages)->str
        self.reducer = PayloadReducer(self.cfg)
        self.preselector = HeuristicPreselector(self.cfg)
        self.enable_preselect = enable_preselect

    def choose(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        入口：兼容 killchain.py 的调用方式。
        返回 dict：{"chosen_path_ids":[...], "explanation":"...", "pair_explanations":[...]}
        """
        reduced = self.reducer.reduce(payload)
        if self.enable_preselect:
            reduced = self.preselector.preselect(reduced)

        # 如果没有注入真实 LLM，则直接 fallback
        if self.chat_complete is None:
            return fallback_choose(reduced)

        messages = build_choose_prompt(reduced, require_pair_explanations=self.cfg.require_pair_explanations)
        text = self.chat_complete(messages)

        obj = _extract_json_obj(text if isinstance(text, str) else str(text))
        if obj is None:
            return fallback_choose(reduced)

        ok, reason = validate_choose_result(obj, reduced)
        if not ok:
            # 给上层留 trace 的话，可以在 obj 中附加 reason
            fb = fallback_choose(reduced)
            fb["explanation"] += f" (invalid_llm_output: {reason})"
            return fb

        # 保证至少返回 required keys
        out: Dict[str, Any] = {
            "chosen_path_ids": obj.get("chosen_path_ids"),
            "explanation": obj.get("explanation", ""),
        }
        if isinstance(obj.get("pair_explanations"), list):
            out["pair_explanations"] = obj.get("pair_explanations")
        else:
            out["pair_explanations"] = []
        return out


class MockChooser(KillChainLLMClient):
    """
    本地调试用 chooser：
    - 每个 pair 选择 hop 最短候选
    - 可快速跑通 pipeline
    """

    def __init__(self, config: Optional[LLMChooseConfig] = None) -> None:
        self.cfg = config or LLMChooseConfig()
        self.reducer = PayloadReducer(self.cfg)
        self.preselector = HeuristicPreselector(self.cfg)

    def choose(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        reduced = self.reducer.reduce(payload)
        reduced = self.preselector.preselect(reduced)
        return fallback_choose(reduced)


# ---------------------------------------------------------------------
# OpenAI integration & factory functions
# ---------------------------------------------------------------------

def _create_openai_chat_complete(
    api_key: str,
    base_url: str = "https://api.openai.com/v1",
    model: str = "gpt-3.5-turbo",
    timeout: float = 30.0,
    max_retries: int = 2,
) -> Any:
    """
    创建 OpenAI chat_complete 函数。
    返回 callable(messages: List[Dict[str, str]]) -> str
    """
    try:
        from openai import OpenAI
    except ImportError:
        raise ImportError(
            "请安装 openai: uv add openai 或 pip install openai>=1.0.0"
        )

    client = OpenAI(
        api_key=api_key,
        base_url=base_url,
        timeout=timeout,
        max_retries=max_retries,
    )

    def chat_complete(messages: List[Dict[str, str]]) -> str:
        """
        调用 OpenAI ChatCompletion API。
        messages: [{"role": "system", "content": "..."}, {"role": "user", "content": "..."}]
        返回: 模型生成的文本（应包含 JSON）
        """
        try:
            # 构建请求参数
            kwargs = {
                "model": model,
                "messages": messages,
                "temperature": 0.3,  # 较低温度，更确定性输出
            }
            
            # response_format 仅在 gpt-3.5-turbo-1106 及以后版本支持
            # 对于旧版本，依赖 prompt 中的 JSON 格式要求
            if "1106" in model or "gpt-4" in model.lower() or "gpt-4o" in model.lower():
                kwargs["response_format"] = {"type": "json_object"}
            
            response = client.chat.completions.create(**kwargs)
            content = response.choices[0].message.content
            if content is None:
                raise ValueError("OpenAI 返回空内容")
            return content
        except Exception as e:
            raise RuntimeError(f"OpenAI API 调用失败: {e}") from e

    return chat_complete


def create_llm_client(
    *,
    provider: Optional[str] = None,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    model: Optional[str] = None,
    timeout: Optional[float] = None,
    max_retries: Optional[int] = None,
    config: Optional[LLMChooseConfig] = None,
    enable_preselect: bool = True,
) -> KillChainLLMClient:
    """
    工厂函数：根据配置创建 LLM client。

    参数:
        provider: "openai" 或 "mock"（默认从环境变量 LLM_PROVIDER 读取）
        api_key: OpenAI API key（默认从环境变量 OPENAI_API_KEY 读取）
        base_url: OpenAI base URL（默认从环境变量 OPENAI_BASE_URL 读取）
        model: 模型名称（默认从环境变量 OPENAI_MODEL 读取，默认 "gpt-3.5-turbo"）
        timeout: 超时时间（秒）
        max_retries: 最大重试次数
        config: LLMChooseConfig 实例
        enable_preselect: 是否启用启发式预筛选

    返回:
        KillChainLLMClient 实例（LLMChooser 或 MockChooser）

    示例:
        # 使用环境变量配置
        client = create_llm_client()

        # 显式指定
        client = create_llm_client(
            provider="openai",
            api_key="sk-...",
            model="gpt-3.5-turbo"
        )

        # 使用 mock（本地调试）
        client = create_llm_client(provider="mock")
    """
    try:
        from app.core.config import settings
    except ImportError:
        # 如果无法导入 settings，使用默认值
        _provider = provider or "mock"
        _api_key = api_key or ""
        _base_url = base_url or "https://api.openai.com/v1"
        _model = model or "gpt-3.5-turbo"
        _timeout = timeout if timeout is not None else 30.0
        _max_retries = max_retries if max_retries is not None else 2
    else:
        _provider = provider or settings.llm_provider
        _api_key = api_key or settings.openai_api_key
        _base_url = base_url or settings.openai_base_url
        _model = model or settings.openai_model
        _timeout = timeout if timeout is not None else settings.openai_timeout
        _max_retries = max_retries if max_retries is not None else settings.openai_max_retries

    if _provider.lower() == "mock":
        return MockChooser(config=config)

    if _provider.lower() == "openai":
        if not _api_key:
            # 如果没有 API key，回退到 mock
            return MockChooser(config=config)

        chat_complete_fn = _create_openai_chat_complete(
            api_key=_api_key,
            base_url=_base_url,
            model=_model,
            timeout=_timeout,
            max_retries=_max_retries,
        )
        return LLMChooser(
            chat_complete=chat_complete_fn,
            config=config,
            enable_preselect=enable_preselect,
        )

    # 未知 provider，回退到 mock
    return MockChooser(config=config)