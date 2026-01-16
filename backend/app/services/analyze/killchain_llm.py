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
        "explanation": "详细的全局解释，使用中文，10-20 句话，详细描述整个攻击链的完整过程，必须说明每个关键节点的主谓宾结构。在解释中，请使用易懂的形式加上括号，比如 p_c2 (pid:1234) 代表c2进程，host_web (host.id:host-001) 代表web主机等",
        "confidence": 0.85,  # 可信度评分 (0.0-1.0)，表示对整个 killchain 的置信度
        "pair_explanations": [
            {"pair_idx": 0, "path_id": "p-...", "why": "使用中文，1-3 句话解释为什么选择此路径"},
        ] if require_pair_explanations else [],
    }

    system = (
        "你是一位资深的安全事件响应专家。"
        "给定一个按 MITRE ATT&CK 战术分段的攻击时间线，"
        "为每个相邻的段对选择恰好一条候选路径。"
        "你的选择必须在全局上保持一致（实体/进程/主机的连续性）和时间一致性。"
        "同时提供一个可信度评分 (0.0-1.0)，表示你对这个攻击链分析的置信程度。"
        "如果攻击涉及权限提升或 C2（命令与控制），你必须分析并解释："
        "初始入侵点、攻击者在内部网络中的横向移动路径、"
        "权限提升路径、从存储的完整数据泄露路径、"
        "通过提取攻击工具/脚本/配置文件的指纹特征进行攻击者归因、"
        "以及攻击者和 C2 服务器 IP 地址的分析。"
        "所有解释必须使用中文，并且要详细（10-20 句话）。"
        "在 explanation 字段中，你必须为每个关键节点明确说明主谓宾结构，"
        "即：谁（主语）做了什么（谓语）对什么/在哪里（宾语/状语）。"
        "在解释中，请使用易懂的形式加上括号，比如 p_c2 (pid:1234) 代表c2进程，"
        "host_web (host.id:host-001) 代表web主机，user_admin (user.name:admin) 代表管理员用户等。"
        "重要：在描述网络连接时，必须严格区分攻击者 IP（source.ip）和受害主机 IP（destination.ip 或 host.ip）。"
        "在 Initial Access 阶段，攻击者 IP 是发起连接的源 IP，受害主机 IP 是目标 IP。"
        "在攻击者归因部分，必须使用正确的攻击者 IP 地址（通常是 Initial Access 阶段的 source.ip），而不是受害主机的 IP。"
        "返回严格的 JSON 格式（不要使用 markdown），确保 JSON 格式完整且正确，explanation 字段必须完整输出，不要截断。"
    )

    user = {
        "task": "为每个段对选择一条路径以形成最合理的攻击链连接，并提供可信度评分。所有输出必须使用中文。",
        "output_schema": schema_hint,
        "input": payload,
        "rules": [
            "必须为每个段对选择恰好一个 path_id，顺序与 pairs[] 相同",
            "选择的 path_id 必须存在于该段对的 candidates 中",
            "优先选择在段对之间保持实体连续性的路径（在合理的情况下，相同的 process.entity_id/host.id/user.name）",
            "如果有多条合理路径，优先选择更简单（跳数更少）且与段异常摘要更语义对齐的路径",
            "提供可信度评分 (0.0-1.0)：连接良好、一致的攻击链评分更高；模糊或不完整的链评分更低",
            "如果检测到权限提升或 C2，解释必须包括：(1) 初始入侵点识别，(2) 攻击者在内部网络中的横向移动路径，(3) 权限提升路径分析，(4) 从存储的完整数据泄露路径，(5) 通过提取攻击工具、脚本和配置文件的指纹特征进行攻击者归因，(6) 攻击者和 C2 服务器 IP 地址分析",
            "explanation 字段必须使用中文，详细描述整个攻击链的完整过程，长度应在 10-20 句话之间",
            "explanation 字段中，对于每个关键节点（进程、主机、IP、域名等实体），必须明确说明主谓宾结构：主语（谁/什么实体）+ 谓语（执行了什么动作）+ 宾语/状语（对什么/在哪里/通过什么方式）",
            "在解释中，请使用易懂的形式加上括号，比如 p_c2 (pid:1234) 代表c2进程，host_web (host.id:host-001) 代表web主机，user_admin (user.name:admin) 代表管理员用户等，使解释更加清晰易懂",
            "在描述 Initial Access 阶段时，必须明确区分：攻击者 IP（source.ip，发起连接的源 IP）和受害主机 IP（destination.ip 或 host.ip，被攻击的目标 IP）。例如：'攻击者从外部 IP 地址 [source.ip] 连接到受害主机 [host.name] (IP: [host.ip])'",
            "在攻击者归因部分，必须使用正确的攻击者 IP 地址（通常是 Initial Access 阶段的 source.ip），而不是受害主机的 IP 地址。如果数据中没有明确的攻击者 IP，应说明无法确定攻击者 IP",
            "在描述网络连接时，必须明确说明连接的源和目标：谁（主语，攻击者/进程）从哪个 IP（源 IP）连接到哪个 IP/主机（目标 IP/主机）",
            "explanation 字段必须完整输出，不要截断，确保 JSON 格式正确（如果 explanation 中包含引号，请使用转义字符）",
            "pair_explanations 中的 why 字段也必须使用中文，解释为什么选择该路径，长度应在 1-3 句话之间",
        ],
    }

    return [
        {"role": "system", "content": system},
        {"role": "user", "content": json.dumps(user, ensure_ascii=False)},
    ]


_JSON_OBJ_RE = re.compile(r"\{.*\}", re.S | re.DOTALL)

def _extract_json_obj(text: str) -> Optional[Dict[str, Any]]:
    """
    尝试从模型输出中提取 JSON 对象（即使模型夹带解释文字也尽量救回来）。
    改进：使用更可靠的方法提取 JSON，确保长文本不会被截断。
    """
    text = text.strip()
    
    # 首先尝试直接解析整个文本
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass
    
    # 如果直接解析失败，尝试找到 JSON 对象的开始和结束
    # 查找第一个 { 和最后一个 }
    start_idx = text.find('{')
    if start_idx == -1:
        return None
    
    # 从后往前查找匹配的 }
    brace_count = 0
    end_idx = -1
    for i in range(start_idx, len(text)):
        if text[i] == '{':
            brace_count += 1
        elif text[i] == '}':
            brace_count -= 1
            if brace_count == 0:
                end_idx = i
                break
    
    if end_idx == -1:
        # 如果找不到匹配的 }，尝试使用正则表达式（作为后备）
        m = _JSON_OBJ_RE.search(text)
        if m:
            try:
                obj = json.loads(m.group(0))
                if isinstance(obj, dict):
                    return obj
            except Exception:
                pass
        return None
    
    # 提取完整的 JSON 对象
    json_str = text[start_idx:end_idx + 1]
    try:
        obj = json.loads(json_str)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass
    
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
        "explanation": (
            "由于大语言模型不可用或无效，系统使用回退策略选择了攻击链路径。"
            "回退策略为每个段对选择了跳数最短的路径，以确保攻击链的基本连通性。"
            "这种方法虽然能够构建完整的攻击链，但由于缺乏智能分析，可能无法识别最优路径。"
            "建议在配置大语言模型 API 密钥后重新运行分析，以获得更准确和详细的攻击链解释。"
            "当前选择的路径基于最短路径启发式算法，优先考虑了路径的简洁性和直接性。"
        ),
        "confidence": 0.5,  # fallback 模式默认可信度
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
        timeout: Optional[float] = None,
    ) -> None:
        self.cfg = config or LLMChooseConfig()
        self.chat_complete = chat_complete  # callable(messages)->str
        self.reducer = PayloadReducer(self.cfg)
        self.preselector = HeuristicPreselector(self.cfg)
        self.enable_preselect = enable_preselect
        self._timeout = timeout

    def choose(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        入口：兼容 killchain.py 的调用方式。
        返回 dict：{"chosen_path_ids":[...], "explanation":"...", "pair_explanations":[...]}
        """
        
        reduced = self.reducer.reduce(payload)

        
        if self.enable_preselect:
            reduced = self.preselector.preselect(reduced)

        # 如果 pairs 为空，直接使用 fallback，不调用 LLM
        if not reduced.get('pairs'):
            result = fallback_choose(reduced)
            return result

        # 如果没有注入真实 LLM，则直接 fallback
        if self.chat_complete is None:
            result = fallback_choose(reduced)
            return result

        messages = build_choose_prompt(reduced, require_pair_explanations=self.cfg.require_pair_explanations)
        try:
            text = self.chat_complete(messages)
        except Exception as e:
            result = fallback_choose(reduced)
            return result

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
        # 提取可信度评分
        conf = obj.get("confidence")
        if isinstance(conf, (int, float)):
            out["confidence"] = max(0.0, min(1.0, float(conf)))  # 确保在 0.0-1.0 范围内
        else:
            out["confidence"] = 0.5  # 默认可信度
        
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
        result = fallback_choose(reduced)
        return result


# ---------------------------------------------------------------------
# DeepSeek LLM integration & factory functions
# ---------------------------------------------------------------------

def _create_llm_chat_complete(
    api_key: str,
    base_url: str = "https://api.deepseek.com/v1",
    model: str = "deepseek-chat",
    timeout: float = 30.0,
    max_retries: int = 2,
) -> Any:
    """
    创建 LLM chat_complete 函数（兼容 OpenAI API 格式，支持 DeepSeek）。
    返回 callable(messages: List[Dict[str, str]]) -> str
    """
    try:
        from openai import OpenAI
        from httpx import Timeout as HTTPXTimeout
    except ImportError:
        raise ImportError(
            "请安装 openai: uv add openai 或 pip install openai>=1.0.0"
        )

    # 使用 httpx.Timeout 设置更细粒度的超时控制
    # connect: 连接超时（短）
    # read: 读取超时（长，因为 LLM 生成需要时间）
    # write: 写入超时（中等）
    # pool: 连接池超时（短）
    httpx_timeout = HTTPXTimeout(
        connect=10.0,      # 连接服务器最多 10 秒
        read=timeout,     # 读取响应最多 timeout 秒（这是关键，LLM 生成需要时间）
        write=30.0,       # 写入请求最多 30 秒
        pool=5.0,         # 从连接池获取连接最多 5 秒
    )

    client = OpenAI(
        api_key=api_key,
        base_url=base_url,
        timeout=httpx_timeout,  # 使用 httpx.Timeout 对象
        max_retries=max_retries,
    )

    def chat_complete(messages: List[Dict[str, str]]) -> str:
        """
        调用 LLM ChatCompletion API（DeepSeek 兼容 OpenAI API 格式）。
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
            
            # DeepSeek 支持 JSON 格式输出
            # 对于支持 response_format 的模型，启用 JSON 模式
            if "deepseek" in model.lower() or "gpt-4" in model.lower():
                kwargs["response_format"] = {"type": "json_object"}
            
            response = client.chat.completions.create(**kwargs)
            content = response.choices[0].message.content
            if content is None:
                raise ValueError("LLM 返回空内容")
            return content
        except Exception as e:
            # 提供更友好的错误信息
            error_msg = str(e)
            if "402" in error_msg or "Insufficient Balance" in error_msg or "余额" in error_msg:
                raise RuntimeError(
                    f"DeepSeek API 余额不足 (402): 请前往 https://platform.deepseek.com/ 充值或等待免费额度重置。"
                    f" 原始错误: {e}"
                ) from e
            elif "429" in error_msg or "quota" in error_msg.lower():
                raise RuntimeError(
                    f"DeepSeek API 配额超限 (429): 已达到使用限制，请稍后重试或升级账户。"
                    f" 原始错误: {e}"
                ) from e
            else:
                raise RuntimeError(f"LLM API 调用失败: {e}") from e

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
        provider: "deepseek" 或 "mock"（默认从环境变量 LLM_PROVIDER 读取）
        api_key: DeepSeek API key（默认从环境变量 DEEPSEEK_API_KEY 读取）
        base_url: DeepSeek base URL（默认从环境变量 DEEPSEEK_BASE_URL 读取）
        model: 模型名称（默认从环境变量 DEEPSEEK_MODEL 读取，默认 "deepseek-chat"）
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
            provider="deepseek",
            api_key="sk-...",
            model="deepseek-chat"
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
        _base_url = base_url or "https://api.deepseek.com/v1"
        _model = model or "deepseek-chat"
        _timeout = timeout if timeout is not None else 30.0
        _max_retries = max_retries if max_retries is not None else 2
    else:
        _provider = provider or settings.llm_provider
        _api_key = api_key or settings.llm_api_key
        _base_url = base_url or settings.llm_base_url
        _model = model or settings.llm_model
        _timeout = timeout if timeout is not None else settings.llm_timeout
        _max_retries = max_retries if max_retries is not None else settings.llm_max_retries

    if _provider.lower() == "mock":
        return MockChooser(config=config)

    if _provider.lower() == "deepseek":
        if not _api_key:
            # 如果没有 API key，回退到 mock
            return MockChooser(config=config)

        chat_complete_fn = _create_llm_chat_complete(
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
            timeout=_timeout,  # 传递 timeout 用于调试
        )

    # 未知 provider，回退到 mock
    return MockChooser(config=config)