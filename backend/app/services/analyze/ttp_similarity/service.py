from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
import json
import math
from pathlib import Path
import re
from typing import Any, Iterable

import os

from app.core.time import format_rfc3339
from app.services.opensearch.internal import INDEX_PATTERNS, search


_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_TACTIC_ID_RE = re.compile(r"^TA\d{4}$")


def _as_str(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    return None


def _get_in(obj: Any, keys: Iterable[str]) -> Any | None:
    cur: Any = obj
    for key in keys:
        if not isinstance(cur, dict) or key not in cur:
            return None
        cur = cur[key]
    return cur


def _normalize_technique_id(raw_id: str | None) -> str | None:
    if raw_id is None:
        return None
    cleaned = raw_id.strip().upper()
    if not cleaned:
        return None
    if cleaned in {"UNKNOWN", "TBD"}:
        return None
    if cleaned == "T0000" or cleaned.startswith("T0000."):
        return None
    if not _TECHNIQUE_ID_RE.match(cleaned):
        return None
    return cleaned


def _normalize_tactic_id(raw_id: str | None) -> str | None:
    if raw_id is None:
        return None
    cleaned = raw_id.strip().upper()
    if not cleaned:
        return None
    if cleaned in {"UNKNOWN", "TBD"}:
        return None
    if cleaned == "TA0000":
        return None
    if not _TACTIC_ID_RE.match(cleaned):
        return None
    return cleaned


def _expand_technique_ids(raw_id: str | None) -> set[str]:
    """
    Expand a (sub-)technique id into a stable set:
    - T1055.012 -> {"T1055.012", "T1055"}
    - T1055     -> {"T1055"}
    Invalid / placeholder -> empty set.
    """
    tid = _normalize_technique_id(raw_id)
    if tid is None:
        return set()
    out = {tid}
    if "." in tid:
        out.add(tid.split(".", 1)[0])
    return out


def _extract_technique_ids_from_finding(finding: dict[str, Any]) -> set[str]:
    tid = _as_str(_get_in(finding, ["threat", "technique", "id"])) or _as_str(
        finding.get("threat.technique.id")
    )
    return _expand_technique_ids(tid)


def _extract_tactic_id_from_finding(finding: dict[str, Any]) -> str | None:
    # Prefer stable ECS flattened key first; fall back to nested object.
    tid = _as_str(finding.get("threat.tactic.id")) or _as_str(
        _get_in(finding, ["threat", "tactic", "id"])
    )
    return _normalize_tactic_id(tid)


def _extract_tactic_ids_from_finding(finding: dict[str, Any]) -> set[str]:
    tid = _extract_tactic_id_from_finding(finding)
    return {tid} if tid else set()


def _extract_intrusion_set_external_id(stix_obj: dict[str, Any]) -> str | None:
    """
    Prefer stable ATT&CK "group id" (e.g., G0016) if present; fall back to STIX id.
    """
    refs = stix_obj.get("external_references")
    if not isinstance(refs, list):
        return None
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        if ref.get("source_name") != "mitre-attack":
            continue
        ext_id = _as_str(ref.get("external_id"))
        if ext_id and ext_id.startswith("G"):
            return ext_id
    return None


def _extract_technique_external_id(stix_obj: dict[str, Any]) -> str | None:
    refs = stix_obj.get("external_references")
    if not isinstance(refs, list):
        return None
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        if ref.get("source_name") != "mitre-attack":
            continue
        ext_id = _as_str(ref.get("external_id"))
        if ext_id and ext_id.startswith("T"):
            return ext_id.strip().upper()
    return None


def _extract_tactic_external_id(stix_obj: dict[str, Any]) -> str | None:
    refs = stix_obj.get("external_references")
    if not isinstance(refs, list):
        return None
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        if ref.get("source_name") != "mitre-attack":
            continue
        ext_id = _as_str(ref.get("external_id"))
        if ext_id and ext_id.upper().startswith("TA"):
            return ext_id.strip().upper()
    return None


@dataclass(frozen=True)
class SimilarAptCandidate:
    intrusion_set_id: str
    intrusion_set_name: str
    similarity_score: float
    top_tactics: tuple[str, ...]
    top_techniques: tuple[str, ...]


@dataclass(frozen=True)
class EnterpriseCtiIndex:
    """
    In-memory CTI index:
    - intrusion_sets: {intrusion_set_stix_id -> (display_id, name)}
    - techniques: {attack_pattern_stix_id -> technique_id(Txxxx[.xxx])}
    - uses: {intrusion_set_stix_id -> frozenset(technique_ids)}
    - group_tactics: {intrusion_set_stix_id -> frozenset(tactic_ids)}
    - technique_idf: {technique_id -> float}
    - tactic_idf: {tactic_id -> float}
    - group_norm: {intrusion_set_stix_id -> L2 norm of its technique TF-IDF vector}
    - group_tactic_norm: {intrusion_set_stix_id -> L2 norm of its tactic TF-IDF vector}
    """

    intrusion_sets: dict[str, tuple[str, str]]
    techniques: dict[str, str]
    tactic_shortnames: dict[str, str]
    technique_tactics: dict[str, frozenset[str]]
    uses: dict[str, frozenset[str]]
    group_tactics: dict[str, frozenset[str]]
    technique_idf: dict[str, float]
    tactic_idf: dict[str, float]
    group_norm: dict[str, float]
    group_tactic_norm: dict[str, float]

    @property
    def num_intrusion_sets(self) -> int:
        return len(self.uses)


def _load_attack_stix_objects(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and isinstance(data.get("objects"), list):
        return [obj for obj in data["objects"] if isinstance(obj, dict)]
    if isinstance(data, list):
        return [obj for obj in data if isinstance(obj, dict)]
    raise ValueError("Unsupported STIX JSON structure (expected bundle with 'objects').")


def build_enterprise_cti_index(stix_path: Path) -> EnterpriseCtiIndex:
    objects = _load_attack_stix_objects(stix_path)

    intrusion_sets: dict[str, tuple[str, str]] = {}
    techniques: dict[str, str] = {}
    tactic_shortnames: dict[str, str] = {}

    for obj in objects:
        if obj.get("type") == "intrusion-set":
            stix_id = _as_str(obj.get("id"))
            name = _as_str(obj.get("name"))
            if not stix_id or not name:
                continue
            display_id = _extract_intrusion_set_external_id(obj) or stix_id
            intrusion_sets[stix_id] = (display_id, name)
        elif obj.get("type") == "x-mitre-tactic":
            shortname = _as_str(obj.get("x_mitre_shortname")) or _as_str(obj.get("name"))
            tactic_id = _extract_tactic_external_id(obj)
            if not shortname or not tactic_id:
                continue
            tactic_id_norm = _normalize_tactic_id(tactic_id)
            if tactic_id_norm is None:
                continue
            tactic_shortnames[shortname.strip().lower()] = tactic_id_norm
        elif obj.get("type") == "attack-pattern":
            stix_id = _as_str(obj.get("id"))
            if not stix_id:
                continue
            ext_id = _extract_technique_external_id(obj)
            if not ext_id:
                continue
            ext_id_norm = _normalize_technique_id(ext_id)
            if ext_id_norm is None:
                continue
            techniques[stix_id] = ext_id_norm

    # Technique -> tactics (derived from kill_chain_phases + x-mitre-tactic mapping).
    technique_tactics_raw: dict[str, set[str]] = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        stix_id = _as_str(obj.get("id"))
        if not stix_id:
            continue
        technique_id = techniques.get(stix_id)
        if technique_id is None:
            continue

        phases = obj.get("kill_chain_phases")
        if not isinstance(phases, list):
            continue
        tactic_ids: set[str] = set()
        for phase in phases:
            if not isinstance(phase, dict):
                continue
            if phase.get("kill_chain_name") != "mitre-attack":
                continue
            phase_name = _as_str(phase.get("phase_name"))
            if not phase_name:
                continue
            tid = tactic_shortnames.get(phase_name.strip().lower())
            if tid:
                tactic_ids.add(tid)

        if not tactic_ids:
            continue

        # Keep tactic mapping for both sub-technique and its parent technique.
        for tid in _expand_technique_ids(technique_id):
            technique_tactics_raw.setdefault(tid, set()).update(tactic_ids)

    technique_tactics: dict[str, frozenset[str]] = {
        k: frozenset(v) for k, v in technique_tactics_raw.items() if v
    }

    uses: dict[str, set[str]] = {}
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "uses":
            continue
        src = _as_str(obj.get("source_ref"))
        dst = _as_str(obj.get("target_ref"))
        if not src or not dst:
            continue
        if src not in intrusion_sets:
            continue
        tech_id = techniques.get(dst)
        if tech_id is None:
            continue
        # Expand sub-techniques to include their parent technique id, to improve matching.
        uses.setdefault(src, set()).update(_expand_technique_ids(tech_id))

    # Only keep intrusion sets that have at least one technique.
    uses_frozen: dict[str, frozenset[str]] = {k: frozenset(v) for k, v in uses.items() if v}

    # Group tactics are derived from group's technique set and technique->tactic mapping.
    group_tactics_raw: dict[str, set[str]] = {}
    for group_stix_id, techs in uses_frozen.items():
        tactic_ids: set[str] = set()
        for t in techs:
            tactic_ids.update(technique_tactics.get(t, frozenset()))
        if tactic_ids:
            group_tactics_raw[group_stix_id] = tactic_ids
    group_tactics: dict[str, frozenset[str]] = {k: frozenset(v) for k, v in group_tactics_raw.items() if v}

    # IDF: computed over intrusion sets (documents) where technique appears.
    N = len(uses_frozen)
    df: dict[str, int] = {}
    for techs in uses_frozen.values():
        for t in techs:
            df[t] = df.get(t, 0) + 1

    technique_idf: dict[str, float] = {}
    for t, doc_freq in df.items():
        technique_idf[t] = math.log((N + 1) / (doc_freq + 1)) + 1.0

    # Tactic IDF over intrusion sets.
    df_tactic: dict[str, int] = {}
    for tactics in group_tactics.values():
        for ta in tactics:
            df_tactic[ta] = df_tactic.get(ta, 0) + 1
    tactic_idf: dict[str, float] = {}
    for ta, doc_freq in df_tactic.items():
        tactic_idf[ta] = math.log((N + 1) / (doc_freq + 1)) + 1.0

    group_norm: dict[str, float] = {}
    for group_stix_id, techs in uses_frozen.items():
        ssq = 0.0
        for t in techs:
            w = technique_idf.get(t)
            if w is None:
                continue
            ssq += w * w
        group_norm[group_stix_id] = math.sqrt(ssq)

    group_tactic_norm: dict[str, float] = {}
    for group_stix_id, tactics in group_tactics.items():
        ssq = 0.0
        for ta in tactics:
            w = tactic_idf.get(ta)
            if w is None:
                continue
            ssq += w * w
        group_tactic_norm[group_stix_id] = math.sqrt(ssq)

    return EnterpriseCtiIndex(
        intrusion_sets=intrusion_sets,
        techniques=techniques,
        tactic_shortnames=tactic_shortnames,
        technique_tactics=technique_tactics,
        uses=uses_frozen,
        group_tactics=group_tactics,
        technique_idf=technique_idf,
        tactic_idf=tactic_idf,
        group_norm=group_norm,
        group_tactic_norm=group_tactic_norm,
    )


@lru_cache(maxsize=1)
def get_enterprise_cti_index() -> EnterpriseCtiIndex:
    """
    Resolve local ATT&CK Enterprise CTI bundle path.

    Notes on path resolution:
    - If ATTACK_CTI_PATH is absolute, use it directly.
    - If it's relative, we try:
      1) as-is (relative to current working directory)
      2) relative to backend root (and accept repo-root style "backend/..." by stripping the prefix)
    - If ATTACK_CTI_PATH is not set, fall back to the module-local default:
      backend/app/services/analyze/ttp_similarity/cti/enterprise-attack.json
    """
    default_path = Path(__file__).resolve().parent / "cti" / "enterprise-attack.json"

    raw = os.environ.get("ATTACK_CTI_PATH", "").strip()
    if not raw:
        path = default_path
    else:
        env_path = Path(raw)
        candidates: list[Path] = []
        if env_path.is_absolute():
            candidates.append(env_path)
        else:
            # 1) relative to current working directory
            candidates.append(env_path)

            # 2) relative to backend root (best-effort; more stable across different cwd)
            resolved = Path(__file__).resolve()
            backend_root = next(
                (p for p in resolved.parents if (p / "pyproject.toml").exists()),
                resolved.parents[-1],
            )
            normalized = raw
            if normalized.startswith("backend/"):
                normalized = normalized[len("backend/") :]
            candidates.append(backend_root / normalized)

        path = next((p for p in candidates if p.exists()), env_path)

    if not path.exists():
        hint = (
            "Place attack-stix-data Enterprise bundle at "
            "backend/app/services/analyze/ttp_similarity/cti/enterprise-attack.json "
            "or set ATTACK_CTI_PATH."
        )
        raise FileNotFoundError(f"ATT&CK Enterprise CTI file not found: {path}. {hint}")

    return build_enterprise_cti_index(path)


def _cosine_from_intersection_weights(
    *,
    intersection: Iterable[str],
    idf: dict[str, float],
    left_norm: float,
    right_norm: float,
) -> float:
    if left_norm <= 0.0 or right_norm <= 0.0:
        return 0.0
    dot = 0.0
    for t in intersection:
        w = idf.get(t)
        if w is None:
            continue
        dot += w * w
    if dot <= 0.0:
        return 0.0
    return dot / (left_norm * right_norm)


def rank_similar_intrusion_sets(
    *,
    attack_tactics: set[str],
    attack_techniques: set[str],
) -> tuple[tuple[str, ...], list[SimilarAptCandidate]]:
    """
    Compute Top-3 similar intrusion sets using TF-IDF (binary TF) + cosine.

    Similarity uses both:
    - ATT&CK Techniques (Txxxx[.xxx])
    - ATT&CK Tactics (TAxxxx), derived from CTI technique tactic mapping.

    Returns:
        (attack_technique_ids, candidates)
    """
    top_k = 3
    tactic_weight = 0.5
    explain_top_n = 5
    cti = get_enterprise_cti_index()

    # Filter to techniques that exist in CTI; otherwise they cannot contribute.
    attack_techniques_filtered = {t for t in attack_techniques if t in cti.technique_idf}
    attack_tactics_filtered = {t for t in attack_tactics if t in cti.tactic_idf}

    attack_tech_norm = math.sqrt(sum(cti.technique_idf[t] ** 2 for t in attack_techniques_filtered))
    attack_tactic_norm = math.sqrt(sum(cti.tactic_idf[t] ** 2 for t in attack_tactics_filtered))

    if attack_tech_norm <= 0.0 and attack_tactic_norm <= 0.0:
        return tuple(sorted(attack_techniques_filtered)), []

    scored: list[tuple[float, str]] = []
    for group_stix_id, group_techs in cti.uses.items():
        # Technique similarity
        inter_tech = attack_techniques_filtered.intersection(group_techs)
        tech_score = _cosine_from_intersection_weights(
            intersection=inter_tech,
            idf=cti.technique_idf,
            left_norm=attack_tech_norm,
            right_norm=cti.group_norm.get(group_stix_id, 0.0),
        )

        # Tactic similarity
        group_tactics = cti.group_tactics.get(group_stix_id, frozenset())
        inter_tactic = attack_tactics_filtered.intersection(group_tactics)
        tactic_score = _cosine_from_intersection_weights(
            intersection=inter_tactic,
            idf=cti.tactic_idf,
            left_norm=attack_tactic_norm,
            right_norm=cti.group_tactic_norm.get(group_stix_id, 0.0),
        )

        score = (1.0 - tactic_weight) * tech_score + tactic_weight * tactic_score
        if score > 0.0:
            scored.append((score, group_stix_id))

    scored.sort(reverse=True, key=lambda x: x[0])
    top = scored[: max(0, top_k)]

    candidates: list[SimilarAptCandidate] = []
    for score, group_stix_id in top:
        display_id, name = cti.intrusion_sets.get(group_stix_id, (group_stix_id, group_stix_id))
        group_techs = cti.uses.get(group_stix_id, frozenset())
        inter_tech = attack_techniques_filtered.intersection(group_techs)
        ranked_techs = sorted(inter_tech, key=lambda t: cti.technique_idf.get(t, 0.0), reverse=True)
        top_techniques = tuple(ranked_techs[: max(0, explain_top_n)])

        group_tactics = cti.group_tactics.get(group_stix_id, frozenset())
        inter_tactic = attack_tactics_filtered.intersection(group_tactics)
        ranked_tactics = sorted(inter_tactic, key=lambda t: cti.tactic_idf.get(t, 0.0), reverse=True)
        top_tactics = tuple(ranked_tactics[: max(0, explain_top_n)])

        candidates.append(
            SimilarAptCandidate(
                intrusion_set_id=display_id,
                intrusion_set_name=name,
                similarity_score=float(score),
                top_tactics=top_tactics,
                top_techniques=top_techniques,
            )
        )

    return tuple(sorted(attack_techniques_filtered)), candidates


def fetch_attack_ttps_from_canonical_findings(
    *,
    host_id: str,
    start_ts: datetime,
    end_ts: datetime,
    size: int = 10000,
) -> tuple[set[str], set[str]]:
    """
    Fetch Canonical Findings from OpenSearch and extract cleaned technique ids.
    Placeholder technique ids are filtered (e.g., T0000 / Unknown).
    """
    index = f"{INDEX_PATTERNS['CANONICAL_FINDINGS']}-*"
    query = {
        "bool": {
            "filter": [
                {"term": {"event.dataset": "finding.canonical"}},
                {"term": {"host.id": host_id}},
                {
                    "range": {
                        "@timestamp": {"gte": format_rfc3339(start_ts), "lte": format_rfc3339(end_ts)}
                    }
                },
            ]
        }
    }
    findings = search(index, query, size=size)

    tactics: set[str] = set()
    techniques: set[str] = set()
    for f in findings:
        techniques.update(_extract_technique_ids_from_finding(f))
        tactics.update(_extract_tactic_ids_from_finding(f))
    return tactics, techniques
