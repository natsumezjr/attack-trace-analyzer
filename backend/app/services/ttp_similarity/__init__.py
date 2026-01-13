"""ATT&CK TTP similarity module (Enterprise CTI + TF-IDF + cosine)."""

from app.services.ttp_similarity.router import router
from app.services.ttp_similarity.service import (
    fetch_attack_techniques_from_canonical_findings,
    get_enterprise_cti_index,
    rank_similar_intrusion_sets,
)

__all__ = [
    "fetch_attack_techniques_from_canonical_findings",
    "get_enterprise_cti_index",
    "rank_similar_intrusion_sets",
    "router",
]
