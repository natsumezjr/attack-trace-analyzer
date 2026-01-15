"""ATT&CK TTP similarity (tactics + techniques) via offline Enterprise CTI + TF-IDF + cosine."""

from app.services.analyze.ttp_similarity.router import router
from app.services.analyze.ttp_similarity.service import (
    fetch_attack_ttps_from_canonical_findings,
    get_enterprise_cti_index,
    rank_similar_intrusion_sets,
)

__all__ = [
    "fetch_attack_ttps_from_canonical_findings",
    "get_enterprise_cti_index",
    "rank_similar_intrusion_sets",
    "router",
]

