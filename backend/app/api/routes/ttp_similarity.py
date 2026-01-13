from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services.ttp_similarity import (
    fetch_attack_techniques_from_canonical_findings,
    rank_similar_intrusion_sets,
)


router = APIRouter()


class TTPSimilarityRequest(BaseModel):
    host_id: str = Field(..., description="ECS host.id")
    start_ts: datetime = Field(..., description="ISO 8601 start timestamp (inclusive)")
    end_ts: datetime = Field(..., description="ISO 8601 end timestamp (inclusive)")


class IntrusionSetRef(BaseModel):
    id: str
    name: str


class SimilarAptItem(BaseModel):
    intrusion_set: IntrusionSetRef
    similarity_score: float
    top_techniques: list[str]


class TTPSimilarityResponse(BaseModel):
    host_id: str
    start_ts: datetime
    end_ts: datetime
    attack_techniques: list[str]
    similar_apts: list[SimilarAptItem]


@router.post("/api/v1/analysis/ttp-similarity", response_model=TTPSimilarityResponse)
def ttp_similarity(req: TTPSimilarityRequest) -> TTPSimilarityResponse:
    if req.end_ts < req.start_ts:
        raise HTTPException(status_code=400, detail="end_ts must be >= start_ts")

    try:
        attack_techniques = fetch_attack_techniques_from_canonical_findings(
            host_id=req.host_id,
            start_ts=req.start_ts,
            end_ts=req.end_ts,
        )
        attack_ids, candidates = rank_similar_intrusion_sets(attack_techniques=attack_techniques)
    except FileNotFoundError as error:
        raise HTTPException(status_code=500, detail=str(error)) from error
    except Exception as error:
        raise HTTPException(status_code=500, detail=f"ttp similarity failed: {error}") from error

    return TTPSimilarityResponse(
        host_id=req.host_id,
        start_ts=req.start_ts,
        end_ts=req.end_ts,
        attack_techniques=list(attack_ids),
        similar_apts=[
            SimilarAptItem(
                intrusion_set=IntrusionSetRef(
                    id=c.intrusion_set_id,
                    name=c.intrusion_set_name,
                ),
                similarity_score=c.similarity_score,
                top_techniques=list(c.top_techniques),
            )
            for c in candidates
        ],
    )
