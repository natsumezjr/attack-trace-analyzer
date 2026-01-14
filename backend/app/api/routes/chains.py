from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.api.utils import err


router = APIRouter()


class GenerateChainsRequest(BaseModel):
    # Placeholder for v1 API shape. We keep it minimal until the chain generator is wired.
    host_id: str | None = None
    start_ts: datetime | None = None
    end_ts: datetime | None = None


@router.post("/api/v1/chains/generate")
def generate_chains(_: GenerateChainsRequest):
    # TODO: wire Phase A/B/C chain generator (Neo4j + attack_fsa + GDS), then persist to OpenSearch.
    return JSONResponse(
        status_code=501,
        content=err("NOT_IMPLEMENTED", "attack chain generation is not implemented yet"),
    )


@router.get("/api/v1/chains/{chain_id}")
def get_chain(chain_id: str):
    # TODO: load chain detail from OpenSearch (attack-chains-*), keyed by chain_id.
    return JSONResponse(
        status_code=501,
        content=err("NOT_IMPLEMENTED", f"attack chain {chain_id} is not implemented yet"),
    )

