from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.api.utils import err, ok, utc_now_rfc3339


router = APIRouter()


class GraphQueryRequest(BaseModel):
    action: Literal[
        "alarm_edges",
        "edges_in_window",
        "shortest_path_in_window",
    ] = "alarm_edges"

    start_ts: datetime | None = None
    end_ts: datetime | None = None

    allowed_reltypes: list[str] | None = None
    only_alarm: bool = False

    src_uid: str | None = None
    dst_uid: str | None = None

    risk_weights: dict[str, float] | None = None
    min_risk: float = Field(0.0, ge=0.0)

    include_nodes: bool = False


def _edge_to_dict(edge: Any) -> dict[str, Any]:
    rtype = getattr(edge, "rtype", None)
    rtype_value = getattr(rtype, "value", None) if rtype is not None else None
    return {
        "src_uid": getattr(edge, "src_uid", None),
        "dst_uid": getattr(edge, "dst_uid", None),
        "rtype": rtype_value or rtype,
        "props": getattr(edge, "props", None),
    }


def _node_to_dict(node: Any) -> dict[str, Any]:
    ntype = getattr(node, "ntype", None)
    ntype_value = getattr(ntype, "value", None) if ntype is not None else None
    return {
        "uid": getattr(node, "uid", None),
        "ntype": ntype_value or ntype,
        "key": getattr(node, "key", None),
        "props": getattr(node, "props", None),
    }


@router.post("/api/v1/graph/query")
def graph_query(req: GraphQueryRequest):
    # Lazy import: graph module depends on neo4j, which may not be installed in every dev env.
    try:
        from app.services.graph import api as graph_api  # type: ignore
    except Exception as error:
        return JSONResponse(
            status_code=501,
            content=err("NOT_IMPLEMENTED", f"graph backend unavailable: {error}"),
        )

    try:
        if req.action == "alarm_edges":
            edges = graph_api.get_alarm_edges()
            nodes: list[dict[str, Any]] = []
            if req.include_nodes:
                uids = {e.src_uid for e in edges} | {e.dst_uid for e in edges}
                for uid in sorted(uids):
                    node = graph_api.get_node(uid)
                    if node is not None:
                        nodes.append(_node_to_dict(node))
            return ok(
                edges=[_edge_to_dict(e) for e in edges],
                nodes=nodes,
                server_time=utc_now_rfc3339(),
            )

        if req.action == "edges_in_window":
            if req.start_ts is None or req.end_ts is None:
                return JSONResponse(
                    status_code=400,
                    content=err("BAD_REQUEST", "start_ts and end_ts are required"),
                )
            t_min = req.start_ts.timestamp()
            t_max = req.end_ts.timestamp()
            edges = graph_api.get_edges_in_window(
                t_min,
                t_max,
                allowed_reltypes=req.allowed_reltypes,
                only_alarm=req.only_alarm,
            )
            nodes = []
            if req.include_nodes:
                uids = {e.src_uid for e in edges} | {e.dst_uid for e in edges}
                for uid in sorted(uids):
                    node = graph_api.get_node(uid)
                    if node is not None:
                        nodes.append(_node_to_dict(node))
            return ok(
                edges=[_edge_to_dict(e) for e in edges],
                nodes=nodes,
                server_time=utc_now_rfc3339(),
            )

        if req.action == "shortest_path_in_window":
            if not req.src_uid or not req.dst_uid:
                return JSONResponse(
                    status_code=400,
                    content=err("BAD_REQUEST", "src_uid and dst_uid are required"),
                )
            if req.start_ts is None or req.end_ts is None:
                return JSONResponse(
                    status_code=400,
                    content=err("BAD_REQUEST", "start_ts and end_ts are required"),
                )
            if not isinstance(req.risk_weights, dict) or not req.risk_weights:
                return JSONResponse(
                    status_code=400,
                    content=err("BAD_REQUEST", "risk_weights is required"),
                )

            t_min = req.start_ts.timestamp()
            t_max = req.end_ts.timestamp()

            result = graph_api.gds_shortest_path_in_window(
                req.src_uid,
                req.dst_uid,
                t_min,
                t_max,
                risk_weights=req.risk_weights,
                min_risk=req.min_risk,
                allowed_reltypes=req.allowed_reltypes,
            )
            if result is None:
                return ok(
                    found=False,
                    cost=None,
                    edges=[],
                    server_time=utc_now_rfc3339(),
                )

            cost, edges = result
            return ok(
                found=True,
                cost=cost,
                edges=[_edge_to_dict(e) for e in edges],
                server_time=utc_now_rfc3339(),
            )

        return JSONResponse(
            status_code=400,
            content=err("BAD_REQUEST", f"unknown action: {req.action}"),
        )
    except Exception as error:
        return JSONResponse(
            status_code=500,
            content=err("INTERNAL_ERROR", str(error)),
        )

