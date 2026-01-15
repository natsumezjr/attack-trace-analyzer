export type GraphQueryAction =
  | "alarm_edges"
  | "edges_in_window"
  | "shortest_path_in_window"
  | "analysis_edges_by_task";

export type GraphApiEdge = {
  src_uid: string;
  dst_uid: string;
  rtype: string;
  props?: Record<string, unknown>;
};

export type GraphApiNode = {
  uid: string;
  ntype: string;
  key?: Record<string, string>;
  props?: Record<string, unknown>;
};

export type GraphQueryResponse = {
  status: "ok" | "error";
  edges?: GraphApiEdge[];
  nodes?: GraphApiNode[];
  found?: boolean;
  cost?: number | null;
  error?: { code: string; message: string };
  server_time?: string;
};

export type GraphQueryRequest = {
  action: GraphQueryAction;
  start_ts?: string | null;
  end_ts?: string | null;
  allowed_reltypes?: string[] | null;
  only_alarm?: boolean;
  src_uid?: string | null;
  dst_uid?: string | null;
  risk_weights?: Record<string, number> | null;
  min_risk?: number;
  task_id?: string | null;
  only_path?: boolean;
};

export async function fetchGraphQuery(
  payload: GraphQueryRequest
): Promise<GraphQueryResponse> {
  const response = await fetch("/api/graph/query", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    throw new Error("Failed to fetch graph data");
  }

  return response.json();
}
