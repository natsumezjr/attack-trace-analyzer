export type GraphQueryAction = "alarm_edges";

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
  ok: boolean;
  edges: GraphApiEdge[];
  nodes: GraphApiNode[];
  server_time: string;
};

export async function fetchGraphQuery(
  action: GraphQueryAction = "alarm_edges"
): Promise<GraphQueryResponse> {
  const response = await fetch("/api/graph/query", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action }),
  });

  if (!response.ok) {
    throw new Error("Failed to fetch graph data");
  }

  return response.json();
}
