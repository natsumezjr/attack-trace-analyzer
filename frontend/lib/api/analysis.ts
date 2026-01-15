export type CreateAnalysisTaskPayload = {
  target_node_uid: string;
  start_ts: string;
  end_ts: string;
};

export type CreateAnalysisTaskResponse = {
  status: "ok" | "error";
  task_id?: string;
  task?: Record<string, unknown>;
  error?: { code: string; message: string };
  server_time?: string;
};

export type AnalysisTaskItem = {
  "@timestamp": string;
  "task.id": string;
  "task.status": string;
  "task.progress": number;
  "task.target.node_uid": string;
  "task.window.start_ts": string;
  "task.window.end_ts": string;
  "task.started_at"?: string | null;
  "task.finished_at"?: string | null;
};

export type AnalysisTasksResponse = {
  ok: boolean;
  total: number;
  items: AnalysisTaskItem[];
  server_time?: string;
};

export type AnalysisTasksQuery = {
  status?: string;
  target_node_uid?: string;
  size?: number;
  offset?: number;
};

export async function createAnalysisTask(
  payload: CreateAnalysisTaskPayload
): Promise<CreateAnalysisTaskResponse> {
  const response = await fetch("/api/analysis/tasks", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    throw new Error("Failed to create analysis task");
  }

  return response.json();
}

export async function fetchAnalysisTasks(
  query: AnalysisTasksQuery = {}
): Promise<AnalysisTasksResponse> {
  const searchParams = new URLSearchParams();
  if (query.status) searchParams.set("status", query.status);
  if (query.target_node_uid) {
    searchParams.set("target_node_uid", query.target_node_uid);
  }
  if (typeof query.size === "number") {
    searchParams.set("size", String(query.size));
  }
  if (typeof query.offset === "number") {
    searchParams.set("offset", String(query.offset));
  }

  const response = await fetch(
    `/api/analysis/tasks${searchParams.toString() ? `?${searchParams}` : ""}`
  );

  if (!response.ok) {
    throw new Error("Failed to fetch analysis tasks");
  }

  return response.json();
}
