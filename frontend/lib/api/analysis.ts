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

// TTP Similarity APT 条目类型
export type SimilarAptItem = {
  intrusion_set?: {
    id?: string;
    name?: string;
  };
  similarity_score?: number;
  confidence?: number;
  explanation?: string;
  top_tactics?: string[];
  top_techniques?: string[];
};

// KillChain 数据类型
export type KillChainData = {
  kc_uuid: string;
  confidence: number;
  segments: Array<{
    seg_idx: number;
    state: string;
    t_start: number;
    t_end: number;
    anchor_in_uid: string;
    anchor_out_uid: string;
    abnormal_edge_count: number;
  }>;
  selected_paths: Array<{
    path_id: string;
    src_anchor: string;
    dst_anchor: string;
    hop_count: number;
    edge_ids: string[];
  }>;
  explanation: string;
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
  "task.error"?: string | null;
  "task.result.summary"?: string | null;
  "task.result.ttp_similarity.attack_tactics"?: string[] | null;
  "task.result.ttp_similarity.attack_techniques"?: string[] | null;
  "task.result.ttp_similarity.similar_apts"?: SimilarAptItem[] | null;
  "task.result.trace.updated_edges"?: number | null;
  "task.result.trace.path_edges"?: number | null;
  "task.result.killchain_uuid"?: string;
  "task.result.killchain"?: KillChainData | null;
};

export type AnalysisTasksResponse =
  | {
      status: "ok";
      total: number;
      items: AnalysisTaskItem[];
      server_time?: string;
    }
  | {
      status: "error";
      error: { code: string; message: string };
      server_time?: string;
    };

export type AnalysisTaskResponse =
  | {
      status: "ok";
      task: AnalysisTaskItem;
      server_time?: string;
    }
  | {
      status: "error";
      error: { code: string; message: string };
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
  const response = await fetch("/api/v1/analysis/tasks", {
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
    `/api/v1/analysis/tasks${searchParams.toString() ? `?${searchParams}` : ""}`
  );

  if (!response.ok) {
    throw new Error("Failed to fetch analysis tasks");
  }

  return response.json();
}

export async function fetchAnalysisTask(taskId: string): Promise<AnalysisTaskResponse> {
  const response = await fetch(
    `/api/v1/analysis/tasks/${encodeURIComponent(taskId)}`
  );

  if (!response.ok) {
    try {
      const data = await response.json();
      return data;
    } catch {
      const text = await response.text();
      return {
        status: "error",
        error: { code: "HTTP_ERROR", message: text || "Failed to fetch analysis task" },
      };
    }
  }

  return response.json();
}

// ============================================
// 测试接口：直接测试 killchain 分析
// 注意：这是一个临时测试接口，方便删除
// ============================================
export type TestKillchainResponse =
  | {
      status: "ok";
      message?: string;
      result?: {
        kc_uuid: string;
        killchain_count: number;
        killchains: Array<{
          kc_uuid: string;
          confidence: number;
          explanation: string;
          segment_count: number;
          selected_path_count: number;
        }>;
      };
      server_time?: string;
    }
  | {
      status: "error";
      error: { code: string; message: string };
      server_time?: string;
    };

export async function testKillchainAnalysis(): Promise<TestKillchainResponse> {
  console.log("[TEST] testKillchainAnalysis: calling /api/analysis/killchain/test");
  const response = await fetch("/api/analysis/killchain/test", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
  });
  console.log("[TEST] testKillchainAnalysis: response status:", response.status);

  if (!response.ok) {
    try {
      const data = await response.json();
      return data;
    } catch {
      const text = await response.text();
      return {
        status: "error",
        error: { code: "HTTP_ERROR", message: text || "Failed to test killchain analysis" },
      };
    }
  }

  return response.json();
}
