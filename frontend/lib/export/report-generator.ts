import { fetchAnalysisTask, type AnalysisTaskItem } from "@/lib/api/analysis";
import {
  fetchGraphQuery,
  type GraphApiEdge,
  type GraphApiNode,
  type GraphQueryRequest,
} from "@/lib/api/graph";
import { fetchFindingsSearch, type FindingsSearchRequest } from "@/lib/api/findings";

const MAX_CANONICAL_FINDINGS = 2000;
const APPENDIX_EDGE_LIMIT = 50;
const APPENDIX_FINDING_LIMIT = 50;

type IntrusionSetRef = { id?: string; name?: string };

export type SimilarAptItem = {
  intrusion_set?: IntrusionSetRef;
  similarity_score?: number;
  top_tactics?: string[];
  top_techniques?: string[];
};

export type TtpSimilarityBlock = {
  source: "task.result" | "api" | "none";
  attack_tactics: string[];
  attack_techniques: string[];
  similar_apts: SimilarAptItem[];
};

export type ReportData = {
  task: AnalysisTaskItem;
  taskId: string;
  taskStatus: string;
  targetNodeUid: string;
  startTs: string;
  endTs: string;
  hostId: string | null;
  canonicalFindings: Record<string, unknown>[];
  canonicalFindingsTruncated: boolean;
  graphEdges: GraphApiEdge[];
  graphNodes: GraphApiNode[];
  pathEdges: GraphApiEdge[];
  ttpSimilarity: TtpSimilarityBlock;
  notes: string[];
};

type TtpSimilarityApiResponse = {
  host_id: string;
  start_ts: string;
  end_ts: string;
  attack_tactics: string[];
  attack_techniques: string[];
  similar_apts: Array<{
    intrusion_set: { id: string; name: string };
    similarity_score: number;
    top_tactics: string[];
    top_techniques: string[];
  }>;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function getIn(obj: unknown, path: string[]): unknown {
  if (!isRecord(obj)) return undefined;

  let cur: unknown = obj;
  for (const key of path) {
    if (!isRecord(cur) || !(key in cur)) {
      cur = undefined;
      break;
    }
    cur = cur[key];
  }
  if (cur !== undefined) return cur;

  const dotted = path.join(".");
  return dotted in obj ? obj[dotted] : undefined;
}

function compareStrings(a: string, b: string): number {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

function toStringArray(value: unknown): string[] {
  if (typeof value === "string" && value) return [value];
  if (!Array.isArray(value)) return [];
  return value.filter((v) => typeof v === "string" && v);
}

function uniqSortedStrings(values: Iterable<string>): string[] {
  const out = new Set<string>();
  for (const v of values) {
    if (typeof v === "string" && v) out.add(v);
  }
  return Array.from(out).sort(compareStrings);
}

function parseNumber(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim()) {
    const n = Number(value);
    if (Number.isFinite(n)) return n;
  }
  return null;
}

function parseHostIdFromUid(uid: string): string | null {
  // Examples:
  // - Host:host.id=h-xxxx
  // - File:host.id=h-xxxx;file.path=/etc/passwd
  // - User:host.id=h-xxxx;user.name=alice
  const match = uid.match(/(?:^|:|;|,)\s*host\.id=([^;,\n\r]+)/);
  const hostId = match?.[1]?.trim();
  return hostId ? hostId : null;
}

export function extractHostIdFromGraphNodes(args: {
  targetNodeUid: string;
  graphNodes: GraphApiNode[];
}): string | null {
  const uid = args.targetNodeUid;
  if (!uid) return null;

  const byUid = parseHostIdFromUid(uid);
  if (byUid) return byUid;

  const node = args.graphNodes.find((n) => n.uid === uid);
  if (!node) return null;

  const fromKey = node.key?.["host.id"];
  if (typeof fromKey === "string" && fromKey) return fromKey;

  const fromProps = node.props?.["host.id"];
  if (typeof fromProps === "string" && fromProps) return fromProps;

  return null;
}

function isPathEdge(edge: GraphApiEdge): boolean {
  const v = edge.props?.["analysis.is_path_edge"];
  return v === true || v === "true";
}

function sortGraphNodes(nodes: GraphApiNode[]): GraphApiNode[] {
  return [...nodes].sort((a, b) => compareStrings(a.uid, b.uid));
}

function sortGraphEdges(edges: GraphApiEdge[]): GraphApiEdge[] {
  return [...edges].sort((a, b) => {
    const aTs = parseNumber(a.props?.["ts_float"]) ?? 0;
    const bTs = parseNumber(b.props?.["ts_float"]) ?? 0;
    if (aTs !== bTs) return aTs - bTs;

    if (a.src_uid !== b.src_uid) return compareStrings(a.src_uid, b.src_uid);
    if (a.rtype !== b.rtype) return compareStrings(a.rtype, b.rtype);
    if (a.dst_uid !== b.dst_uid) return compareStrings(a.dst_uid, b.dst_uid);

    const aEvent = a.props?.["event.id"];
    const bEvent = b.props?.["event.id"];
    return compareStrings(String(aEvent ?? ""), String(bEvent ?? ""));
  });
}

function sortFindings(findings: Record<string, unknown>[]): Record<string, unknown>[] {
  return [...findings].sort((a, b) => {
    const aTs = getIn(a, ["@timestamp"]);
    const bTs = getIn(b, ["@timestamp"]);
    const tsCmp = compareStrings(String(aTs ?? ""), String(bTs ?? ""));
    if (tsCmp !== 0) return tsCmp;

    const aId = getIn(a, ["event", "id"]);
    const bId = getIn(b, ["event", "id"]);
    return compareStrings(String(aId ?? ""), String(bId ?? ""));
  });
}

function normalizeSimilarAptItems(raw: unknown): SimilarAptItem[] {
  if (!Array.isArray(raw)) return [];
  const out: SimilarAptItem[] = [];

  for (const item of raw) {
    if (!isRecord(item)) continue;
    const intrusion = item["intrusion_set"];
    const intrusion_set: IntrusionSetRef | undefined = isRecord(intrusion)
      ? {
          id: typeof intrusion["id"] === "string" ? intrusion["id"] : undefined,
          name: typeof intrusion["name"] === "string" ? intrusion["name"] : undefined,
        }
      : undefined;

    const similarity_score =
      typeof item["similarity_score"] === "number" ? item["similarity_score"] : undefined;
    const top_tactics = Array.isArray(item["top_tactics"])
      ? item["top_tactics"].filter((v) => typeof v === "string" && v)
      : undefined;
    const top_techniques = Array.isArray(item["top_techniques"])
      ? item["top_techniques"].filter((v) => typeof v === "string" && v)
      : undefined;

    out.push({ intrusion_set, similarity_score, top_tactics, top_techniques });
  }

  return out.sort((a, b) => {
    const as = typeof a.similarity_score === "number" ? a.similarity_score : -Infinity;
    const bs = typeof b.similarity_score === "number" ? b.similarity_score : -Infinity;
    if (as !== bs) return bs - as;
    const aId = a.intrusion_set?.id ?? a.intrusion_set?.name ?? "";
    const bId = b.intrusion_set?.id ?? b.intrusion_set?.name ?? "";
    return compareStrings(aId, bId);
  });
}

async function fetchTtpSimilarityFromApi(args: {
  hostId: string;
  startTs: string;
  endTs: string;
}): Promise<TtpSimilarityApiResponse> {
  const response = await fetch("/api/v1/analysis/ttp-similarity", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      host_id: args.hostId,
      start_ts: args.startTs,
      end_ts: args.endTs,
    }),
  });

  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new Error(text || `HTTP ${response.status}`);
  }

  return response.json();
}

export async function generateReportData(taskId: string): Promise<ReportData> {
  if (!taskId || !taskId.trim()) {
    throw new Error("task_id is required");
  }

  const notes: string[] = [];

  const taskResponse = await fetchAnalysisTask(taskId);
  if (taskResponse.status !== "ok") {
    throw new Error(taskResponse.error?.message ?? "无法获取任务信息");
  }

  const task = taskResponse.task;
  const targetNodeUid = task["task.target.node_uid"];
  const startTs = task["task.window.start_ts"];
  const endTs = task["task.window.end_ts"];

  if (!targetNodeUid || !startTs || !endTs) {
    throw new Error("任务文档缺少必要字段（target_node_uid/start_ts/end_ts）");
  }

  const taskStatus = task["task.status"];

  let graphEdges: GraphApiEdge[] = [];
  let graphNodes: GraphApiNode[] = [];
  try {
    const graphQuery: GraphQueryRequest = {
      action: "analysis_edges_by_task",
      task_id: taskId,
      // Fetch all updated edges to maximize the chance that `nodes[]` contains
      // the task target node (even if there is no path edge in this task).
      only_path: false,
    };
    const graphResponse = await fetchGraphQuery(graphQuery);
    if (graphResponse.status !== "ok") {
      notes.push(graphResponse.error?.message ?? "图查询返回 error");
    } else {
      graphEdges = Array.isArray(graphResponse.edges) ? graphResponse.edges : [];
      graphNodes = Array.isArray(graphResponse.nodes) ? graphResponse.nodes : [];
    }
  } catch (error) {
    notes.push(error instanceof Error ? error.message : String(error));
  }

  const hostId = extractHostIdFromGraphNodes({
    targetNodeUid,
    graphNodes,
  });

  if (!hostId) {
    notes.push("无法提取 host.id：Canonical Findings 拉取将被跳过");
  }

  let canonicalFindings: Record<string, unknown>[] = [];
  let canonicalFindingsTruncated = false;
  if (hostId) {
    const findingsReq: FindingsSearchRequest = {
      stage: "canonical",
      start_ts: startTs,
      end_ts: endTs,
      host_id: hostId,
      size: MAX_CANONICAL_FINDINGS,
      offset: 0,
      sort_order: "asc",
    };

    try {
      const findingsResp = await fetchFindingsSearch(findingsReq);
      if (findingsResp.status === "ok") {
        canonicalFindings = Array.isArray(findingsResp.items) ? findingsResp.items : [];
        canonicalFindingsTruncated = findingsResp.total > canonicalFindings.length;
      } else {
        notes.push(findingsResp.error?.message ?? "Canonical Findings 查询失败");
      }
    } catch (error) {
      notes.push(error instanceof Error ? error.message : String(error));
    }
  }

  const taskTactics = Array.isArray(task["task.result.ttp_similarity.attack_tactics"])
    ? (task["task.result.ttp_similarity.attack_tactics"] as string[]).filter(
        (v) => typeof v === "string" && v
      )
    : [];
  const taskTechniques = Array.isArray(task["task.result.ttp_similarity.attack_techniques"])
    ? (task["task.result.ttp_similarity.attack_techniques"] as string[]).filter(
        (v) => typeof v === "string" && v
      )
    : [];
  const taskSimilarApts = normalizeSimilarAptItems(
    task["task.result.ttp_similarity.similar_apts"] ?? null
  );

  let ttpSimilarity: TtpSimilarityBlock = {
    source: "none",
    attack_tactics: [],
    attack_techniques: [],
    similar_apts: [],
  };

  if (taskTactics.length || taskTechniques.length || taskSimilarApts.length) {
    ttpSimilarity = {
      source: "task.result",
      attack_tactics: uniqSortedStrings(taskTactics),
      attack_techniques: uniqSortedStrings(taskTechniques),
      similar_apts: taskSimilarApts,
    };
  } else if (hostId) {
    try {
      const api = await fetchTtpSimilarityFromApi({ hostId, startTs, endTs });
      ttpSimilarity = {
        source: "api",
        attack_tactics: uniqSortedStrings(api.attack_tactics ?? []),
        attack_techniques: uniqSortedStrings(api.attack_techniques ?? []),
        similar_apts: normalizeSimilarAptItems(api.similar_apts ?? []),
      };
    } catch (error) {
      notes.push(error instanceof Error ? error.message : String(error));
    }
  }

  const sortedNodes = sortGraphNodes(graphNodes);
  const sortedEdges = sortGraphEdges(graphEdges);
  const pathEdges = sortGraphEdges(sortedEdges.filter(isPathEdge));
  const sortedFindings = sortFindings(canonicalFindings);

  return {
    task,
    taskId,
    taskStatus: typeof taskStatus === "string" ? taskStatus : "unknown",
    targetNodeUid,
    startTs,
    endTs,
    hostId,
    canonicalFindings: sortedFindings,
    canonicalFindingsTruncated,
    graphEdges: sortedEdges,
    graphNodes: sortedNodes,
    pathEdges,
    ttpSimilarity,
    notes,
  };
}

const OMIT_JSON_KEYS = new Set(["server_time"]);

function toStableJson(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(toStableJson);
  if (!isRecord(value)) return value;

  const keys = Object.keys(value)
    .filter((k) => !OMIT_JSON_KEYS.has(k))
    .sort(compareStrings);

  const out: Record<string, unknown> = {};
  for (const key of keys) {
    out[key] = toStableJson(value[key]);
  }
  return out;
}

function stableStringify(value: unknown): string {
  return JSON.stringify(toStableJson(value), null, 2);
}

function formatSimilarityScore(score: unknown): string {
  if (typeof score !== "number" || !Number.isFinite(score)) return "-";
  return score.toFixed(4);
}

function formatRiskScore(score: unknown): string {
  if (typeof score !== "number" || !Number.isFinite(score)) return "-";
  return score.toFixed(1);
}

function collectFindingTacticsTechniques(findings: Record<string, unknown>[]): {
  tacticIds: string[];
  techniqueIds: string[];
} {
  const tactics: string[] = [];
  const techniques: string[] = [];

  for (const f of findings) {
    for (const v of toStringArray(getIn(f, ["threat", "tactic", "id"]))) tactics.push(v);
    for (const v of toStringArray(getIn(f, ["threat", "technique", "id"]))) techniques.push(v);
    for (const v of toStringArray(getIn(f, ["threat", "technique", "subtechnique", "id"])))
      techniques.push(v);
  }

  return {
    tacticIds: uniqSortedStrings(tactics),
    techniqueIds: uniqSortedStrings(techniques),
  };
}

function pickEdgeProps(edge: GraphApiEdge): Record<string, unknown> {
  const props = isRecord(edge.props) ? edge.props : {};
  return {
    src_uid: edge.src_uid,
    dst_uid: edge.dst_uid,
    rtype: edge.rtype,
    props,
  };
}

export function generateMarkdownReport(data: ReportData): string {
  const lines: string[] = [];

  const updatedEdges = data.task["task.result.trace.updated_edges"];
  const pathEdgeCount = data.task["task.result.trace.path_edges"];

  const findingsCoverage = collectFindingTacticsTechniques(data.canonicalFindings);

  lines.push(`# Attack Trace Report`);
  lines.push("");

  lines.push(`## 1. 报告元信息`);
  lines.push("");
  lines.push(`- task_id: \`${data.taskId}\``);
  lines.push(`- task_status: \`${data.taskStatus}\``);
  lines.push(`- task_progress: \`${String(data.task["task.progress"] ?? "-")}\``);
  lines.push(`- task_started_at: \`${String(data.task["task.started_at"] ?? "-")}\``);
  lines.push(`- task_finished_at: \`${String(data.task["task.finished_at"] ?? "-")}\``);
  lines.push(`- host_id: \`${data.hostId ?? "-"}\``);
  lines.push(`- trace.updated_edges: \`${String(updatedEdges ?? "-")}\``);
  lines.push(`- trace.path_edges: \`${String(pathEdgeCount ?? "-")}\``);
  if (typeof data.task["task.result.summary"] === "string" && data.task["task.result.summary"]) {
    lines.push(`- summary: ${data.task["task.result.summary"]}`);
  }
  if (data.notes.length) {
    lines.push(`- notes:`);
    for (const note of data.notes) {
      lines.push(`  - ${note}`);
    }
  }
  lines.push("");

  lines.push(`## 2. 输入与边界`);
  lines.push("");
  lines.push(`- target_node_uid: \`${data.targetNodeUid}\``);
  lines.push(`- window.start_ts: \`${data.startTs}\``);
  lines.push(`- window.end_ts: \`${data.endTs}\``);
  lines.push("");

  lines.push(`## 3. 告警与证据摘要`);
  lines.push("");
  lines.push(`- Canonical Findings: \`${data.canonicalFindings.length}\`${data.canonicalFindingsTruncated ? " (truncated)" : ""}`);
  lines.push(`- 覆盖战术（Canonical）: ${findingsCoverage.tacticIds.length ? findingsCoverage.tacticIds.map((v) => `\`${v}\``).join(", ") : "-"}`);
  lines.push(`- 覆盖技术（Canonical）: ${findingsCoverage.techniqueIds.length ? findingsCoverage.techniqueIds.map((v) => `\`${v}\``).join(", ") : "-"}`);
  lines.push("");

  if (data.canonicalFindings.length) {
    lines.push(`### 3.1 告警列表（固定排序）`);
    lines.push("");
    for (const f of data.canonicalFindings) {
      const ts = getIn(f, ["@timestamp"]);
      const id = getIn(f, ["event", "id"]);
      const dataset = getIn(f, ["event", "dataset"]);
      const ruleId = getIn(f, ["rule", "id"]);
      const ruleName = getIn(f, ["rule", "name"]);
      const tacticId = getIn(f, ["threat", "tactic", "id"]);
      const techId = getIn(f, ["threat", "technique", "id"]);
      const evidence = toStringArray(getIn(f, ["custom", "evidence", "event_ids"]));

      const ruleText =
        typeof ruleId === "string" && ruleId
          ? ruleId
          : typeof ruleName === "string" && ruleName
            ? ruleName
            : "-";

      lines.push(
        `- [\`${String(ts ?? "-")}\`] event.id=\`${String(id ?? "-")}\` dataset=\`${String(dataset ?? "-")}\` rule=\`${ruleText}\` tactic=\`${String(tacticId ?? "-")}\` technique=\`${String(techId ?? "-")}\` evidence=${evidence.length ? evidence.map((v) => `\`${v}\``).join(", ") : "-"}`
      );
    }
    lines.push("");
  } else {
    lines.push(`> 说明：未获取到 Canonical Findings（可能 host_id 无法提取，或该时间窗内无告警）。`);
    lines.push("");
  }

  lines.push(`## 4. 溯源关键路径`);
  lines.push("");
  lines.push(`- path_edges: \`${data.pathEdges.length}\``);
  lines.push(`- nodes_in_path: \`${uniqSortedStrings(new Set(data.pathEdges.flatMap((e) => [e.src_uid, e.dst_uid]))).length}\``);
  lines.push("");

  if (data.pathEdges.length) {
    lines.push(`### 4.1 关键路径边（固定排序）`);
    lines.push("");
    for (const edge of data.pathEdges) {
      const props = isRecord(edge.props) ? edge.props : {};

      const tsFloat = props["ts_float"];
      const eventId = props["event.id"];
      const dataset = props["event.dataset"];
      const evidence = toStringArray(props["custom.evidence.event_ids"]);
      const isAlarm = props["is_alarm"] === true;

      lines.push(`- \`${edge.src_uid}\` -[\`${edge.rtype}\`]-> \`${edge.dst_uid}\``);
      lines.push(`  - ts_float: \`${String(tsFloat ?? "-")}\``);
      lines.push(`  - event.id: \`${String(eventId ?? "-")}\``);
      lines.push(`  - event.dataset: \`${String(dataset ?? "-")}\``);
      lines.push(
        `  - custom.evidence.event_ids: ${evidence.length ? evidence.map((v) => `\`${v}\``).join(", ") : "-"}`
      );
      lines.push(`  - analysis.task_id: \`${String(props["analysis.task_id"] ?? "-")}\``);
      lines.push(`  - analysis.is_path_edge: \`${String(props["analysis.is_path_edge"] ?? "-")}\``);
      lines.push(`  - analysis.risk_score: \`${formatRiskScore(props["analysis.risk_score"])}\``);
      lines.push(
        `  - analysis.ttp.technique_ids: ${
          toStringArray(props["analysis.ttp.technique_ids"]).length
            ? toStringArray(props["analysis.ttp.technique_ids"])
                .map((v) => `\`${v}\``)
                .join(", ")
            : "-"
        }`
      );
      lines.push(`  - analysis.summary: ${typeof props["analysis.summary"] === "string" ? props["analysis.summary"] : "-"}`);
      if (isAlarm) {
        lines.push(`  - is_alarm: \`true\``);
        lines.push(`  - rule.id: \`${String(props["rule.id"] ?? "-")}\``);
        lines.push(`  - rule.name: \`${String(props["rule.name"] ?? "-")}\``);
        lines.push(`  - threat.tactic.id: \`${String(props["threat.tactic.id"] ?? "-")}\``);
        lines.push(`  - threat.technique.id: \`${String(props["threat.technique.id"] ?? "-")}\``);
        lines.push(`  - custom.finding.stage: \`${String(props["custom.finding.stage"] ?? "-")}\``);
        lines.push(`  - custom.finding.providers: \`${String(props["custom.finding.providers"] ?? "-")}\``);
      }
    }
    lines.push("");
  } else {
    lines.push(`> 说明：该任务未产生关键路径边（可能时间窗内无告警边，或该任务未写回任何边）。`);
    lines.push("");
  }

  lines.push(`## 5. APT 相似度匹配结果`);
  lines.push("");
  lines.push(`- source: \`${data.ttpSimilarity.source}\``);
  lines.push(
    `- 覆盖战术（TTP）: ${
      data.ttpSimilarity.attack_tactics.length
        ? data.ttpSimilarity.attack_tactics.map((v) => `\`${v}\``).join(", ")
        : "-"
    }`
  );
  lines.push(
    `- 覆盖技术（TTP）: ${
      data.ttpSimilarity.attack_techniques.length
        ? data.ttpSimilarity.attack_techniques.map((v) => `\`${v}\``).join(", ")
        : "-"
    }`
  );
  lines.push("");

  if (data.ttpSimilarity.similar_apts.length) {
    lines.push(`### 5.1 Top-3 相似组织`);
    lines.push("");
    data.ttpSimilarity.similar_apts.slice(0, 3).forEach((item, index) => {
      const name =
        item.intrusion_set?.name ?? item.intrusion_set?.id ?? `APT-${index + 1}`;
      lines.push(`- ${index + 1}. ${name} (score=${formatSimilarityScore(item.similarity_score)})`);
      if (Array.isArray(item.top_tactics) && item.top_tactics.length) {
        lines.push(`  - top_tactics: ${uniqSortedStrings(item.top_tactics).map((v) => `\`${v}\``).join(", ")}`);
      }
      if (Array.isArray(item.top_techniques) && item.top_techniques.length) {
        lines.push(`  - top_techniques: ${uniqSortedStrings(item.top_techniques).map((v) => `\`${v}\``).join(", ")}`);
      }
    });
    lines.push("");
  } else {
    lines.push(`> 说明：暂无相似组织结果（可能该时间窗内无 Canonical Findings，或 CTI 未配置）。`);
    lines.push("");
  }

  lines.push(`## 6. 附录：原始数据（JSON）`);
  lines.push("");
  lines.push(`### 6.1 任务文档（task）`);
  lines.push("");
  lines.push("```json");
  lines.push(stableStringify(data.task));
  lines.push("```");
  lines.push("");

  lines.push(`### 6.2 关键路径边（Top ${APPENDIX_EDGE_LIMIT}）`);
  lines.push("");
  lines.push("```json");
  lines.push(
    stableStringify(
      data.pathEdges.slice(0, APPENDIX_EDGE_LIMIT).map((edge) => pickEdgeProps(edge))
    )
  );
  lines.push("```");
  lines.push("");

  lines.push(`### 6.3 Canonical Findings（Top ${APPENDIX_FINDING_LIMIT}）`);
  lines.push("");
  lines.push("```json");
  lines.push(stableStringify(data.canonicalFindings.slice(0, APPENDIX_FINDING_LIMIT)));
  lines.push("```");
  lines.push("");

  lines.push(`### 6.4 TTP 相似度（归一化）`);
  lines.push("");
  lines.push("```json");
  lines.push(
    stableStringify({
      source: data.ttpSimilarity.source,
      attack_tactics: data.ttpSimilarity.attack_tactics,
      attack_techniques: data.ttpSimilarity.attack_techniques,
      similar_apts: data.ttpSimilarity.similar_apts,
    })
  );
  lines.push("```");
  lines.push("");

  return lines.join("\n");
}
