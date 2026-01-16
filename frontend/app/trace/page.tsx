"use client";

import { Graph } from "@antv/g6";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState } from "react";
import { toast } from "sonner";
import { Card, CardContent } from "@/components/card/card2";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetFooter,
  SheetTitle,
} from "@/components/ui/sheet";
import { Button } from "@/components/button/button";
import { ExportButton } from "@/components/export-button";
import { Slider } from "@/components/ui/slider";
import {
  fetchGraphQuery,
  type GraphApiEdge,
  type GraphApiNode,
  type GraphQueryRequest,
} from "@/lib/api/graph";
import {
  createAnalysisTask,
  fetchAnalysisTask,
  type AnalysisTaskItem,
} from "@/lib/api/analysis";
import { KillChainPanel } from "@/components/killchain/killchain-panel";

type GraphNode = {
  id: string;
  group: string;
  label?: string;
  raw?: GraphApiNode;
};

type GraphLink = {
  id: string;
  source: string;
  target: string;
  rtype: string;
  value?: number;
  count: number;
  records: GraphApiEdge[];
};

const NODE_TYPE_STYLES: Record<
  string,
  { fill: string; stroke: string; size: number }
> = {
  Host: { fill: "#E2E8F0", stroke: "#1E293B", size: 34 },
  User: { fill: "#FDE68A", stroke: "#92400E", size: 32 },
  Process: { fill: "#BFDBFE", stroke: "#1D4ED8", size: 30 },
  File: { fill: "#FECACA", stroke: "#B91C1C", size: 30 },
  IP: { fill: "#D9F99D", stroke: "#3F6212", size: 28 },
  Domain: { fill: "#E9D5FF", stroke: "#6B21A8", size: 30 },
};

const DEFAULT_NODE_STYLE = { fill: "#E2E8F0", stroke: "#334155", size: 30 };

function getNodeGroup(datum: unknown): string {
  const node = datum as GraphNode;
  return typeof node.group === "string" ? node.group : "";
}

function getNodeLabelText(datum: unknown): string {
  const node = datum as GraphNode;
  if (typeof node.label === "string" && node.label.trim() !== "") {
    return node.label;
  }
  return node.id ? String(node.id) : "";
}

const EDGE_PROP_LABELS: Array<{ key: string; label: string }> = [
  { key: "@timestamp", label: "时间" },
  { key: "event.category", label: "类别" },
  { key: "event.kind", label: "事件类型" },
  { key: "event.action", label: "动作" },
  { key: "event.severity", label: "严重性" },
  { key: "event.dataset", label: "数据集" },
  { key: "event.type", label: "事件子类" },
  { key: "event.id", label: "事件 ID" },
  { key: "analysis.task_id", label: "溯源任务" },
  { key: "analysis.is_path_edge", label: "关键路径" },
  { key: "analysis.risk_score", label: "风险分" },
  { key: "analysis.ttp.technique_ids", label: "路径技术 ID" },
  { key: "analysis.summary", label: "分析摘要" },
  { key: "analysis.updated_at", label: "分析更新时间" },
  { key: "network.transport", label: "协议" },
  { key: "destination.port", label: "端口" },
  { key: "rule.id", label: "规则 ID" },
  { key: "rule.name", label: "规则名" },
  { key: "rule.ruleset", label: "规则集" },
  { key: "threat.framework", label: "威胁框架" },
  { key: "threat.tactic.id", label: "战术 ID" },
  { key: "threat.tactic.name", label: "战术" },
  { key: "threat.technique.id", label: "技术 ID" },
  { key: "threat.technique.name", label: "技术" },
  { key: "flow.id", label: "流 ID" },
  { key: "network.community_id", label: "社区 ID" },
  { key: "custom.confidence", label: "置信度" },
  { key: "custom.finding.stage", label: "阶段" },
  { key: "custom.finding.fingerprint", label: "指纹" },
  { key: "custom.finding.providers", label: "提供方" },
  { key: "custom.evidence.event_ids", label: "证据事件" },
  { key: "ts_float", label: "时间戳(浮点)" },
  { key: "ts", label: "时间戳" },
  { key: "is_alarm", label: "告警" },
];

function formatEdgeProp(value: unknown): string {
  if (value === null || value === undefined) return "-";
  if (Array.isArray(value)) {
    return value
      .map((item) => (typeof item === "string" ? item : JSON.stringify(item)))
      .join(", ");
  }
  if (typeof value === "object") {
    try {
      return JSON.stringify(value);
    } catch {
      return String(value);
    }
  }
  return String(value);
}

function truncateText(value: string, maxLength = 16): string {
  if (value.length <= maxLength) return value;
  return `${value.slice(0, Math.max(0, maxLength - 1))}…`;
}

type TargetLike = {
  id?: unknown;
  parent?: unknown;
  parentNode?: unknown;
};

function getTargetLike(value: unknown): TargetLike | null {
  if (value && typeof value === "object") {
    return value as TargetLike;
  }
  return null;
}

function getEventTargetId(event: unknown): string | undefined {
  if (!event || typeof event !== "object") return undefined;
  const target = (event as { target?: unknown }).target;
  const targetLike = getTargetLike(target);
  const id = targetLike?.id;
  if (typeof id === "string" || typeof id === "number") {
    return String(id);
  }
  return undefined;
}

function resolveEdgeIdFromEvent(
  event: unknown,
  graph: Graph
): string | undefined {
  if (!event || typeof event !== "object") return undefined;
  let current = getTargetLike((event as { target?: unknown }).target);
  for (let depth = 0; depth < 4 && current; depth += 1) {
    const id = current.id;
    if (typeof id === "string" || typeof id === "number") {
      const edgeId = String(id);
      try {
        const edgeData = graph.getEdgeData(edgeId);
        if (edgeData) return edgeId;
      } catch {
        // ignore
      }
    }
    current = getTargetLike(current.parent ?? current.parentNode ?? null);
  }
  return undefined;
}

function getNodeLabel(node: GraphApiNode): string {
  const props = node.props ?? {};
  const key = node.key ?? {};

  const candidates = [
    props["host.name"],
    props["user.name"],
    props["process.name"],
    props["file.name"],
    props["file.path"],
    props["domain"],
    props["ip"],
    key["host.id"],
    key["user.name"],
    key["process.entity_id"],
    key["file.path"],
    key["ip"],
    node.uid,
  ];

  for (const value of candidates) {
    if (typeof value === "string" && value.trim() !== "") {
      return value;
    }
  }

  return node.uid;
}

type ViewMode = "alarm" | "window" | "task";

function computeRecentWindow(minutes: number): {
  startTs: string;
  endTs: string;
} {
  const safeMinutes = Number.isFinite(minutes) ? Math.max(1, minutes) : 5;
  const end = new Date();
  const start = new Date(end.getTime() - safeMinutes * 60 * 1000);
  return { startTs: start.toISOString(), endTs: end.toISOString() };
}

function getTaskStatus(task?: AnalysisTaskItem | null): string {
  const raw = task?.["task.status"];
  return typeof raw === "string" ? raw : "unknown";
}

function getTaskFromResponse(response: unknown): AnalysisTaskItem | null {
  if (!response || typeof response !== "object") return null;
  const obj = response as Record<string, unknown>;
  if (obj.status !== "ok") return null;
  const task = obj.task;
  if (!task || typeof task !== "object") return null;
  return task as AnalysisTaskItem;
}

type SimilarAptItem = {
  intrusion_set?: { id?: string; name?: string };
  similarity_score?: number;
  top_tactics?: string[];
  top_techniques?: string[];
};

function toSimilarAptItems(value: unknown): SimilarAptItem[] {
  if (!Array.isArray(value)) return [];
  const items: SimilarAptItem[] = [];
  for (const rawItem of value) {
    if (!rawItem || typeof rawItem !== "object") continue;
    const obj = rawItem as Record<string, unknown>;
    const intrusion = obj["intrusion_set"];
    const intrusionObj =
      intrusion && typeof intrusion === "object"
        ? (intrusion as Record<string, unknown>)
        : null;
    const intrusionSetId = intrusionObj?.["id"];
    const intrusionSetName = intrusionObj?.["name"];
    const similarityScore = obj["similarity_score"];

    const topTactics = obj["top_tactics"];
    const topTechniques = obj["top_techniques"];

    items.push({
      intrusion_set: {
        id: typeof intrusionSetId === "string" ? intrusionSetId : undefined,
        name:
          typeof intrusionSetName === "string" ? intrusionSetName : undefined,
      },
      similarity_score:
        typeof similarityScore === "number" ? similarityScore : undefined,
      top_tactics: Array.isArray(topTactics)
        ? topTactics.filter((v) => typeof v === "string")
        : undefined,
      top_techniques: Array.isArray(topTechniques)
        ? topTechniques.filter((v) => typeof v === "string")
        : undefined,
    });
  }
  return items;
}

export default function TracePage() {
  const queryClient = useQueryClient();
  const containerRef = useRef<HTMLDivElement>(null);
  const graphRef = useRef<Graph | null>(null);
  const handledTaskResultIdRef = useRef<string | null>(null);
  const [size, setSize] = useState({ width: 0, height: 0 });
  const [sheetOpen, setSheetOpen] = useState(false);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<{
    source: string;
    target: string;
    records: GraphApiEdge[];
  } | null>(null);
  const [viewMode, setViewMode] = useState<ViewMode>("window");
  const [onlyAlarm, setOnlyAlarm] = useState(true);
  const [recentMinutes, setRecentMinutes] = useState(15);
  const [activeWindow, setActiveWindow] = useState<{
    startTs: string;
    endTs: string;
  } | null>(null);
  const [activeTaskId, setActiveTaskId] = useState<string | null>(null);
  const [killChainPathIds, setKillChainPathIds] = useState<Set<string>>(
    new Set()
  );

  const graphQueryRequest = useMemo<GraphQueryRequest | null>(() => {
    if (viewMode === "alarm") {
      return { action: "alarm_edges" };
    }
    if (viewMode === "task") {
      if (!activeTaskId) return null;
      return {
        action: "analysis_edges_by_task",
        task_id: activeTaskId,
        only_path: true,
      };
    }
    if (!activeWindow) return null;
    return {
      action: "edges_in_window",
      start_ts: activeWindow.startTs,
      end_ts: activeWindow.endTs,
      allowed_reltypes: null,
      only_alarm: onlyAlarm,
    };
  }, [
    activeTaskId,
    activeWindow?.endTs,
    activeWindow?.startTs,
    onlyAlarm,
    viewMode,
  ]);

  const { data: graphResponse, isFetching: isGraphFetching } = useQuery({
    queryKey: [
      "graph-query",
      graphQueryRequest?.action ?? "none",
      activeWindow?.startTs ?? "none",
      activeWindow?.endTs ?? "none",
      onlyAlarm,
      activeTaskId,
    ],
    queryFn: () => fetchGraphQuery(graphQueryRequest as GraphQueryRequest),
    enabled: !!graphQueryRequest,
  });
  const createTaskMutation = useMutation({
    mutationFn: createAnalysisTask,
    onSuccess: (data) => {
      if (data.status === "ok") {
        if (data.task_id) {
          setActiveTaskId(data.task_id);
          handledTaskResultIdRef.current = null;
        }
        toast.success("溯源任务已创建", {
          className: "border-[var(--chart-2)] text-[var(--chart-2)]",
        });
        setSheetOpen(false);
        return;
      }

      toast.error(data.error?.message ?? "创建溯源任务失败", {
        className: "border-[var(--destructive)] text-[var(--destructive)]",
      });
    },
    onError: () => {
      toast.error("创建溯源任务失败", {
        className: "border-[var(--destructive)] text-[var(--destructive)]",
      });
    },
  });

  const { data: taskResponse } = useQuery({
    queryKey: ["analysis-task", activeTaskId],
    queryFn: () => fetchAnalysisTask(activeTaskId as string),
    enabled: !!activeTaskId,
    refetchInterval: (query) => {
      const data = query.state.data as unknown;
      if (!data || typeof data !== "object") return 1000;
      const status = (data as { status?: unknown }).status;
      if (status !== "ok") return 1000;
      const task = (data as { task?: AnalysisTaskItem }).task;
      const taskStatus = getTaskStatus(task);
      if (taskStatus === "succeeded" || taskStatus === "failed") return false;
      return 1000;
    },
  });

  const activeTask: AnalysisTaskItem | null = getTaskFromResponse(taskResponse);
  const activeTaskStatus = getTaskStatus(activeTask);
  const activeTaskProgressRaw = activeTask?.["task.progress"];
  const activeTaskProgress =
    typeof activeTaskProgressRaw === "number"
      ? Math.min(100, Math.max(0, activeTaskProgressRaw))
      : 0;
  const ttpSimilarApts = toSimilarAptItems(
    activeTask?.["task.result.ttp_similarity.similar_apts"] ?? null
  );
  const attackTactics = Array.isArray(
    activeTask?.["task.result.ttp_similarity.attack_tactics"]
  )
    ? (activeTask?.["task.result.ttp_similarity.attack_tactics"] as string[])
    : [];
  const attackTechniques = Array.isArray(
    activeTask?.["task.result.ttp_similarity.attack_techniques"]
  )
    ? (activeTask?.["task.result.ttp_similarity.attack_techniques"] as string[])
    : [];

  useEffect(() => {
    if (activeWindow) return;
    setActiveWindow(computeRecentWindow(recentMinutes));
  }, [activeWindow, recentMinutes]);

  useEffect(() => {
    if (!activeTaskId) return;
    if (!activeTask) return;
    if (handledTaskResultIdRef.current === activeTaskId) return;
    if (activeTaskStatus !== "succeeded" && activeTaskStatus !== "failed")
      return;

    handledTaskResultIdRef.current = activeTaskId;
    void queryClient.invalidateQueries({ queryKey: ["graph-query"] });

    if (activeTaskStatus === "succeeded") {
      toast.success("溯源任务已完成", {
        className: "border-[var(--chart-2)] text-[var(--chart-2)]",
      });
      return;
    }

    toast.error(activeTask?.["task.error"] ?? "溯源任务失败", {
      className: "border-[var(--destructive)] text-[var(--destructive)]",
    });
  }, [activeTask, activeTaskId, activeTaskStatus, queryClient]);

  useEffect(() => {
    if (!containerRef.current) return;
    const observer = new ResizeObserver((entries) => {
      const entry = entries[0];
      if (!entry) return;
      const { width, height } = entry.contentRect;
      setSize({ width, height });
    });
    observer.observe(containerRef.current);
    return () => observer.disconnect();
  }, []);

  const graphData = useMemo<{ nodes: GraphNode[]; links: GraphLink[] }>(() => {
    const rawNodes =
      graphResponse?.status === "ok" && Array.isArray(graphResponse.nodes)
        ? graphResponse.nodes
        : [];
    const rawEdges =
      graphResponse?.status === "ok" && Array.isArray(graphResponse.edges)
        ? graphResponse.edges
        : [];

    const nodes: GraphNode[] = rawNodes.map((node) => ({
      id: node.uid,
      group: node.ntype,
      label: getNodeLabel(node),
      raw: node,
    }));

    const edgeMap = new Map<
      string,
      { source: string; target: string; rtype: string; records: GraphApiEdge[] }
    >();

    rawEdges.forEach((edge) => {
      const key = `${edge.src_uid}__${edge.rtype}__${edge.dst_uid}`;
      const existing = edgeMap.get(key);
      if (existing) {
        existing.records.push(edge);
      } else {
        edgeMap.set(key, {
          source: edge.src_uid,
          target: edge.dst_uid,
          rtype: edge.rtype,
          records: [edge],
        });
      }
    });

    const links: GraphLink[] = Array.from(edgeMap.values()).map((entry) => ({
      id: `${entry.source}__${entry.rtype}__${entry.target}`,
      source: entry.source,
      target: entry.target,
      rtype: entry.rtype,
      count: entry.records.length,
      records: entry.records,
    }));

    return { nodes, links };
  }, [graphResponse]);
  const hasGraphData = graphData.nodes.length > 0 || graphData.links.length > 0;

  useEffect(() => {
    if (!containerRef.current) return;
    if (size.width === 0 || size.height === 0) return;
    if (graphRef.current) return;
    if (!hasGraphData) return;

    const graph = new Graph({
      container: containerRef.current,
      width: size.width,
      height: size.height,
      data: {
        nodes: graphData.nodes,
        edges: graphData.links,
      },
      node: {
        palette: {
          type: "group",
          field: "group",
        },
        style: {
          size: (datum) =>
            NODE_TYPE_STYLES[getNodeGroup(datum)]?.size ??
            DEFAULT_NODE_STYLE.size,
          fill: (datum) =>
            NODE_TYPE_STYLES[getNodeGroup(datum)]?.fill ??
            DEFAULT_NODE_STYLE.fill,
          stroke: (datum) =>
            NODE_TYPE_STYLES[getNodeGroup(datum)]?.stroke ??
            DEFAULT_NODE_STYLE.stroke,
          labelText: (datum) => getNodeLabelText(datum),
          labelFill: "#0F172A",
          labelFontSize: 12,
        },
      },
      edge: {
        type: "line",
        style: {
          stroke: (datum) => {
            const link = datum as GraphLink;
            // KillChain highlighting (highest priority)
            const kcData = activeTask?.["task.result.killchain"];
            if (
              kcData &&
              typeof kcData === "object" &&
              killChainPathIds.size > 0
            ) {
              const selectedPaths = Array.isArray(kcData.selected_paths)
                ? kcData.selected_paths
                : [];

              const hasKillChainEdge = link.records.some((edge) => {
                const edgeId = edge.props?.["event.id"];
                if (!edgeId || typeof edgeId !== "string") return false;

                return Array.from(killChainPathIds).some((pathId) => {
                  const path = selectedPaths.find(
                    (p: any) =>
                      p && typeof p === "object" && p.path_id === pathId
                  );
                  if (!path || !Array.isArray(path.edge_ids)) return false;
                  return path.edge_ids.includes(edgeId);
                });
              });
              if (hasKillChainEdge) return "#FF6B6B";
            }
            // Path edge
            const hasPathEdge = link.records.some(
              (edge) => edge.props?.["analysis.is_path_edge"] === true
            );
            if (hasPathEdge) return "#2563EB";
            // Alarm edge
            const hasAlarmEdge = link.records.some(
              (edge) => edge.props?.["is_alarm"] === true
            );
            if (hasAlarmEdge) return "#EF4444";
            // Default
            return "#64748B";
          },
          lineWidth: (datum) => {
            const link = datum as GraphLink;
            // KillChain highlighting (highest priority)
            const kcData = activeTask?.["task.result.killchain"];
            if (
              kcData &&
              typeof kcData === "object" &&
              killChainPathIds.size > 0
            ) {
              const hasKillChainEdge = link.records.some((edge) => {
                const edgeId = edge.props?.["event.id"];
                return (
                  edgeId &&
                  Array.from(killChainPathIds).some((pathId) => {
                    const path = (
                      kcData.selected_paths as Array<{
                        path_id: string;
                        edge_ids: string[];
                      }>
                    )?.find((p: any) => p.path_id === pathId);
                    return path?.edge_ids?.includes(edgeId);
                  })
                );
              });
              if (hasKillChainEdge) return 3;
            }
            // Path edge
            const hasPathEdge = link.records.some(
              (edge) => edge.props?.["analysis.is_path_edge"] === true
            );
            if (hasPathEdge) return 4;
            // Alarm edge
            const hasAlarmEdge = link.records.some(
              (edge) => edge.props?.["is_alarm"] === true
            );
            if (hasAlarmEdge) return 3;
            // Default
            return Math.min(10, 1 + (link.count ?? 1) * 0.4);
          },
          opacity: (datum) => {
            const link = datum as GraphLink;
            // KillChain highlighting (highest priority)
            const kcData = activeTask?.["task.result.killchain"];
            if (
              kcData &&
              typeof kcData === "object" &&
              killChainPathIds.size > 0
            ) {
              const hasKillChainEdge = link.records.some((edge) => {
                const edgeId = edge.props?.["event.id"];
                return (
                  edgeId &&
                  Array.from(killChainPathIds).some((pathId) => {
                    const path = (
                      kcData.selected_paths as Array<{
                        path_id: string;
                        edge_ids: string[];
                      }>
                    )?.find((p: any) => p.path_id === pathId);
                    return path?.edge_ids?.includes(edgeId);
                  })
                );
              });
              if (hasKillChainEdge) return 0.95;
            }
            // Path edge
            const hasPathEdge = link.records.some(
              (edge) => edge.props?.["analysis.is_path_edge"] === true
            );
            if (hasPathEdge) return 0.9;
            // Alarm edge
            const hasAlarmEdge = link.records.some(
              (edge) => edge.props?.["is_alarm"] === true
            );
            if (hasAlarmEdge) return 0.85;
            // Default
            return 0.55;
          },
          lineDash: (datum) => {
            const link = datum as GraphLink;
            // KillChain highlighting (highest priority)
            const kcData = activeTask?.["task.result.killchain"];
            if (
              kcData &&
              typeof kcData === "object" &&
              killChainPathIds.size > 0
            ) {
              const hasKillChainEdge = link.records.some((edge) => {
                const edgeId = edge.props?.["event.id"];
                return (
                  edgeId &&
                  Array.from(killChainPathIds).some((pathId) => {
                    const path = (
                      kcData.selected_paths as Array<{
                        path_id: string;
                        edge_ids: string[];
                      }>
                    )?.find((p: any) => p.path_id === pathId);
                    return path?.edge_ids?.includes(edgeId);
                  })
                );
              });
              if (hasKillChainEdge) return [5, 5];
            }
            return undefined;
          },
          labelText: (datum) => {
            const count = (datum as GraphLink).count ?? 0;
            return count > 1 ? `${count}` : "";
          },
          labelFill: "#0F172A",
          labelFontSize: 10,
        },
      },
      layout: {
        type: "force-atlas2",
        width: size.width,
        height: size.height,
        center: [size.width / 2, size.height / 2],
        // Tighten spacing: lower repulsion, stronger gravity/springs.
        kr: 200,
        kg: 0.5,
        ks: 0.4,
        ksmax: 5,
        barnesHut: true,
        dissuadeHubs: false,
        prune: false,
        preventOverlap: true,
        nodeSize: 32,
      },
      behaviors: ["drag-canvas", "zoom-canvas", "drag-node"],
    });

    graph.on("node:click", (event: unknown) => {
      const nodeId = getEventTargetId(event);
      if (!nodeId) return;
      const nodeData = graph.getNodeData(nodeId) as GraphNode;
      if (!nodeData) return;
      setSelectedNode({
        id: String(nodeData.id),
        group: String(nodeData.group ?? ""),
      });
      setSelectedEdge(null);
      setSheetOpen(true);
    });

    const openEdgeDetails = (edgeId?: string) => {
      if (!edgeId) return;
      const edgeData = graph.getEdgeData(edgeId) as GraphLink;
      if (!edgeData) return;
      setSelectedEdge({
        source: String(edgeData.source),
        target: String(edgeData.target),
        records: edgeData.records ?? [],
      });
      setSelectedNode(null);
      setSheetOpen(true);
    };

    graph.on("edge:click", (event: unknown) => {
      const edgeId = resolveEdgeIdFromEvent(event, graph);
      openEdgeDetails(edgeId);
    });

    graph.render();
    void graph.fitView();
    graphRef.current = graph;
  }, [graphData, hasGraphData, size.height, size.width]);

  useEffect(() => {
    const graph = graphRef.current;
    if (!graph) return;
    if (!hasGraphData) return;
    graph.setData({
      nodes: graphData.nodes,
      edges: graphData.links,
    });
    void graph
      .layout()
      .then(() => graph.fitView())
      .catch(() => {});
  }, [graphData, hasGraphData]);

  useEffect(() => {
    const graph = graphRef.current;
    if (!graph) return;
    if (size.width === 0 || size.height === 0) return;
    graph.setSize(size.width, size.height);
    void graph.fitView();
  }, [size.height, size.width]);

  useEffect(() => {
    return () => {
      graphRef.current?.destroy();
      graphRef.current = null;
    };
  }, []);

  return (
    <div className="flex h-[calc(100vh-96px)] min-h-0 flex-col gap-4 overflow-hidden p-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <h1 className="text-2xl font-semibold text-foreground">溯源分析</h1>
        <div className="flex flex-wrap items-center gap-2">
          <Button
            type="button"
            size="sm"
            variant={viewMode === "window" ? "default" : "outline"}
            onClick={() => setViewMode("window")}
          >
            时间窗视图
          </Button>
          <Button
            type="button"
            size="sm"
            variant={viewMode === "alarm" ? "default" : "outline"}
            onClick={() => setViewMode("alarm")}
          >
            告警视图
          </Button>
          <Button
            type="button"
            size="sm"
            variant={viewMode === "task" ? "default" : "outline"}
            disabled={!activeTaskId || activeTaskStatus !== "succeeded"}
            onClick={() => setViewMode("task")}
          >
            任务视图
          </Button>
        </div>
      </div>

      <Card>
        <CardContent className="space-y-4 p-4">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="text-sm text-foreground">
                时间窗：最近{" "}
                <span className="font-semibold">{recentMinutes}</span> 分钟
              </div>
              <div className="text-xs text-muted-foreground">
                当前窗口：{activeWindow?.startTs ?? "-"} →{" "}
                {activeWindow?.endTs ?? "-"}
              </div>
              {activeTaskId ? (
                <div className="space-y-2 pt-1">
                  <div className="flex flex-wrap items-center gap-2 text-xs">
                    <span className="text-muted-foreground">任务：</span>
                    <span className="font-mono">{activeTaskId}</span>
                    <span className="rounded bg-muted px-2 py-0.5 text-foreground">
                      {activeTaskStatus}
                    </span>
                    <span className="text-muted-foreground">
                      {activeTaskProgress}%
                    </span>
                    <Button
                      type="button"
                      size="sm"
                      variant="ghost"
                      className="h-7 px-2 text-xs"
                      onClick={() => {
                        setActiveTaskId(null);
                        handledTaskResultIdRef.current = null;
                        if (viewMode === "task") setViewMode("window");
                      }}
                    >
                      清除
                    </Button>
                  </div>
                  <div className="h-2 w-full max-w-[360px] overflow-hidden rounded-full bg-muted">
                    <div
                      className="h-full rounded-full bg-primary transition-all"
                      style={{ width: `${activeTaskProgress}%` }}
                    />
                  </div>
                  {activeTaskStatus === "failed" &&
                  activeTask?.["task.error"] ? (
                    <div className="text-xs text-destructive">
                      {activeTask["task.error"]}
                    </div>
                  ) : null}
                  {activeTaskStatus === "succeeded" ? (
                    <div className="space-y-3 pt-2">
                      <div className="rounded-md border border-border/60 p-3">
                        <div className="flex items-center justify-between gap-3">
                          <div className="text-sm font-semibold text-foreground">
                            TTP 相似度（Top-3）
                          </div>
                          <ExportButton
                            taskId={activeTaskId}
                            taskStatus={activeTaskStatus}
                          />
                        </div>
                        <div className="mt-1 text-xs text-muted-foreground">
                          {attackTactics.length ? (
                            <div>覆盖战术：{attackTactics.join(", ")}</div>
                          ) : (
                            <div>覆盖战术：-</div>
                          )}
                          {attackTechniques.length ? (
                            <div>覆盖技术：{attackTechniques.join(", ")}</div>
                          ) : (
                            <div>覆盖技术：-</div>
                          )}
                        </div>
                        <div className="mt-3 space-y-2">
                          {ttpSimilarApts.length ? (
                            ttpSimilarApts.slice(0, 3).map((item, index) => {
                              const name =
                                item.intrusion_set?.name ??
                                item.intrusion_set?.id ??
                                `APT-${index + 1}`;
                              const score =
                                typeof item.similarity_score === "number"
                                  ? item.similarity_score.toFixed(2)
                                  : "-";
                              return (
                                <div
                                  key={`${
                                    item.intrusion_set?.id ?? name
                                  }-${index}`}
                                  className="rounded-md bg-muted/40 px-3 py-2"
                                >
                                  <div className="flex items-center justify-between gap-3 text-sm">
                                    <span className="font-medium text-foreground">
                                      {name}
                                    </span>
                                    <span className="font-mono text-xs text-muted-foreground">
                                      {score}
                                    </span>
                                  </div>
                                  <div className="mt-1 text-xs text-muted-foreground">
                                    {item.top_tactics?.length ? (
                                      <div>
                                        Top Tactics：
                                        {item.top_tactics.join(", ")}
                                      </div>
                                    ) : null}
                                    {item.top_techniques?.length ? (
                                      <div>
                                        Top Techniques：
                                        {item.top_techniques.join(", ")}
                                      </div>
                                    ) : null}
                                  </div>
                                </div>
                              );
                            })
                          ) : (
                            <div className="text-xs text-muted-foreground">
                              暂无相似组织结果（可能该时间窗内没有 Canonical
                              Findings，或 CTI 未配置）。
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  ) : null}
                  {/* KillChain Panel */}
                  {activeTask?.["task.result.killchain_uuid"] && (
                    <div className="mt-3">
                      <KillChainPanel
                        task={activeTask}
                        onHighlightPath={setKillChainPathIds}
                        killChainPathIds={killChainPathIds}
                      />
                    </div>
                  )}
                </div>
              ) : null}
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <Button
                type="button"
                variant="outline"
                size="sm"
                disabled={isGraphFetching}
                onClick={() => {
                  if (viewMode !== "window") setViewMode("window");
                  setActiveWindow(computeRecentWindow(recentMinutes));
                }}
              >
                {isGraphFetching ? "刷新中…" : "刷新图谱"}
              </Button>
              <Button
                type="button"
                variant={onlyAlarm ? "default" : "outline"}
                size="sm"
                disabled={viewMode !== "window"}
                onClick={() => setOnlyAlarm((v) => !v)}
              >
                仅告警
              </Button>
            </div>
          </div>
          <Slider
            min={1}
            max={720}
            step={1}
            value={[recentMinutes]}
            onValueChange={(value) => {
              const next = Array.isArray(value) ? value[0] : value;
              if (typeof next === "number") {
                setRecentMinutes(next);
              }
            }}
          />
        </CardContent>
      </Card>

      <Card className="flex min-h-0 flex-1 flex-col overflow-hidden">
        <CardContent className="flex-1 p-0">
          <div ref={containerRef} className="h-full w-full" />
        </CardContent>
      </Card>
      <Sheet
        open={sheetOpen}
        onOpenChange={(open) => {
          setSheetOpen(open);
          if (!open) {
            setSelectedNode(null);
            setSelectedEdge(null);
          }
        }}
      >
        <SheetContent side="right">
          <SheetHeader>
            <SheetTitle>
              {selectedEdge ? "边详情" : selectedNode?.id ?? "节点详情"}
            </SheetTitle>
            <SheetDescription>
              {selectedEdge ? "攻击路径边记录" : "攻击路径节点信息"}
            </SheetDescription>
          </SheetHeader>
          <div className="px-4 text-sm text-muted-foreground">
            {selectedEdge ? (
              <div className="space-y-3">
                <div className="text-xs text-muted-foreground">
                  {selectedEdge.source} → {selectedEdge.target}
                </div>
                <div className="text-sm text-foreground">
                  共 {selectedEdge.records.length} 条边记录
                </div>
                <div className="max-h-[50vh] space-y-2 overflow-auto pr-2 text-sm">
                  {selectedEdge.records.slice(0, 50).map((record, index) => (
                    <div
                      key={`${record.rtype}-${index}`}
                      className="rounded-md border border-border/60 px-3 py-2"
                    >
                      <div className="text-foreground">
                        {formatEdgeProp(record.props?.["event.category"]) ||
                          "未标注"}
                      </div>
                      <div className="text-xs text-muted-foreground">
                        {record.rtype}
                      </div>
                      <div className="mt-2 space-y-1 text-xs text-muted-foreground">
                        {EDGE_PROP_LABELS.map(({ key, label }) => (
                          <div key={key} className="flex gap-2">
                            <span className="w-28 shrink-0 text-foreground">
                              {label}：
                            </span>
                            <span>
                              {truncateText(
                                formatEdgeProp(record.props?.[key])
                              )}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                  {selectedEdge.records.length > 50 ? (
                    <div className="text-xs text-muted-foreground">
                      仅展示前 50 条记录
                    </div>
                  ) : null}
                </div>
              </div>
            ) : selectedNode ? (
              <div className="space-y-2">
                <div>
                  <span className="text-foreground">类型：</span>
                  {selectedNode.group}
                </div>
                <div>
                  <span className="text-foreground">节点 ID：</span>
                  {selectedNode.id}
                </div>
              </div>
            ) : (
              "点击图中的节点以查看详情。"
            )}
          </div>
          {selectedNode ? (
            <SheetFooter>
              <Button
                type="button"
                className="w-full"
                disabled={createTaskMutation.isPending}
                onClick={() => {
                  const window = computeRecentWindow(recentMinutes);
                  setOnlyAlarm(false);
                  setActiveWindow(window);
                  createTaskMutation.mutate({
                    target_node_uid: selectedNode.id,
                    start_ts: window.startTs,
                    end_ts: window.endTs,
                  });
                }}
              >
                {createTaskMutation.isPending ? "创建中…" : "创建溯源任务"}
              </Button>
            </SheetFooter>
          ) : null}
        </SheetContent>
      </Sheet>
    </div>
  );
}
