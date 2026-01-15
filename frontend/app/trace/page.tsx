"use client";

import { Graph } from "@antv/g6";
import { useMutation, useQuery } from "@tanstack/react-query";
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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/button/button";
import { Slider } from "@/components/ui/slider";
import {
  fetchGraphQuery,
  type GraphApiEdge,
  type GraphApiNode,
  type GraphQueryAction,
} from "@/lib/api/graph";
import {
  createAnalysisTask,
} from "@/lib/api/analysis";

type GraphNode = {
  id: string;
  group: string;
  label?: string;
};

type GraphLink = {
  id: string;
  source: string;
  target: string;
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
  edgeIndex: Map<string, GraphLink>
): string | undefined {
  if (!event || typeof event !== "object") return undefined;
  let current = getTargetLike((event as { target?: unknown }).target);
  for (let depth = 0; depth < 4 && current; depth += 1) {
    const id = current.id;
    if (
      (typeof id === "string" || typeof id === "number") &&
      edgeIndex.has(String(id))
    ) {
      return String(id);
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

export default function TracePage() {
  const containerRef = useRef<HTMLDivElement>(null);
  const graphRef = useRef<Graph | null>(null);
  const [size, setSize] = useState({ width: 0, height: 0 });
  const [sheetOpen, setSheetOpen] = useState(false);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<{
    source: string;
    target: string;
    records: GraphApiEdge[];
  } | null>(null);
  const [traceDialogOpen, setTraceDialogOpen] = useState(false);
  const [traceMinutes, setTraceMinutes] = useState(5);
  const [traceTargetUid, setTraceTargetUid] = useState<string | null>(null);
  const action: GraphQueryAction = "alarm_edges";
  const { data: graphResponse } = useQuery({
    queryKey: ["graph", action],
    queryFn: () => fetchGraphQuery(action),
  });
  const createTaskMutation = useMutation({
    mutationFn: createAnalysisTask,
    onSuccess: (data) => {
      if (data.status === "ok") {
        toast.success("溯源任务已创建", {
          className: "border-[var(--chart-2)] text-[var(--chart-2)]",
        });
        setTraceDialogOpen(false);
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
    const rawNodes = graphResponse?.nodes ?? [];
    const rawEdges = graphResponse?.edges ?? [];

    const nodes: GraphNode[] = rawNodes.map((node) => ({
      id: node.uid,
      group: node.ntype,
      label: getNodeLabel(node),
    }));

    const edgeMap = new Map<
      string,
      { source: string; target: string; records: GraphApiEdge[] }
    >();

    rawEdges.forEach((edge) => {
      const key = `${edge.src_uid}__${edge.dst_uid}`;
      const existing = edgeMap.get(key);
      if (existing) {
        existing.records.push(edge);
      } else {
        edgeMap.set(key, {
          source: edge.src_uid,
          target: edge.dst_uid,
          records: [edge],
        });
      }
    });

    const links: GraphLink[] = Array.from(edgeMap.values()).map(
      (entry, index) => ({
        id: `edge-${index}-${entry.source}-${entry.target}`,
        source: entry.source,
        target: entry.target,
        count: entry.records.length,
        records: entry.records,
      })
    );

    return { nodes, links };
  }, [graphResponse]);
  const edgeIndex = useMemo(() => {
    return new Map(graphData.links.map((edge) => [edge.id, edge]));
  }, [graphData.links]);
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
          stroke: "#64748B",
          lineWidth: (datum) =>
            Math.min(10, 1 + ((datum as GraphLink).count ?? 1) * 0.4),
          opacity: 0.55,
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
        kr: 400,
        kg: 0.1,
        ks: 0.1,
        ksmax: 10,
        barnesHut: true,
        dissuadeHubs: false,
        prune: false,
        preventOverlap: true,
        nodeSize: 32,
      },
      behaviors: ["drag-canvas", "zoom-canvas"],
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
      const edgeData = edgeIndex.get(edgeId);
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
      const edgeId = resolveEdgeIdFromEvent(event, edgeIndex);
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
    <div className="grid h-[calc(100vh-96px)] grid-cols-1 grid-rows-[auto_minmax(0,1fr)_minmax(0,1fr)] gap-10 overflow-hidden p-6">
      <h1 className="text-2xl font-semibold text-foreground">溯源分析</h1>
      <Card className="flex min-h-[360px] flex-col">
        <CardContent className="flex-1">
          <div ref={containerRef} className="h-full w-full"></div>
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
                onClick={() => {
                  setTraceTargetUid(selectedNode.id);
                  setTraceDialogOpen(true);
                }}
              >
                溯源分析
              </Button>
            </SheetFooter>
          ) : null}
        </SheetContent>
      </Sheet>
      <Dialog open={traceDialogOpen} onOpenChange={setTraceDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>创建溯源任务</DialogTitle>
            <DialogDescription>
              选择最近{" "}
              <span className="text-base font-semibold">
                {traceMinutes} 分钟
              </span>
              的数据进行回溯
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <Slider
              min={1}
              max={60}
              step={1}
              value={[traceMinutes]}
              onValueChange={(value) => {
                const next = Array.isArray(value) ? value[0] : value;
                if (typeof next === "number") {
                  setTraceMinutes(next);
                }
              }}
            />
            <Button
              type="button"
              className="w-full"
              disabled={!traceTargetUid || createTaskMutation.isPending}
              onClick={() => {
                if (!traceTargetUid) return;
                const endTs = new Date().toISOString();
                const startTs = new Date(
                  Date.now() - traceMinutes * 60 * 1000
                ).toISOString();
                createTaskMutation.mutate({
                  target_node_uid: traceTargetUid,
                  start_ts: startTs,
                  end_ts: endTs,
                });
              }}
            >
              创建溯源任务
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
