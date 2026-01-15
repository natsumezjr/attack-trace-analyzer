"use client";

import { useState } from "react";
import { Card, CardContent } from "@/components/card/card2";
import { ExportButton } from "@/components/export-button";
import { Button } from "@/components/button/button";
import type { AnalysisTaskItem } from "@/lib/api/analysis";

// Types
interface KillChainData {
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
}

interface KillChainPanelProps {
  task: AnalysisTaskItem;
  onHighlightPath?: (pathIds: string[]) => void;
  killChainPathIds?: Set<string>;
}

// Attack state Chinese mapping
const ATTACK_STATE_ZH_MAP: Record<string, string> = {
  "INITIAL_ACCESS": "初始入侵",
  "EXECUTION": "执行",
  "PRIVILEGE_ESCALATION": "权限提升",
  "LATERAL_MOVEMENT": "横向移动",
  "COMMAND_AND_CONTROL": "命令与控制",
  "DISCOVERY": "发现",
  "IMPACT": "影响",
  "RESOURCE_DEVELOPMENT": "资源开发",
  "PERSISTENCE": "持久化",
  "DEFENSE_EVASION": "防御规避",
  "CREDENTIAL_ACCESS": "凭证访问",
  "COLLECTION": "收集",
  "EXFILTRATION": "数据渗出",
};

// Helper functions
function getConfidenceLevel(confidence: number) {
  if (confidence > 0.7) {
    return {
      color: "bg-green-500",
      textColor: "text-green-600 dark:text-green-400",
      label: "高可信度",
    };
  }
  if (confidence >= 0.4) {
    return {
      color: "bg-yellow-500",
      textColor: "text-yellow-600 dark:text-yellow-400",
      label: "中等可信度",
    };
  }
  return {
    color: "bg-red-500",
    textColor: "text-red-600 dark:text-red-400",
    label: "低可信度",
  };
}

function formatTimestamp(ts: number): string {
  const date = new Date(ts * 1000);
  return date.toLocaleString("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function splitExplanation(explanation: string): { summary: string; full: string } {
  const sentences = explanation.split(/([。！？.?!])/);
  let fullText = "";
  let summaryText = "";
  let sentenceCount = 0;

  for (let i = 0; i < sentences.length; i++) {
    const part = sentences[i];
    if (!part) continue;

    fullText += part;
    if (i + 1 < sentences.length && /[。！？.?!]/.test(sentences[i + 1])) {
      fullText += sentences[i + 1];
      sentenceCount++;
      if (sentenceCount <= 3) {
        summaryText += part + sentences[i + 1];
      }
      i++; // Skip the punctuation
    }
  }

  return { summary: summaryText.trim(), full: fullText.trim() };
}

export function KillChainPanel({ task, onHighlightPath, killChainPathIds }: KillChainPanelProps) {
  const [isExpanded, setIsExpanded] = useState(false);
  const [expandedSegmentIdx, setExpandedSegmentIdx] = useState<number | null>(null);
  const [expandedPathIds, setExpandedPathIds] = useState<Set<string>>(new Set());

  // Extract killchain data from task
  const kcUuid = task["task.result.killchain_uuid"];
  const kcRaw = task["task.result.killchain"];

  if (!kcUuid) {
    return null;
  }

  // Parse killchain data
  const kcData: KillChainData | null = kcRaw && typeof kcRaw === "object" ? {
    kc_uuid: typeof kcRaw.kc_uuid === "string" ? kcRaw.kc_uuid : kcUuid || "",
    confidence: typeof kcRaw.confidence === "number" ? kcRaw.confidence : 0,
    segments: Array.isArray(kcRaw.segments)
      ? kcRaw.segments.filter((s): s is any =>
          s && typeof s === "object" && typeof s.seg_idx === "number"
        )
      : [],
    selected_paths: Array.isArray(kcRaw.selected_paths)
      ? kcRaw.selected_paths.filter((p): p is any =>
          p && typeof p === "object" && typeof p.path_id === "string"
        )
      : [],
    explanation: typeof kcRaw.explanation === "string" ? kcRaw.explanation : "",
  } : null;

  if (!kcData) {
    return (
      <div className="rounded-md border border-dashed border-border/60 p-6 text-center">
        <p className="text-sm text-muted-foreground">本次分析未生成 KillChain 攻击链</p>
        <p className="text-xs text-muted-foreground mt-1">
          可能原因：异常边不足、时间窗过短、或状态机未收敛
        </p>
      </div>
    );
  }

  const confidenceLevel = getConfidenceLevel(kcData.confidence);
  const percentage = Math.round(kcData.confidence * 100);
  const { summary: explanationSummary, full: explanationFull } = splitExplanation(kcData.explanation);

  // Handlers
  const handleExpand = () => {
    setIsExpanded(true);
    // Highlight all paths
    const allPathIds = Array.isArray(kcData.selected_paths)
      ? kcData.selected_paths
          .filter((p) => p && typeof p === "object" && typeof p.path_id === "string")
          .map((p) => p.path_id)
      : [];
    onHighlightPath?.(allPathIds);
  };

  const handleCollapse = () => {
    setIsExpanded(false);
    setExpandedSegmentIdx(null);
    setExpandedPathIds(new Set());
    onHighlightPath?.([]);
  };

  const handleToggleSegment = (idx: number) => {
    setExpandedSegmentIdx(prev => (prev === idx ? null : idx));
  };

  const handleTogglePath = (pathId: string) => {
    setExpandedPathIds(prev => {
      const newSet = new Set(prev);
      if (newSet.has(pathId)) {
        newSet.delete(pathId);
      } else {
        newSet.add(pathId);
      }
      return newSet;
    });
  };

  const handleHighlightSinglePath = (pathId: string) => {
    onHighlightPath?.([pathId]);
  };

  const isPathHighlighted = (pathId: string) => {
    return killChainPathIds?.has(pathId) || false;
  };

  // Timeline component
  const Timeline = () => (
    <div className="flex items-center gap-2 overflow-x-auto py-2">
      {kcData.segments.map((seg, idx) => {
        const stateZh = ATTACK_STATE_ZH_MAP[seg.state] || seg.state;
        return (
          <div key={seg.seg_idx} className="flex items-center">
            {idx > 0 && <span className="text-xs text-muted-foreground mx-1">→</span>}
            <span className="inline-flex items-center px-2 py-1 rounded-md text-xs font-medium bg-primary/10 text-primary">
              [{stateZh}]
            </span>
          </div>
        );
      })}
    </div>
  );

  return (
    <div className="rounded-md border border-border/60 p-3">
      {/* Header */}
      <div className="flex items-center justify-between gap-3">
        <div className="text-sm font-semibold text-foreground">
          KillChain 攻击链分析
        </div>
        <div className="flex items-center gap-2">
          <ExportButton taskId={task["task.id"]} taskStatus={task["task.status"]} />
          {isExpanded && (
            <Button size="sm" variant="outline" onClick={handleCollapse}>
              收起详情
            </Button>
          )}
        </div>
      </div>

      {/* Content */}
      <div className="mt-3 space-y-3">
        {/* Confidence Bar */}
        <div className="flex items-center gap-3">
          <div className="h-2 flex-1 overflow-hidden rounded-full bg-muted">
            <div
              className={`h-full rounded-full transition-all ${confidenceLevel.color}`}
              style={{ width: `${percentage}%` }}
            />
          </div>
          <span className="text-xs font-medium text-foreground">{percentage}%</span>
          <span className={`text-xs ${confidenceLevel.textColor}`}>{confidenceLevel.label}</span>
        </div>

        {/* Timeline */}
        <div>
          <div className="text-xs text-muted-foreground mb-1">MITRE ATT&CK 战术时间线</div>
          <Timeline />
        </div>

        {/* Explanation Summary or Full */}
        <div>
          <div className="text-xs text-muted-foreground mb-1">
            LLM {isExpanded ? "全链解释" : "解释摘要"}
          </div>
          <div className="text-xs text-muted-foreground whitespace-pre-wrap">
            {isExpanded ? explanationFull : explanationSummary}
            {!isExpanded && explanationFull.length > explanationSummary.length && "..."}
          </div>
        </div>

        {/* Expand Button or Full Details */}
        {!isExpanded ? (
          <Button size="sm" variant="outline" onClick={handleExpand} className="w-full">
            查看详情
          </Button>
        ) : (
          <div className="space-y-3 pt-2 border-t border-border/60">
            {/* Overview Card */}
            <div className="rounded-md bg-muted/40 px-3 py-2">
              <div className="text-xs font-medium text-foreground mb-2">概览</div>
              <div className="grid grid-cols-2 gap-2 text-xs text-muted-foreground">
                <div>kc_uuid: <code className="text-xs">{kcData.kc_uuid.slice(0, 8)}...</code></div>
                <div>分段数: {kcData.segments.length}</div>
                <div>路径数: {kcData.selected_paths.length}</div>
              </div>
            </div>

            {/* Segments Detail */}
            <div>
              <div className="text-xs font-medium text-foreground mb-2">战术分段详情</div>
              <div className="space-y-2">
                {kcData.segments.map((seg) => {
                  const stateZh = ATTACK_STATE_ZH_MAP[seg.state] || seg.state;
                  const isSegExpanded = expandedSegmentIdx === seg.seg_idx;
                  return (
                    <div key={seg.seg_idx} className="rounded-md bg-muted/40 px-3 py-2">
                      <div
                        className="flex items-center justify-between cursor-pointer"
                        onClick={() => handleToggleSegment(seg.seg_idx)}
                      >
                        <span className="text-xs font-medium text-foreground">
                          {isSegExpanded ? "▼" : "▶"} {seg.seg_idx + 1}. {stateZh} ({seg.state})
                        </span>
                        <span className="text-xs text-muted-foreground">
                          {formatTimestamp(seg.t_start)} - {formatTimestamp(seg.t_end)}
                        </span>
                      </div>
                      {isSegExpanded && (
                        <div className="mt-2 space-y-1 pl-4 text-xs text-muted-foreground">
                          <div>入口锚点: <code className="text-xs">{seg.anchor_in_uid}</code></div>
                          <div>出口锚点: <code className="text-xs">{seg.anchor_out_uid}</code></div>
                          <div>异常边数: {seg.abnormal_edge_count}</div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Paths Detail */}
            {kcData.selected_paths.length > 0 && (
              <div>
                <div className="text-xs font-medium text-foreground mb-2">
                  段间连接路径 ({kcData.selected_paths.length} 条)
                </div>
                <div className="space-y-2">
                  {kcData.selected_paths.map((path) => {
                    const isPathExpanded = expandedPathIds.has(path.path_id);
                    const isHighlighted = isPathHighlighted(path.path_id);
                    return (
                      <div
                        key={path.path_id}
                        className={`rounded-md px-3 py-2 ${isHighlighted ? "bg-primary/20 border border-primary/50" : "bg-muted/40"}`}
                      >
                        <div className="flex items-center justify-between">
                          <span
                            className="text-xs font-medium text-foreground cursor-pointer"
                            onClick={() => handleTogglePath(path.path_id)}
                          >
                            {isPathExpanded ? "▼" : "▶"} {path.path_id}
                          </span>
                          <Button
                            size="sm"
                            variant={isHighlighted ? "default" : "outline"}
                            onClick={() => handleHighlightSinglePath(path.path_id)}
                          >
                            {isHighlighted ? "已高亮" : "在图谱中高亮"}
                          </Button>
                        </div>
                        {isPathExpanded && (
                          <div className="mt-2 space-y-1 pl-4 text-xs text-muted-foreground">
                            <div>
                              {path.src_anchor} → {path.dst_anchor}
                            </div>
                            <div>hop 数量: {path.hop_count}</div>
                            <div className="font-mono text-xs">
                              edges: {path.edge_ids.slice(0, 5).join(", ")}
                              {path.edge_ids.length > 5 && ` ... 等 ${path.edge_ids.length} 条`}
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
