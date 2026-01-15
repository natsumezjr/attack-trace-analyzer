"use client";

import { useQuery } from "@tanstack/react-query";
import { useParams, useRouter } from "next/navigation";
import { fetchAnalysisTask, type AnalysisTaskItem } from "@/lib/api/analysis";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ArrowLeft, Loader2 } from "lucide-react";
import Link from "next/link";

export default function TaskDetailPage() {
  const params = useParams();
  const router = useRouter();
  const taskId = params.taskId as string;

  const { data: taskResponse, isLoading, error } = useQuery({
    queryKey: ["analysis-task", taskId],
    queryFn: () => fetchAnalysisTask(taskId),
    enabled: !!taskId,
  });

  const task = taskResponse?.status === "ok" ? taskResponse.task : null;

  if (isLoading) {
    return (
      <div className="flex h-[calc(100vh-96px)] items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (error || !task) {
    return (
      <div className="flex h-[calc(100vh-96px)] flex-col gap-4 p-6">
        <div className="flex items-center gap-4">
          <Link href="/analysis/tasks">
            <Button variant="ghost" size="sm">
              <ArrowLeft className="mr-2 h-4 w-4" />
              返回任务列表
            </Button>
          </Link>
        </div>
        <Card>
          <CardContent className="py-6">
            <p className="text-muted-foreground">
              {taskResponse?.status === "error"
                ? taskResponse.error.message
                : "任务未找到"}
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  const progress = Math.min(100, Math.max(0, task["task.progress"] ?? 0));
  const status = task["task.status"];
  const killchain = task["task.result.killchain"];

  const getStatusColor = (status: string) => {
    switch (status) {
      case "succeeded":
        return "bg-green-500/10 text-green-500";
      case "failed":
        return "bg-red-500/10 text-red-500";
      case "running":
        return "bg-blue-500/10 text-blue-500";
      case "pending":
        return "bg-yellow-500/10 text-yellow-500";
      default:
        return "bg-muted text-muted-foreground";
    }
  };

  return (
    <div className="flex h-[calc(100vh-96px)] flex-col gap-4 p-6 overflow-auto">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Link href="/analysis/tasks">
            <Button variant="ghost" size="sm">
              <ArrowLeft className="mr-2 h-4 w-4" />
              返回任务列表
            </Button>
          </Link>
          <h1 className="text-2xl font-semibold">任务详情</h1>
        </div>
        <Badge className={getStatusColor(status)}>
          {status}
        </Badge>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* 任务基本信息 */}
        <Card>
          <CardHeader>
            <CardTitle>基本信息</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex justify-between">
              <span className="text-sm text-muted-foreground">任务 ID</span>
              <span className="text-sm font-mono">{task["task.id"]}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-sm text-muted-foreground">目标节点</span>
              <span className="text-sm font-mono">{task["task.target.node_uid"]}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-sm text-muted-foreground">开始时间</span>
              <span className="text-sm">{task["task.window.start_ts"]}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-sm text-muted-foreground">结束时间</span>
              <span className="text-sm">{task["task.window.end_ts"]}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-sm text-muted-foreground">创建时间</span>
              <span className="text-sm">{task["@timestamp"]}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-sm text-muted-foreground">启动时间</span>
              <span className="text-sm">
                {task["task.started_at"] || "-"}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-sm text-muted-foreground">完成时间</span>
              <span className="text-sm">
                {task["task.finished_at"] || "-"}
              </span>
            </div>
            {task["task.error"] && (
              <div className="flex flex-col gap-1">
                <span className="text-sm text-muted-foreground">错误信息</span>
                <span className="text-sm text-red-500">{task["task.error"]}</span>
              </div>
            )}
            <div>
              <div className="flex justify-between mb-2">
                <span className="text-sm text-muted-foreground">进度</span>
                <span className="text-sm font-medium">{progress}%</span>
              </div>
              <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
                <div
                  className="h-full rounded-full bg-primary transition-all"
                  style={{ width: `${progress}%` }}
                />
              </div>
            </div>
          </CardContent>
        </Card>

        {/* TTP 分析结果 */}
        <Card>
          <CardHeader>
            <CardTitle>TTP 相似度分析</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {task["task.result.ttp_similarity.attack_tactics"]?.length ? (
              <div>
                <span className="text-sm text-muted-foreground">攻击战术</span>
                <div className="flex flex-wrap gap-2 mt-2">
                  {task["task.result.ttp_similarity.attack_tactics"].map((tactic) => (
                    <Badge key={tactic} variant="outline">{tactic}</Badge>
                  ))}
                </div>
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">暂无战术数据</p>
            )}
            {task["task.result.ttp_similarity.attack_techniques"]?.length ? (
              <div>
                <span className="text-sm text-muted-foreground">攻击技术</span>
                <div className="flex flex-wrap gap-2 mt-2">
                  {task["task.result.ttp_similarity.attack_techniques"].map((technique) => (
                    <Badge key={technique} variant="secondary">{technique}</Badge>
                  ))}
                </div>
              </div>
            ) : null}
            {task["task.result.ttp_similarity.similar_apts"]?.length ? (
              <div>
                <span className="text-sm text-muted-foreground">相似 APT 组织</span>
                <div className="space-y-2 mt-2">
                  {task["task.result.ttp_similarity.similar_apts"].map((apt, idx) => (
                    <div key={idx} className="text-sm border rounded p-2">
                      <div className="font-medium">{apt.intrusion_set?.name || "未知组织"}</div>
                      <div className="flex gap-2 mt-1">
                        <span className="text-muted-foreground">
                          相似度: {(apt.similarity_score ?? 0).toFixed(2)}
                        </span>
                        <span className="text-muted-foreground">
                          置信度: {(apt.confidence ?? 0).toFixed(2)}
                        </span>
                      </div>
                      {apt.explanation && (
                        <p className="text-xs text-muted-foreground mt-1">{apt.explanation}</p>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            ) : null}
          </CardContent>
        </Card>

        {/* KillChain 分析结果 */}
        {killchain && (
          <Card className="lg:col-span-2">
            <CardHeader>
              <CardTitle>KillChain 分析结果</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <span className="text-sm text-muted-foreground">KillChain UUID</span>
                  <p className="text-sm font-mono mt-1">{killchain.kc_uuid}</p>
                </div>
                <div>
                  <span className="text-sm text-muted-foreground">置信度</span>
                  <p className="text-sm font-medium mt-1">{killchain.confidence.toFixed(2)}</p>
                </div>
                <div>
                  <span className="text-sm text-muted-foreground">分段数量</span>
                  <p className="text-sm font-medium mt-1">{killchain.segments.length}</p>
                </div>
              </div>

              {killchain.explanation && (
                <div>
                  <span className="text-sm text-muted-foreground">攻击链解释</span>
                  <p className="text-sm mt-1 p-3 bg-muted rounded">{killchain.explanation}</p>
                </div>
              )}

              <div>
                <span className="text-sm text-muted-foreground">攻击路径分段</span>
                <div className="mt-2 space-y-2 max-h-[300px] overflow-auto">
                  {killchain.segments.map((segment) => (
                    <div key={segment.seg_idx} className="text-sm border rounded p-3">
                      <div className="flex justify-between items-start">
                        <div className="flex gap-4">
                          <span className="font-medium">分段 #{segment.seg_idx}</span>
                          <Badge variant="outline">{segment.state}</Badge>
                        </div>
                        <div className="text-xs text-muted-foreground">
                          {new Date(segment.t_start).toLocaleTimeString()} - {new Date(segment.t_end).toLocaleTimeString()}
                        </div>
                      </div>
                      <div className="grid grid-cols-2 gap-2 mt-2 text-xs text-muted-foreground">
                        <div>起始锚点: <span className="font-mono">{segment.anchor_in_uid}</span></div>
                        <div>结束锚点: <span className="font-mono">{segment.anchor_out_uid}</span></div>
                        <div>异常边数量: {segment.abnormal_edge_count}</div>
                        <div>选中路径数: {killchain.selected_paths.filter(p => p.path_id.startsWith(`${segment.seg_idx}-`)).length}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {killchain.selected_paths.length > 0 && (
                <div>
                  <span className="text-sm text-muted-foreground">选中的攻击路径</span>
                  <div className="mt-2 space-y-2 max-h-[200px] overflow-auto">
                    {killchain.selected_paths.map((path) => (
                      <div key={path.path_id} className="text-sm border rounded p-2">
                        <div className="flex justify-between items-start">
                          <span className="font-mono text-xs">{path.path_id}</span>
                          <Badge variant="secondary" className="text-xs">跳数: {path.hop_count}</Badge>
                        </div>
                        <div className="text-xs text-muted-foreground mt-1">
                          <div>源锚点: <span className="font-mono">{path.src_anchor}</span></div>
                          <div>目标锚点: <span className="font-mono">{path.dst_anchor}</span></div>
                          <div>边数量: {path.edge_ids.length}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {/* 图谱统计 */}
        {task["task.result.trace.updated_edges"] !== undefined && (
          <Card>
            <CardHeader>
              <CardTitle>图谱统计</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <div className="flex justify-between">
                <span className="text-sm text-muted-foreground">更新边数</span>
                <span className="text-sm font-medium">{task["task.result.trace.updated_edges"]}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-muted-foreground">路径边数</span>
                <span className="text-sm font-medium">{task["task.result.trace.path_edges"] || 0}</span>
              </div>
            </CardContent>
          </Card>
        )}

        {/* 摘要 */}
        {task["task.result.summary"] && (
          <Card>
            <CardHeader>
              <CardTitle>分析摘要</CardTitle>
            </CardHeader>
          <CardContent>
            <p className="text-sm whitespace-pre-wrap">{task["task.result.summary"]}</p>
          </CardContent>
        </Card>
        )}
      </div>
    </div>
  );
}
