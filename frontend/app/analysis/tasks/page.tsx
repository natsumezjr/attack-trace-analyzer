"use client";

import { useQuery } from "@tanstack/react-query";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { fetchAnalysisTasks, type AnalysisTaskItem } from "@/lib/api/analysis";

export default function AnalysisTasksPage() {
  const { data: analysisTasks } = useQuery({
    queryKey: ["analysis-tasks"],
    queryFn: () => fetchAnalysisTasks(),
  });

  const items =
    analysisTasks?.status === "ok" && Array.isArray(analysisTasks.items)
      ? analysisTasks.items
      : [];

  return (
    <div className="flex h-[calc(100vh-96px)] flex-col gap-4 p-6">
      <h1 className="text-2xl font-semibold text-foreground">溯源任务</h1>
      <div className="flex-1 overflow-auto rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>任务 ID</TableHead>
              <TableHead>状态</TableHead>
              <TableHead>目标节点</TableHead>
              <TableHead>进度</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.length ? (
              items.map((task: AnalysisTaskItem) => {
                const progress = Math.min(
                  100,
                  Math.max(0, task["task.progress"] ?? 0)
                );
                return (
                  <TableRow key={task["task.id"]}>
                    <TableCell className="font-medium">
                      {task["task.id"]}
                    </TableCell>
                    <TableCell>{task["task.status"]}</TableCell>
                    <TableCell className="max-w-[320px] truncate">
                      {task["task.target.node_uid"]}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-3">
                        <div className="h-2 w-full max-w-[180px] overflow-hidden rounded-full bg-muted">
                          <div
                            className="h-full rounded-full bg-primary transition-all"
                            style={{ width: `${progress}%` }}
                          />
                        </div>
                        <span className="text-xs text-muted-foreground">
                          {progress}%
                        </span>
                      </div>
                    </TableCell>
                  </TableRow>
                );
              })
            ) : (
              <TableRow>
                <TableCell colSpan={4} className="py-6 text-center">
                  暂无溯源任务
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
