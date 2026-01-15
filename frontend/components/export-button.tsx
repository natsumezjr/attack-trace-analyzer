"use client";

import { useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/button/button";
import { downloadMarkdownFile, generateReportFilename } from "@/lib/export/download";
import { generateMarkdownReport, generateReportData } from "@/lib/export/report-generator";

export function ExportButton(props: {
  taskId: string | null;
  taskStatus?: string | null;
  disabled?: boolean;
}) {
  const [isExporting, setIsExporting] = useState(false);

  const canExport =
    !props.disabled &&
    typeof props.taskId === "string" &&
    props.taskId.trim().length > 0 &&
    (props.taskStatus ? props.taskStatus === "succeeded" : true);

  return (
    <Button
      type="button"
      size="sm"
      variant="outline"
      disabled={!canExport || isExporting}
      onClick={async () => {
        if (!canExport) return;

        const taskId = props.taskId?.trim() ?? "";
        if (!taskId) return;

        setIsExporting(true);
        const toastId = toast.loading("正在生成报告…");

        try {
          const data = await generateReportData(taskId);
          const markdown = generateMarkdownReport(data);
          downloadMarkdownFile(markdown, generateReportFilename(taskId));
          toast.success("报告已导出", { id: toastId });
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          toast.error(message || "导出失败", { id: toastId });
        } finally {
          setIsExporting(false);
        }
      }}
    >
      {isExporting ? "导出中…" : "导出报告"}
    </Button>
  );
}
