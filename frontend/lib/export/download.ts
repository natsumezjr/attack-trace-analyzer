export function generateReportFilename(taskId: string): string {
  const trimmed = taskId.trim();
  const safeTaskId = trimmed.length > 0 ? trimmed : "unknown-task";
  return `attack-trace-report-${safeTaskId}.md`;
}

export function downloadMarkdownFile(content: string, filename: string): void {
  const blob = new Blob([content], { type: "text/markdown;charset=utf-8" });
  const url = URL.createObjectURL(blob);

  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.rel = "noopener";
  anchor.style.display = "none";

  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();

  // Safari may cancel the download if we revoke too early.
  window.setTimeout(() => URL.revokeObjectURL(url), 30_000);
}
