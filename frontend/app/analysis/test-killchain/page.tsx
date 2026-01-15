"use client";

import { useState } from "react";
import { testKillchainAnalysis, type TestKillchainResponse } from "@/lib/api/analysis";

/**
 * KillChain 分析测试页面
 * 
 * 注意：这是一个临时测试页面，用于在数据库为空的情况下测试 killchain 分析功能
 * 测试完成后可以删除此页面
 */
export default function TestKillchainPage() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<TestKillchainResponse | null>(null);

  const handleTest = async () => {
    setLoading(true);
    setResult(null);
    
    console.log("[TEST] Starting killchain analysis test...");
    
    try {
      console.log("[TEST] Calling testKillchainAnalysis API...");
      const response = await testKillchainAnalysis();
      console.log("[TEST] API response received:", response);
      setResult(response);
    } catch (error) {
      console.error("[TEST] API call failed:", error);
      setResult({
        status: "error",
        error: {
          code: "UNKNOWN_ERROR",
          message: error instanceof Error ? error.message : String(error),
        },
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex h-[calc(100vh-96px)] flex-col gap-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-foreground">
            KillChain 分析测试
          </h1>
          <p className="mt-2 text-sm text-muted-foreground">
            此页面用于测试 killchain 分析功能。点击按钮将自动加载测试数据并运行分析。
          </p>
          <p className="mt-1 text-xs text-muted-foreground">
            ⚠️ 注意：这是临时测试页面，测试完成后可以删除
          </p>
        </div>
        <button
          onClick={handleTest}
          disabled={loading}
          className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {loading ? "分析中..." : "开始测试 KillChain 分析"}
        </button>
      </div>

      {result && (
        <div className="flex-1 overflow-auto rounded-md border bg-card p-6">
          {result.status === "ok" ? (
            <div className="space-y-4">
              <div className="rounded-md bg-green-50 dark:bg-green-900/20 p-4">
                <h2 className="text-lg font-semibold text-green-900 dark:text-green-100">
                  ✓ 分析成功
                </h2>
                {result.message && (
                  <p className="mt-1 text-sm text-green-800 dark:text-green-200">
                    {result.message}
                  </p>
                )}
              </div>

              {result.result && (
                <div className="space-y-4">
                  <div className="rounded-md border p-4">
                    <h3 className="font-semibold mb-2">分析摘要</h3>
                    <div className="space-y-1 text-sm">
                      <p>
                        <span className="font-medium">KillChain UUID:</span>{" "}
                        <code className="rounded bg-muted px-1 py-0.5">
                          {result.result.kc_uuid}
                        </code>
                      </p>
                      <p>
                        <span className="font-medium">生成的 KillChain 数量:</span>{" "}
                        {result.result.killchain_count}
                      </p>
                    </div>
                  </div>

                  {result.result.killchains.length > 0 && (
                    <div className="space-y-3">
                      <h3 className="font-semibold">KillChain 详情</h3>
                      {result.result.killchains.map((kc, index) => (
                        <div
                          key={kc.kc_uuid}
                          className="rounded-md border p-4 space-y-2"
                        >
                          <div className="flex items-center justify-between">
                            <h4 className="font-medium">
                              KillChain #{index + 1}
                            </h4>
                            <span className="text-xs text-muted-foreground">
                              可信度: {(kc.confidence * 100).toFixed(1)}%
                            </span>
                          </div>
                          <div className="text-sm space-y-1">
                            <p>
                              <span className="font-medium">UUID:</span>{" "}
                              <code className="rounded bg-muted px-1 py-0.5 text-xs">
                                {kc.kc_uuid}
                              </code>
                            </p>
                            <p>
                              <span className="font-medium">状态段数量:</span>{" "}
                              {kc.segment_count}
                            </p>
                            <p>
                              <span className="font-medium">选中路径数量:</span>{" "}
                              {kc.selected_path_count}
                            </p>
                            {kc.explanation && (
                              <div className="mt-2">
                                <span className="font-medium">解释:</span>
                                <p className="mt-1 text-muted-foreground">
                                  {kc.explanation}
                                </p>
                              </div>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          ) : (
            <div className="rounded-md bg-red-50 dark:bg-red-900/20 p-4">
              <h2 className="text-lg font-semibold text-red-900 dark:text-red-100">
                ✗ 分析失败
              </h2>
              {result.error && (
                <div className="mt-2 space-y-1">
                  <p className="text-sm font-medium text-red-800 dark:text-red-200">
                    错误代码: {result.error.code}
                  </p>
                  <p className="text-sm text-red-800 dark:text-red-200 whitespace-pre-wrap">
                    {result.error.message}
                  </p>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
