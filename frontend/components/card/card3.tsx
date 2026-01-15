// demo.tsx
"use client";

import React, { useState } from "react";
import { DonutChart } from "@/components/donut-chart"; // Adjust path as needed
import { motion, AnimatePresence } from "framer-motion";
import { cn } from "@/lib/utils"; // <-- FIX: Added the missing import
import { useQuery } from "@tanstack/react-query";
import { fetchAttackOverview } from "@/lib/api/findings";

export default function DonutChartDemo() {
  const [hoveredSegment, setHoveredSegment] = useState<string | null>(null);
  const { data, isError } = useQuery({
    queryKey: ["dashboard", "attack-overview"],
    queryFn: fetchAttackOverview,
  });

  const segments = data?.segments ?? [];
  const total = data?.total ?? 0;

  // Find the currently hovered segment data
  const activeSegment = segments.find(
    (segment) => segment.label === hoveredSegment
  );

  // Determine total value (either hovered or overall)
  const displayValue = activeSegment?.value ?? (data ? total : "--");
  const displayLabel = activeSegment?.label ?? "攻击总数";
  const displayPercentage =
    activeSegment && total > 0 ? (activeSegment.value / total) * 100 : null;

  return (
    <div className="flex w-full flex-col items-center justify-center space-y-6 p-6 md:p-8">
      <h2 className="text-xl font-semibold text-center tracking-tight text-foreground">
        攻击总数
      </h2>
      <div className="relative flex items-center justify-center">
        <DonutChart
          data={segments}
          totalValue={total}
          size={250}
          strokeWidth={30}
          animationDuration={1.2}
          animationDelayPerSegment={0.05}
          highlightOnHover={true}
          centerContent={
            <AnimatePresence mode="wait">
              <motion.div
                key={displayLabel} // Key changes to trigger animation
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.9 }}
                transition={{ duration: 0.2, ease: "circOut" }}
                className="flex flex-col items-center justify-center text-center"
              >
                <p className="text-muted-foreground text-sm font-medium truncate max-w-[150px]">
                  {displayLabel}
                </p>
                <p className="text-4xl font-bold text-foreground">
                  {displayValue}
                </p>
                {/* Only show percentage if a segment is hovered */}
                {activeSegment && displayPercentage !== null && (
                  <p className="text-lg font-medium text-muted-foreground">
                    [{displayPercentage.toFixed(0)}%]
                  </p>
                )}
              </motion.div>
            </AnimatePresence>
          }
        />
      </div>

      <div className="flex w-full flex-col space-y-2 border-t border-border pt-4">
        {isError ? (
          <div className="text-sm text-muted-foreground">
            无法获取攻击统计（后端未启动或无数据源）。
          </div>
        ) : (
          segments.map((segment, index) => (
            <motion.div
              key={segment.label}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 1.2 + index * 0.1, duration: 0.4 }}
              className={cn(
                "flex items-center justify-between rounded-md p-2 transition-all duration-200 cursor-pointer",
                hoveredSegment === segment.label && "bg-muted"
              )}
              onMouseEnter={() => setHoveredSegment(segment.label)}
              onMouseLeave={() => setHoveredSegment(null)}
            >
              <div className="flex items-center space-x-3">
                <span
                  className="h-3 w-3 rounded-full"
                  style={{ backgroundColor: segment.color }}
                ></span>
                <span className="text-sm font-medium text-foreground">
                  {segment.label}
                </span>
              </div>
              <span className="text-sm font-semibold text-muted-foreground">
                {segment.value}
              </span>
            </motion.div>
          ))
        )}
      </div>
    </div>
  );
}
