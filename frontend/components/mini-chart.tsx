"use client";

import { useState, useRef, useEffect } from "react";
import { cn } from "@/lib/utils";

const data = [
  { label: "恶意登录", value: 65 },
  { label: "权限提升", value: 85 },
  { label: "横向移动", value: 45 },
  { label: "数据外传", value: 95 },
  { label: "可疑进程", value: 70 },
  { label: "异常访问", value: 55 },
  { label: "其他事件", value: 80 },
];

export function MiniChart() {
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);
  const [displayValue, setDisplayValue] = useState<number | null>(null);
  const [isHovering, setIsHovering] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);
  const maxValue = Math.max(...data.map((d) => d.value));
  const chartHeight = 280;

  useEffect(() => {
    if (hoveredIndex !== null) {
      setDisplayValue(data[hoveredIndex].value);
    }
  }, [hoveredIndex]);

  const handleContainerEnter = () => setIsHovering(true);
  const handleContainerLeave = () => {
    setIsHovering(false);
    setHoveredIndex(null);
    setTimeout(() => {
      setDisplayValue(null);
    }, 150);
  };

  return (
    <div
      ref={containerRef}
      onMouseEnter={handleContainerEnter}
      onMouseLeave={handleContainerLeave}
      className="group relative h-full w-full min-h-[300px] rounded-lg p-6 text-card-foreground transition-colors duration-300 hover:bg-muted/30 flex flex-col gap-4"
    >
      <h3 className="text-sm font-semibold text-foreground">事件类型</h3>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-2">
          <div className="h-2 w-2 rounded-full bg-chart-2 animate-pulse" />
          <span className="text-xs font-medium text-muted-foreground tracking-wide uppercase">
            Activity
          </span>
        </div>
        <div className="relative h-7 flex items-center">
          <span
            className={cn(
              "text-lg font-semibold tabular-nums transition-all duration-300 ease-out",
              isHovering && displayValue !== null
                ? "opacity-100 text-foreground"
                : "opacity-50 text-muted-foreground"
            )}
          >
            {displayValue !== null ? displayValue : ""}
            <span
              className={cn(
                "text-xs font-normal text-muted-foreground ml-0.5 transition-opacity duration-300",
                displayValue !== null ? "opacity-100" : "opacity-0"
              )}
            >
              %
            </span>
          </span>
        </div>
      </div>

      {/* Chart */}
      <div
        className="flex items-end gap-2 px-3"
        style={{ height: chartHeight }}
      >
        {data.map((item, index) => {
          const heightPx = (item.value / maxValue) * chartHeight;
          const isHovered = hoveredIndex === index;
          const isAnyHovered = hoveredIndex !== null;
          const isNeighbor =
            hoveredIndex !== null &&
            (index === hoveredIndex - 1 || index === hoveredIndex + 1);

          return (
            <div
              key={item.label}
              className="relative flex-1 flex flex-col items-center justify-end h-full"
              onMouseEnter={() => setHoveredIndex(index)}
            >
              {/* Bar */}
              <div
                className={cn(
                  "w-25 rounded-xl cursor-pointer transition-all duration-300 ease-out origin-bottom",
                  isHovered
                    ? "bg-chart-2"
                    : isNeighbor
                    ? "bg-chart-2/60"
                    : isAnyHovered
                    ? "bg-chart-2/30"
                    : "bg-chart-2/40 group-hover:bg-chart-2/50"
                )}
                style={{
                  height: `${heightPx}px`,
                  transform: isHovered
                    ? "scaleX(1.15) scaleY(1.02)"
                    : isNeighbor
                    ? "scaleX(1.05)"
                    : "scaleX(1)",
                }}
              />

              {/* Label */}
              <span
                className={cn(
                  "text-[10px] font-medium mt-2 transition-all duration-300",
                  isHovered ? "text-foreground" : "text-muted-foreground/60"
                )}
              >
                {item.label}
              </span>

              {/* Tooltip */}
              <div
                className={cn(
                  "absolute -top-8 left-1/2 -translate-x-1/2 rounded-md border border-border bg-popover px-2 py-1 text-xs font-medium text-popover-foreground transition-all duration-200 whitespace-nowrap",
                  isHovered
                    ? "opacity-100 translate-y-0"
                    : "opacity-0 translate-y-1 pointer-events-none"
                )}
              >
                {item.value}%
              </div>
            </div>
          );
        })}
      </div>

      {/* Subtle glow effect on hover */}
      <div className="pointer-events-none absolute inset-0 rounded-lg bg-gradient-to-b from-chart-2/10 to-transparent opacity-0 transition-opacity duration-500 group-hover:opacity-100" />
    </div>
  );
}
