"use client";

import type React from "react";

import { useState, useEffect, useMemo, useRef } from "react";
import { getThroughputKb } from "@/lib/api/throughput";

interface DataPoint {
  index: number;
  time: number;
  value: number;
}

export function Component() {
  const [data, setData] = useState<DataPoint[]>([]);
  const [hoveredPoint, setHoveredPoint] = useState<DataPoint | null>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const plotRef = useRef<HTMLDivElement>(null);
  const indexRef = useRef(0);

  const maxPoints = 30;
  const width = 800;
  const height = 300;
  const padding = { top: 20, right: 20, bottom: 40, left: 50 };

  useEffect(() => {
    let cancelled = false;
    const tick = async () => {
      try {
        const { kb, serverTime } = await getThroughputKb();
        if (cancelled) return;
        const parsedTime = Date.parse(serverTime);
        setData((prev) => {
          const nextIndex = indexRef.current + 1;
          indexRef.current = nextIndex;
          const time = Number.isFinite(parsedTime) && parsedTime > 0
            ? parsedTime
            : Date.now();
          const updated = [...prev, { index: nextIndex, time, value: kb }];
          return updated.slice(-maxPoints);
        });
      } catch {
        // Ignore transient errors for now.
      }
    };

    tick();
    const interval = setInterval(tick, 5000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  const valueDomain = useMemo(() => {
    if (data.length === 0) return { min: 0, max: 1 };
    const values = data.map((point) => point.value);
    const rawMin = Math.min(...values);
    const rawMax = Math.max(...values);
    const span = rawMax - rawMin || 1;
    const paddingValue = span * 0.1;
    const min = Math.max(0, rawMin - paddingValue);
    const max = rawMax + paddingValue;
    return { min, max };
  }, [data]);

  const getX = (index: number) => {
    if (data.length < 2) return padding.left;
    const minIndex = data[0]?.index ?? 0;
    const maxIndex = data[data.length - 1]?.index ?? 1;
    const range = maxIndex - minIndex || 1;
    return (
      padding.left +
      ((index - minIndex) / range) * (width - padding.left - padding.right)
    );
  };

  const getY = (value: number) => {
    const range = valueDomain.max - valueDomain.min || 1;
    const normalized = (value - valueDomain.min) / range;
    return (
      padding.top +
      (1 - normalized) * (height - padding.top - padding.bottom)
    );
  };

  const getPath = () => {
    if (data.length < 2) return "";
    return data
      .map((point, i) => {
        const x = getX(point.index);
        const y = getY(point.value);
        return `${i === 0 ? "M" : "L"} ${x},${y}`;
      })
      .join(" ");
  };

  const getAreaPath = () => {
    if (data.length < 2) return "";
    const linePath = getPath();
    const lastX = getX(data[data.length - 1].index);
    const firstX = getX(data[0].index);
    const bottomY = height - padding.bottom;
    return `${linePath} L ${lastX},${bottomY} L ${firstX},${bottomY} Z`;
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    const svgPoint = getSvgPointFromClient(e.clientX, e.clientY);
    if (!svgPoint) return;
    const x = svgPoint.x;

    // Find closest point
    let closest: DataPoint | null = null;
    let minDist = Number.POSITIVE_INFINITY;
    data.forEach((point) => {
      const px = getX(point.index);
      const dist = Math.abs(px - x);
      if (dist < minDist && dist < 30) {
        minDist = dist;
        closest = point;
      }
    });
    setHoveredPoint(closest);
  };

  const currentValue = data[data.length - 1]?.value || 0;
  const getSvgPointFromClient = (clientX: number, clientY: number) => {
    const svg = svgRef.current;
    if (!svg) return null;
    const ctm = svg.getScreenCTM();
    if (!ctm) return null;
    const point = svg.createSVGPoint();
    point.x = clientX;
    point.y = clientY;
    return point.matrixTransform(ctm.inverse());
  };

  const getClientPointFromSvg = (x: number, y: number) => {
    const svg = svgRef.current;
    if (!svg) return null;
    const ctm = svg.getScreenCTM();
    if (!ctm) return null;
    const point = svg.createSVGPoint();
    point.x = x;
    point.y = y;
    return point.matrixTransform(ctm);
  };

  const getTooltipPosition = (point: DataPoint) => {
    const plotRect = plotRef.current?.getBoundingClientRect();
    const clientPoint = getClientPointFromSvg(
      getX(point.index),
      getY(point.value)
    );
    if (!plotRect || !clientPoint) {
      return { left: getX(point.index), top: getY(point.value) };
    }
    return {
      left: clientPoint.x - plotRect.left,
      top: clientPoint.y - plotRect.top,
    };
  };

  return (
    <div className="bg-background text-foreground px-4 pb-0 pt-4 font-sans">
      <style jsx>{`
        @keyframes pulse {
          0%,
          100% {
            opacity: 1;
            r: 6;
          }
          50% {
            opacity: 0.7;
            r: 8;
          }
        }
        @keyframes drawLine {
          from {
            stroke-dashoffset: 1000;
          }
          to {
            stroke-dashoffset: 0;
          }
        }
        .flowing-line {
          stroke-dasharray: 1000;
          animation: drawLine 2s ease-out forwards;
        }
        .data-dot {
          animation: pulse 2s ease-in-out infinite;
        }
        .glow {
          filter: drop-shadow(
            0 0 8px color-mix(in oklch, var(--chart-1) 60%, transparent)
          );
        }
      `}</style>

      <div className="mx-auto max-w-[1000px]">
        <div className="mb-6 flex items-center justify-between">
          <div>
            <h2 className="text-2xl font-bold text-foreground">实时流量吞吐</h2>
            <p className="text-sm text-muted-foreground">
              Live server performance metrics
            </p>
          </div>

          <div className="flex items-center gap-3 rounded-xl bg-card px-5 py-3">
            <div
              className="size-2.5 rounded-full bg-chart-2"
              style={{ animation: "pulse 1.5s ease-in-out infinite" }}
            />
            <span className="text-sm text-muted-foreground">Live</span>
            <span className="ml-2 text-2xl font-bold text-foreground">
              {currentValue.toFixed(2)} Kb
            </span>
          </div>
        </div>

        <div
          ref={plotRef}
          className="relative rounded-2xl border border-border bg-card p-6"
        >
          <svg
            ref={svgRef}
            width="100%"
            height={height}
            viewBox={`0 0 ${width} ${height}`}
            onMouseMove={handleMouseMove}
            onMouseLeave={() => setHoveredPoint(null)}
            style={{ cursor: "crosshair" }}
          >
            <defs>
              <linearGradient
                id="lineGradient"
                x1="0%"
                y1="0%"
                x2="100%"
                y2="0%"
              >
                <stop offset="0%" stopColor="var(--chart-1)" />
                <stop offset="50%" stopColor="var(--chart-2)" />
                <stop offset="100%" stopColor="var(--chart-3)" />
              </linearGradient>
              <linearGradient
                id="areaGradient"
                x1="0%"
                y1="0%"
                x2="0%"
                y2="100%"
              >
                <stop
                  offset="0%"
                  stopColor="var(--chart-2)"
                  stopOpacity="0.25"
                />
                <stop
                  offset="100%"
                  stopColor="var(--chart-2)"
                  stopOpacity="0"
                />
              </linearGradient>
            </defs>

            {/* Grid lines */}
            {Array.from({ length: 5 }).map((_, i) => {
              const step =
                (valueDomain.max - valueDomain.min) / 4 || 1;
              const val = valueDomain.min + step * i;
              return (
              <g key={val}>
                <line
                  x1={padding.left}
                  y1={getY(val)}
                  x2={width - padding.right}
                  y2={getY(val)}
                  stroke="var(--border)"
                  strokeDasharray="4 4"
                />
                <text
                  x={padding.left - 10}
                  y={getY(val)}
                  fill="var(--muted-foreground)"
                  fontSize="12"
                  textAnchor="end"
                  dominantBaseline="middle"
                >
                  {val.toFixed(1)}
                </text>
              </g>
              );
            })}

            {/* Area fill */}
            <path d={getAreaPath()} fill="url(#areaGradient)" />

            {/* Main line */}
            <path
              className="flowing-line glow"
              d={getPath()}
              fill="none"
              stroke="url(#lineGradient)"
              strokeWidth="3"
              strokeLinecap="round"
              strokeLinejoin="round"
            />

            {/* Data points */}
            {data.map((point, i) => (
              <circle
                key={point.index}
                className={i === data.length - 1 ? "data-dot" : ""}
                cx={getX(point.index)}
                cy={getY(point.value)}
                r={i === data.length - 1 ? 6 : 3}
                fill={
                  i === data.length - 1 ? "var(--chart-4)" : "var(--chart-1)"
                }
                style={{
                  opacity: hoveredPoint?.time === point.time ? 1 : 0.7,
                  transition: "opacity 0.2s ease",
                }}
              />
            ))}

            {/* Hover crosshair */}
            {hoveredPoint && (
              <>
                <line
                  x1={getX(hoveredPoint.index)}
                  y1={padding.top}
                  x2={getX(hoveredPoint.index)}
                  y2={height - padding.bottom}
                  stroke="var(--chart-1)"
                  strokeDasharray="4 4"
                  opacity="0.5"
                />
                <circle
                  cx={getX(hoveredPoint.index)}
                  cy={getY(hoveredPoint.value)}
                  r="8"
                  fill="none"
                  stroke="var(--chart-4)"
                  strokeWidth="2"
                />
              </>
            )}
          </svg>

          {/* Tooltip */}
          {hoveredPoint && (
            <div
              className="pointer-events-none z-10 rounded-lg border border-border bg-popover px-3 py-2 text-popover-foreground"
              style={{
                position: "absolute",
                left: getTooltipPosition(hoveredPoint).left,
                top: getTooltipPosition(hoveredPoint).top - 60,
                transform: "translateX(-50%)",
              }}
            >
              <div className="text-sm font-semibold text-popover-foreground">
                {hoveredPoint.value.toFixed(2)} Kb
              </div>
              <div className="text-xs text-muted-foreground">
                {new Date(hoveredPoint.time).toLocaleTimeString()}
              </div>
            </div>
          )}
        </div>

        <div className="mt-10 grid grid-cols-3 gap-4">
          {[
            {
              label: "Average",
              value: (
                data.reduce((a, b) => a + b.value, 0) / data.length || 0
              ).toFixed(2),
              unit: " Kb",
            },
            {
              label: "Peak",
              value: Math.max(...data.map((d) => d.value), 0).toFixed(2),
              unit: " Kb",
            },
            { label: "Data Points", value: data.length.toString(), unit: "" },
          ].map((stat) => (
            <div
              key={stat.label}
              className="min-h-[96px] rounded-xl border border-border bg-card px-4 py-3 text-center"
            >
              <div className="mb-1 text-[20px] text-muted-foreground">
                {stat.label}
              </div>
              <div className="text-xl font-semibold text-foreground">
                {stat.value}
                {stat.unit}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
