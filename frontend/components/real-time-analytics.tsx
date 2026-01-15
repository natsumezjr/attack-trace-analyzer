"use client";

import type React from "react";

import { useState, useEffect, useRef } from "react";

interface DataPoint {
  time: number;
  value: number;
}

export function Component() {
  const [data, setData] = useState<DataPoint[]>([]);
  const [hoveredPoint, setHoveredPoint] = useState<DataPoint | null>(null);
  const svgRef = useRef<SVGSVGElement>(null);

  const maxPoints = 30;
  const width = 800;
  const height = 300;
  const padding = { top: 20, right: 20, bottom: 40, left: 50 };

  useEffect(() => {
    // Initialize with some data
    const initial: DataPoint[] = [];
    for (let i = 0; i < 20; i++) {
      initial.push({
        time: Date.now() - (20 - i) * 1000,
        value: 30 + Math.random() * 40,
      });
    }
    setData(initial);

    // Add new data points every second
    const interval = setInterval(() => {
      setData((prev) => {
        const newPoint: DataPoint = {
          time: Date.now(),
          value: Math.max(
            10,
            Math.min(
              90,
              prev[prev.length - 1]?.value + (Math.random() - 0.5) * 20 || 50
            )
          ),
        };
        const updated = [...prev, newPoint];
        return updated.slice(-maxPoints);
      });
    }, 1000);

    return () => clearInterval(interval);
  }, []);

  const getX = (time: number) => {
    if (data.length < 2) return padding.left;
    const minTime = data[0]?.time || 0;
    const maxTime = data[data.length - 1]?.time || 1;
    const range = maxTime - minTime || 1;
    return (
      padding.left +
      ((time - minTime) / range) * (width - padding.left - padding.right)
    );
  };

  const getY = (value: number) => {
    return (
      padding.top + (1 - value / 100) * (height - padding.top - padding.bottom)
    );
  };

  const getPath = () => {
    if (data.length < 2) return "";
    return data
      .map((point, i) => {
        const x = getX(point.time);
        const y = getY(point.value);
        return `${i === 0 ? "M" : "L"} ${x},${y}`;
      })
      .join(" ");
  };

  const getAreaPath = () => {
    if (data.length < 2) return "";
    const linePath = getPath();
    const lastX = getX(data[data.length - 1].time);
    const firstX = getX(data[0].time);
    const bottomY = height - padding.bottom;
    return `${linePath} L ${lastX},${bottomY} L ${firstX},${bottomY} Z`;
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!svgRef.current) return;
    const rect = svgRef.current.getBoundingClientRect();
    const x = ((e.clientX - rect.left) / rect.width) * width;

    // Find closest point
    let closest: DataPoint | null = null;
    let minDist = Number.POSITIVE_INFINITY;
    data.forEach((point) => {
      const px = getX(point.time);
      const dist = Math.abs(px - x);
      if (dist < minDist && dist < 30) {
        minDist = dist;
        closest = point;
      }
    });
    setHoveredPoint(closest);
  };

  const currentValue = data[data.length - 1]?.value || 0;
  const getScaledX = (time: number) => {
    if (!svgRef.current) return getX(time);
    const rect = svgRef.current.getBoundingClientRect();
    return (getX(time) / width) * rect.width;
  };
  const getScaledY = (value: number) => {
    if (!svgRef.current) return getY(value);
    const rect = svgRef.current.getBoundingClientRect();
    return (getY(value) / height) * rect.height;
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
              {currentValue.toFixed(1)}%
            </span>
          </div>
        </div>

        <div className="relative rounded-2xl border border-border bg-card p-6">
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
            {[0, 25, 50, 75, 100].map((val) => (
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
                  {val}%
                </text>
              </g>
            ))}

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
                key={point.time}
                className={i === data.length - 1 ? "data-dot" : ""}
                cx={getX(point.time)}
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
                  x1={getX(hoveredPoint.time)}
                  y1={padding.top}
                  x2={getX(hoveredPoint.time)}
                  y2={height - padding.bottom}
                  stroke="var(--chart-1)"
                  strokeDasharray="4 4"
                  opacity="0.5"
                />
                <circle
                  cx={getX(hoveredPoint.time)}
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
                left: getScaledX(hoveredPoint.time),
                top: getScaledY(hoveredPoint.value) - 60,
                transform: "translateX(-50%)",
              }}
            >
              <div className="text-sm font-semibold text-popover-foreground">
                {hoveredPoint.value.toFixed(1)}%
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
              ).toFixed(1),
              unit: "%",
            },
            {
              label: "Peak",
              value: Math.max(...data.map((d) => d.value), 0).toFixed(1),
              unit: "%",
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
