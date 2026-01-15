"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { Area, AreaChart, CartesianGrid, XAxis } from "recharts";

import { getThroughputKb } from "@/lib/api/throughput";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart";

type ThroughputPoint = {
  index: number;
  timeLabel: string;
  throughput: number;
};

const chartConfig = {
  throughput: {
    label: "吞吐 (Kb)",
    color: "var(--chart-1)",
  },
} satisfies ChartConfig;

export function ChartAreaDefault({ className }: { className?: string }) {
  const [data, setData] = useState<ThroughputPoint[]>([]);
  const indexRef = useRef(0);
  const maxPoints = 10;

  useEffect(() => {
    let cancelled = false;
    const tick = async () => {
      try {
        const { kb, lastPollTime, serverTime } = await getThroughputKb();
        if (cancelled) return;
        const nextIndex = indexRef.current + 1;
        indexRef.current = nextIndex;
        const timeSource = lastPollTime || serverTime;
        const timeLabel = timeSource
          ? new Date(timeSource).toLocaleTimeString()
          : new Date().toLocaleTimeString();
        setData((prev) => {
          const updated = [
            ...prev,
            { index: nextIndex, timeLabel, throughput: kb },
          ];
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

  const currentValue = data[data.length - 1]?.throughput ?? 0;
  const averageValue = useMemo(() => {
    if (data.length === 0) return 0;
    return data.reduce((sum, point) => sum + point.throughput, 0) / data.length;
  }, [data]);

  const cardClassName = ["flex", "h-full", "flex-col", className]
    .filter(Boolean)
    .join(" ");

  return (
    <Card className={cardClassName}>
      <CardHeader className="flex flex-row items-start justify-between gap-4">
        <div>
          <CardTitle>实时流量吞吐</CardTitle>
          <CardDescription>每 5 秒更新</CardDescription>
        </div>
        <div className="flex flex-col text-sm text-primary">
          <span>当前: {currentValue.toFixed(2)} Kb</span>
          <span>均值: {averageValue.toFixed(2)} Kb</span>
        </div>
      </CardHeader>
      <CardContent className="flex-1">
        <ChartContainer
          config={chartConfig}
          className="h-125 w-full aspect-auto"
        >
          <AreaChart
            accessibilityLayer
            data={data}
            margin={{
              left: 12,
              right: 12,
            }}
          >
            <CartesianGrid vertical={false} />
            <XAxis
              dataKey="timeLabel"
              tickLine={false}
              axisLine={false}
              tickMargin={8}
            />
            <ChartTooltip
              cursor={false}
              content={<ChartTooltipContent indicator="line" />}
            />
            <Area
              dataKey="throughput"
              type="natural"
              fill="var(--color-throughput)"
              fillOpacity={0.4}
              stroke="var(--color-throughput)"
            />
          </AreaChart>
        </ChartContainer>
      </CardContent>
    </Card>
  );
}
