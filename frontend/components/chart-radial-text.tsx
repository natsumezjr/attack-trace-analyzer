"use client";

import {
  Label,
  PolarGrid,
  PolarRadiusAxis,
  RadialBar,
  RadialBarChart,
} from "recharts";
import { useQuery } from "@tanstack/react-query";

import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { ChartContainer, type ChartConfig } from "@/components/ui/chart";
import { getTargetsLen } from "@/lib/api/targets";

export const description = "A radial chart with text";

const chartConfig = {
  online: {
    label: "在线靶机",
    color: "var(--chart-5)",
  },
} satisfies ChartConfig;

export function ChartRadialText({ className }: { className?: string }) {
  const { data: targetsLen } = useQuery({
    queryKey: ["targets", "len"],
    queryFn: getTargetsLen,
  });
  const onlineTargetsValue = targetsLen ?? 0;
  const onlineTargetsLabel =
    targetsLen === undefined ? "--" : targetsLen.toLocaleString();
  const chartData = [
    {
      name: "online",
      visitors: onlineTargetsValue,
      fill: "var(--color-online)",
    },
  ];

  const cardClassName = ["flex flex-col h-full", className]
    .filter(Boolean)
    .join(" ");

  return (
    <Card className={cardClassName}>
      <CardHeader className="items-center pb-0">
        <CardTitle>在线靶机</CardTitle>
        <CardDescription>当前在线数量</CardDescription>
      </CardHeader>
      <CardContent className="flex-1 pb-0">
        <ChartContainer
          config={chartConfig}
          className="mx-auto aspect-square max-h-[250px]"
        >
          <RadialBarChart
            data={chartData}
            startAngle={0}
            endAngle={250}
            innerRadius={80}
            outerRadius={110}
          >
            <PolarGrid
              gridType="circle"
              radialLines={false}
              stroke="none"
              className="first:fill-muted last:fill-background"
              polarRadius={[86, 74]}
            />
            <RadialBar dataKey="visitors" background cornerRadius={10} />
            <PolarRadiusAxis tick={false} tickLine={false} axisLine={false}>
              <Label
                content={({ viewBox }) => {
                  if (viewBox && "cx" in viewBox && "cy" in viewBox) {
                    return (
                      <text
                        x={viewBox.cx}
                        y={viewBox.cy}
                        textAnchor="middle"
                        dominantBaseline="middle"
                      >
                        <tspan
                          x={viewBox.cx}
                          y={viewBox.cy}
                          className="fill-foreground text-4xl font-bold"
                        >
                          {onlineTargetsLabel}
                        </tspan>
                        <tspan
                          x={viewBox.cx}
                          y={(viewBox.cy || 0) + 24}
                          className="fill-muted-foreground"
                        >
                          在线靶机
                        </tspan>
                      </text>
                    );
                  }
                }}
              />
            </PolarRadiusAxis>
          </RadialBarChart>
        </ChartContainer>
      </CardContent>
      <CardFooter className="flex-col gap-2 text-sm">
        <div className="leading-none font-medium">当前在线靶机数量</div>
        <div className="text-muted-foreground leading-none">
          实时展示在线状态
        </div>
      </CardFooter>
    </Card>
  );
}
