import { Card, CardContent } from "@/components/card/card2";
import {
  AlertTriangle,
  Crosshair,
  ShieldAlert,
  Network,
} from "lucide-react";

const stats = [
  {
    label: "高危告警",
    value: "28",
    icon: ShieldAlert,
    color: "text-chart-1 bg-chart-1/10",
  },
  {
    label: "横向移动",
    value: "13",
    icon: Network,
    color: "text-chart-2 bg-chart-2/10",
  },
  {
    label: "可疑扫描",
    value: "46",
    icon: Crosshair,
    color: "text-chart-3 bg-chart-3/10",
  },
  {
    label: "权限异常",
    value: "9",
    icon: AlertTriangle,
    color: "text-chart-4 bg-chart-4/10",
  },
];

export function AttackStatsGrid() {
  return (
    <div className="grid h-full grid-cols-2 gap-4">
      {stats.map((stat) => (
        <Card key={stat.label} className="h-full">
          <CardContent className="flex h-full items-center justify-between p-4">
            <div>
              <div className="text-sm text-muted-foreground">{stat.label}</div>
              <div className="mt-1 text-2xl font-semibold text-foreground">
                {stat.value}
              </div>
            </div>
            <div
              className={`flex size-10 items-center justify-center rounded-lg ${stat.color}`}
            >
              <stat.icon className="size-5" />
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
