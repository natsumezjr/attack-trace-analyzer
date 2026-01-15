import { ChartAreaDefault } from "@/components/chart-area-default";
import { MiniChart } from "@/components/mini-chart";
import { Card, CardContent } from "@/components/card/card2";
import DonutChartDemo from "@/components/card/card3";
import { AttackStatsGrid } from "@/components/card/attack-stats-grid";

export default function DashboardPage() {
  return (
    <div className="w-full p-6 pr-20 pt-8">
      <h1 className="mb-6 text-2xl font-semibold text-foreground">总览</h1>
      <div className="grid w-full grid-cols-1 gap-6 lg:grid-cols-3 lg:auto-rows-auto">
        <div className="lg:col-span-2 lg:row-span-1 h-full">
          <ChartAreaDefault className="h-full" />
        </div>
        <Card className="lg:col-start-3 lg:row-start-1">
          <CardContent className="p-0">
            <DonutChartDemo />
          </CardContent>
        </Card>
        <Card className="lg:col-start-1 lg:row-start-2">
          <CardContent className="h-full p-4">
            <AttackStatsGrid />
          </CardContent>
        </Card>
        <Card className="lg:col-start-2 lg:col-span-2 lg:row-start-2">
          <CardContent className="p-0">
            <MiniChart />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
