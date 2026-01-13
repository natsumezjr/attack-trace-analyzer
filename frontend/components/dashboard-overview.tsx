import React from "react";
import { motion } from "framer-motion";
import { cn } from "@/lib/utils"; // Assumes shadcn's utility for class merging
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  ArrowDown,
  ArrowUp,
  Minus,
  Users,
  DollarSign,
  Clock,
  AlertCircle,
} from "lucide-react";

// Define the icon type. Using React.ElementType for flexibility.
type IconType =
  | React.ElementType
  | React.FunctionComponent<React.SVGProps<SVGSVGElement>>;

// Define trend types
export type TrendType = "up" | "down" | "neutral";

// --- 📦 API (Props) Definition ---
export interface DashboardMetricCardProps {
  /** The main value of the metric (e.g., "1,234", "$5.6M", "92%"). */
  value: string;
  /** The descriptive title of the metric (e.g., "Total Users", "Revenue"). */
  title: string;
  /** Optional icon to display in the card header. */
  icon?: IconType;
  /** The percentage or absolute change for the trend (e.g., "2.5%"). */
  trendChange?: string;
  /** The direction of the trend ('up', 'down', 'neutral'). */
  trendType?: TrendType;
  /** Optional class name for the card container. */
  className?: string;
}

/**
 * A professional, animated metric card for admin dashboards.
 * Displays a key value, title, icon, and trend indicator with Framer Motion hover effects.
 */
const DashboardMetricCard: React.FC<DashboardMetricCardProps> = ({
  value,
  title,
  icon: IconComponent,
  trendChange,
  trendType = "neutral",
  className,
}) => {
  // Determine trend icon and color
  const TrendIcon =
    trendType === "up" ? ArrowUp : trendType === "down" ? ArrowDown : Minus;
  const trendColorClass =
    trendType === "up"
      ? "text-green-600 dark:text-green-400"
      : trendType === "down"
      ? "text-red-600 dark:text-red-400"
      : "text-muted-foreground";

  return (
    <motion.div
      whileHover={{
        y: -4,
        boxShadow:
          "0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1)",
      }} // Subtle lift and shadow on hover
      transition={{ type: "spring", stiffness: 400, damping: 20 }}
      className={cn(
        "cursor-pointer rounded-lg flex-1 basis-full sm:basis-[calc(50%-1rem)] lg:basis-[calc(25%-1.5rem)]", // Ensure cursor indicates interactivity
        className
      )}
    >
      <Card className="h-full min-h-45 transition-colors duration-200">
        <CardHeader className="flex flex-row items-center justify-between space-y-0 px-7 pt-7 pb-3">
          <CardTitle className="text-sm font-medium text-muted-foreground">
            {title}
          </CardTitle>
          {IconComponent && (
            <IconComponent
              className="h-4 w-4 text-muted-foreground"
              aria-hidden="true"
            />
          )}
        </CardHeader>
        <CardContent className="px-7 pb-7 text-center">
          <div className="text-3xl font-bold text-foreground mb-3">{value}</div>
          {trendChange && (
            <p
              className={cn(
                "flex items-center justify-center text-sm font-medium",
                trendColorClass
              )}
            >
              <TrendIcon className="h-3 w-3 mr-1" aria-hidden="true" />
              {trendChange}{" "}
              {trendType === "up"
                ? "上升"
                : trendType === "down"
                ? "下降"
                : "变化"}
            </p>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
};

const DashBoardView = () => {
  return (
    <div className="flex flex-col gap-8 sm:flex-row sm:flex-wrap">
      <DashboardMetricCard
        title="可疑主机"
        value="70台"
        icon={Users}
        trendChange="+20"
        trendType="up"
      />
      <DashboardMetricCard
        title="告警总数"
        value="1,245"
        icon={DollarSign}
        trendChange="-2.5%"
        trendType="down"
      />
      <DashboardMetricCard
        title="平均处置"
        value="1.3s"
        icon={Clock}
        trendChange="+0.5s"
        trendType="up" // Or "up" if positive
      />
      <DashboardMetricCard
        title="未闭环事件"
        value="12"
        icon={AlertCircle} // Using AlertCircle from lucide-react if needed
        trendChange="+3"
        trendType="up"
      />
    </div>
  );
};

export default DashBoardView;
