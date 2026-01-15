import { Badge } from "@/components/badge-2";
import { Card, CardContent } from "@/components/card";
import { CheckCircle2, LifeBuoy, Smile } from "lucide-react";

import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/**
 * Merges Tailwind class names, resolving any conflicts.
 *
 * @param inputs - An array of class names to merge.
 * @returns A string of merged and optimized class names.
 */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

const cards = [
  {
    icon: LifeBuoy,
    iconBg:
      "border-blue-200 dark:border-blue-800 text-blue-600 dark:text-blue-400",
    value: 320,
    label: "Support Tickets",
    info: (
      <Badge variant="secondary" appearance="light">
        12 Open, 308 Closed
      </Badge>
    ),
  },
  {
    icon: CheckCircle2,
    iconBg:
      "border-green-200 dark:border-green-800 text-green-600 dark:text-green-400",
    value: "98%",
    label: "Resolved",
    info: (
      <Badge variant="success" appearance="light">
        +2.1% this month
      </Badge>
    ),
  },
  {
    icon: Smile,
    iconBg:
      "border-yellow-200 dark:border-yellow-800 text-yellow-600 dark:text-yellow-400",
    value: "4.8",
    label: "Satisfaction Rate",
    info: (
      <Badge variant="secondary" appearance="light">
        Avg. (out of 5)
      </Badge>
    ),
  },
];

export default function StatisticCard12() {
  return (
    <div className="w-full max-w-5xl min-h-screen flex items-center justify-center p-6 lg:p-8">
      <div className="@container grow w-full">
        <div className="grow grid grid-cols-1 @3xl:grid-cols-3 gap-5 max-w-5xl">
          {cards.map((card, i) => (
            <Card key={i}>
              <CardContent className="flex flex-col items-start gap-6">
                {/* Icon */}
                <div
                  className={cn(
                    `rounded-xl flex items-center justify-center size-12 border`,
                    card.iconBg
                  )}
                >
                  <card.icon className="size-6" />
                </div>

                {/* Value & Label */}
                <div className="space-y-0.5">
                  <div className="text-2xl font-bold text-foreground leading-none">
                    {card.value}
                  </div>
                  <div className="text-sm text-muted-foreground">
                    {card.label}
                  </div>
                </div>

                {card.info}
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    </div>
  );
}
