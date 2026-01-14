import Link from "next/link";

import { Button } from "@/components/ui/button";
import { ModeToggle } from "@/components/mode-toggle";
import { Globe } from "@/components/ui/globe";
import {
  AnimatedProfileCard,
  ProfileCardContent,
} from "@/components/ui/animated-profile-card";

export default function Home() {
  const cards = [
    {
      name: "主机日志采集",
      location: "统一汇聚关键系统事件",
      bio: "覆盖登录、进程、文件改动等关键指标，构建完整审计视图。",
    },
    {
      name: "主机行为画像",
      location: "刻画异常操作轨迹",
      bio: "识别权限提升、横向移动等行为链路，快速锁定威胁路径。",
    },
    {
      name: "网络流量分析",
      location: "洞察外联与渗透",
      bio: "追踪异常流量与 C2 通信，关联终端与网络证据。",
    },
    {
      name: "溯源时间线",
      location: "还原攻击全流程",
      bio: "将多源数据汇总成攻击时间线，辅助快速处置与复盘。",
    },
  ];

  return (
    <div className="relative min-h-screen overflow-hidden bg-background text-foreground">
      <div className="pointer-events-none absolute inset-0 opacity-70 [background:radial-gradient(120%_140%_at_0%_0%,hsl(var(--secondary))_0%,transparent_55%),radial-gradient(120%_140%_at_100%_0%,hsl(var(--accent))_0%,transparent_60%)]" />
      <div className="pointer-events-none absolute inset-0 opacity-50 [background:linear-gradient(120deg,transparent_0%,hsl(var(--muted-foreground)/0.12)_25%,transparent_50%)]" />
      <div className="pointer-events-none absolute -left-24 top-12 h-72 w-72 rounded-full bg-primary/10 blur-3xl" />
      <div className="pointer-events-none absolute -right-16 bottom-10 h-80 w-80 rounded-full bg-accent/20 blur-3xl" />

      <main className="relative mx-auto flex min-h-screen w-full max-w-6xl flex-col items-center justify-center px-6 py-24">
        <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
          <Globe className="scale-125 opacity-60 blur-[0.2px]" />
        </div>
        <div className="absolute right-4 top-4 sm:right-6 sm:top-6">
          <ModeToggle />
        </div>
        <section className="relative z-10 flex w-full animate-in flex-col items-center text-center fade-in-0 slide-in-from-bottom-4 duration-700">
          <h1 className="mt-6 text-4xl font-semibold tracking-tight sm:text-5xl lg:text-6xl">
            AttackTraceAnalyzer
          </h1>
          <p className="mt-5 max-w-3xl text-base leading-7 text-muted-foreground dark:text-foreground/80 sm:text-lg">
            基于主机日志、主机行为、网络流量的恶意攻击行为溯源分析系统
          </p>
          <div className="mt-8">
            <Button
              asChild
              size="lg"
              className="rounded-full px-8 shadow-lg transition-transform duration-200 ease-out hover:-translate-y-1"
            >
              <Link href="/dashboard">Go Dashboard</Link>
            </Button>
          </div>
        </section>

        <section className="relative z-10 mt-14 grid w-full gap-6 sm:grid-cols-2 lg:grid-cols-4">
          {cards.map((card) => (
            <AnimatedProfileCard
              key={card.name}
              className="h-full min-h-[260px] w-full"
              baseCard={
                <ProfileCardContent
                  name={card.name}
                  location={card.location}
                  bio={card.bio}
                />
              }
              overlayCard={
                <ProfileCardContent
                  name={card.name}
                  location={card.location}
                  bio={card.bio}
                  variant="on-accent"
                  cardStyle={{ background: "var(--accent-color)" }}
                />
              }
            />
          ))}
        </section>
      </main>
    </div>
  );
}
