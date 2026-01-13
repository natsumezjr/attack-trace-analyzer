import {
  HoverCard,
  HoverCardContent,
  HoverCardTrigger,
} from "@/components/ui/hover-card";
import { Server, ShieldAlert, Activity } from "lucide-react";

export function StatsGrid() {
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-8 md:gap-16 mt-16 text-center">
      <HoverCard openDelay={50}>
        <HoverCardTrigger asChild>
          <div className="flex flex-col items-center group cursor-default transition-all hover:bg-white/5 p-4 rounded-xl">
            <span className="text-4xl md:text-5xl font-bold text-cyan-300 tracking-tighter group-hover:scale-110 transition-transform duration-300">
              5
            </span>
            <span className="text-xs md:text-sm text-neutral-500 font-medium uppercase tracking-widest mt-2 group-hover:text-cyan-300/70 transition-colors">
              在线靶机
            </span>
          </div>
        </HoverCardTrigger>
        <HoverCardContent className="w-64 bg-neutral-900 border-neutral-800 text-neutral-200 shadow-2xl">
          <div className="space-y-3">
            <h4 className="text-sm font-semibold flex items-center gap-2 text-white">
              <Server className="h-4 w-4 text-cyan-300" /> 节点状态概览
            </h4>
            <div className="space-y-2">
              {[
                "192.168.1.101 (Win10)",
                "192.168.1.102 (Linux)",
                "192.168.1.105 (Server)",
              ].map((node) => (
                <div
                  key={node}
                  className="flex items-center justify-between text-xs"
                >
                  <span className="text-neutral-400">{node}</span>
                  <span className="flex h-2 w-2 rounded-full bg-cyan-400 shadow-[0_0_8px_rgba(34,211,238,0.45)]"></span>
                </div>
              ))}
              <div className="flex items-center justify-between text-xs opacity-50">
                <span>+2 更多节点...</span>
              </div>
            </div>
          </div>
        </HoverCardContent>
      </HoverCard>

      <HoverCard openDelay={50}>
        <HoverCardTrigger asChild>
          <div className="flex flex-col items-center group cursor-default transition-all hover:bg-white/5 p-4 rounded-xl">
            <span className="text-4xl md:text-5xl font-bold text-rose-400 tracking-tighter group-hover:scale-110 transition-transform duration-300">
              12
            </span>
            <span className="text-xs md:text-sm text-neutral-500 font-medium uppercase tracking-widest mt-2 group-hover:text-rose-400/70 transition-colors">
              今日威胁
            </span>
          </div>
        </HoverCardTrigger>
        <HoverCardContent className="w-64 bg-neutral-900 border-neutral-800 text-neutral-200 shadow-2xl">
          <div className="space-y-3">
            <h4 className="text-sm font-semibold flex items-center gap-2 text-white">
              <ShieldAlert className="h-4 w-4 text-rose-400" /> 高危告警 Top 3
            </h4>
            <div className="grid gap-2">
              <div className="flex items-center gap-2 text-xs border-l-2 border-rose-400 pl-2 bg-rose-400/5 p-1">
                <span className="font-mono text-rose-200">SSH 暴力破解</span>
                <span className="ml-auto text-neutral-500">2m ago</span>
              </div>
              <div className="flex items-center gap-2 text-xs border-l-2 border-amber-400/80 pl-2 bg-amber-400/5 p-1">
                <span className="font-mono text-amber-200">SQL 注入尝试</span>
                <span className="ml-auto text-neutral-500">15m ago</span>
              </div>
            </div>
          </div>
        </HoverCardContent>
      </HoverCard>

      <HoverCard openDelay={50}>
        <HoverCardTrigger asChild>
          <div className="flex flex-col items-center group cursor-default transition-all hover:bg-white/5 p-4 rounded-xl">
            <span className="text-4xl md:text-5xl font-bold text-indigo-300 tracking-tighter group-hover:scale-110 transition-transform duration-300">
              24.5
            </span>
            <span className="text-xs md:text-sm text-neutral-500 font-medium uppercase tracking-widest mt-2 group-hover:text-indigo-300/70 transition-colors">
              Mbps 流量
            </span>
          </div>
        </HoverCardTrigger>
        <HoverCardContent className="w-64 bg-neutral-900 border-neutral-800 text-neutral-200 shadow-2xl">
          <div className="flex justify-between space-x-4">
            <div className="space-y-1">
              <h4 className="text-sm font-semibold flex items-center gap-2 text-white">
                <ShieldAlert className="h-4 w-4 text-indigo-300" /> 流量统计
              </h4>
              <p className="text-xs text-neutral-400">当前出入站流量总和</p>
              <div className="flex items-center pt-2">
                <Activity className="mr-2 h-4 w-4 text-indigo-300/70" />{" "}
                <span className="text-xs text-neutral-400">峰值: 102 Mbps</span>
              </div>
            </div>
          </div>
        </HoverCardContent>
      </HoverCard>

      <HoverCard openDelay={50}>
        <HoverCardTrigger asChild>
          <div className="flex flex-col items-center group cursor-default transition-all hover:bg-white/5 p-4 rounded-xl">
            <span className="text-4xl md:text-5xl font-bold text-amber-200 tracking-tighter group-hover:scale-110 transition-transform duration-300">
              98
            </span>
            <span className="text-xs md:text-sm text-neutral-500 font-medium uppercase tracking-widest mt-2 group-hover:text-amber-200/70 transition-colors">
              安全评分
            </span>
          </div>
        </HoverCardTrigger>
        <HoverCardContent className="w-64 bg-neutral-900 border-neutral-800 text-neutral-200 shadow-2xl">
          <div className="space-y-2">
            <h4 className="text-sm font-semibold flex items-center gap-2 text-white">
              <ShieldAlert className="h-4 w-4 text-amber-200" /> 系统健康度报告
            </h4>
            <div className="text-xs text-neutral-400">
              <p>扣分原因:</p>
              <ul className="list-disc list-inside text-rose-300 mt-1">
                <li>检测到弱口令账号 (admin)</li>
                <li>未打补丁: CVE-2025-102</li>
              </ul>
            </div>
          </div>
        </HoverCardContent>
      </HoverCard>
    </div>
  );
}
