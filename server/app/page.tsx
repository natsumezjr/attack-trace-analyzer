"use client";

import { motion, type DOMMotionComponents, type Variants } from "framer-motion";
import { FlowButton } from "@/components/index/flow-button";
import { ElegantShape } from "@/components/index/shape-landing-hero";
import DashBoardView from "@/components/dashboard-overview";

const MotionDiv: DOMMotionComponents["div"] = motion.div;

export default function Home() {
  const fadeUpVariants: Variants = {
    hidden: { opacity: 0, y: 30 },
    visible: (i: number) => ({
      opacity: 1,
      y: 0,
      transition: {
        duration: 1,
        delay: 0.5 + i * 0.2,
        ease: [0.25, 0.4, 0.25, 1] as const,
      },
    }),
  };

  return (
    <div className="relative min-h-screen w-full flex items-center justify-center overflow-hidden">
      <div className="absolute inset-0 bg-linear-to-br from-indigo-500/5 via-transparent to-rose-500/5 blur-3xl" />
      <div className="absolute inset-0 overflow-hidden">
        <ElegantShape
          delay={0.3}
          width={600}
          height={140}
          rotate={12}
          gradient="from-indigo-500/[0.15]"
          className="left-[-10%] md:left-[-5%] top-[15%] md:top-[20%]"
        />

        <ElegantShape
          delay={0.5}
          width={500}
          height={120}
          rotate={-15}
          gradient="from-rose-500/[0.15]"
          className="right-[-5%] md:right-[0%] top-[70%] md:top-[75%]"
        />

        <ElegantShape
          delay={0.4}
          width={300}
          height={80}
          rotate={-8}
          gradient="from-violet-500/[0.15]"
          className="left-[5%] md:left-[10%] bottom-[5%] md:bottom-[10%]"
        />

        <ElegantShape
          delay={0.6}
          width={200}
          height={60}
          rotate={20}
          gradient="from-amber-500/[0.15]"
          className="right-[15%] md:right-[20%] top-[10%] md:top-[15%]"
        />

        <ElegantShape
          delay={0.7}
          width={150}
          height={40}
          rotate={-25}
          gradient="from-cyan-500/[0.15]"
          className="left-[20%] md:left-[25%] top-[5%] md:top-[10%]"
        />
      </div>

      <div className="relative z-10 container mx-auto -mt-30 px-4 md:px-6">
        <div className="max-w-3xl mx-auto text-center">
          <MotionDiv
            custom={1}
            variants={fadeUpVariants}
            initial="hidden"
            animate="visible"
          >
            <h1 className="text-3xl sm:text-5xl md:text-7xl font-bold mb-6 md:mb-8 tracking-tight">
              <span className="bg-clip-text text-transparent bg-linear-to-b from-foreground to-foreground/80">
                AttackTraceAnalyzer
              </span>
              <br />
            </h1>
          </MotionDiv>

          <MotionDiv
            custom={2}
            variants={fadeUpVariants}
            initial="hidden"
            animate="visible"
          >
            <p className="text-base sm:text-lg md:text-xl text-muted-foreground mb-8 leading-relaxed font-light tracking-wide max-w-2xl mx-auto px-4">
              基于
              <span className="text-foreground font-medium">
                主机日志、行为监控
              </span>
              与<span className="text-foreground font-medium">网络流量</span>的
              <span className="text-foreground font-medium">多源数据融合</span>
              分析平台。实时构建攻击链路，将孤立的异常拼凑成
              <span className="text-foreground font-semibold drop-shadow-[0_0_10px_rgba(255,255,255,0.3)]">
                完整的入侵真相
              </span>
              。
            </p>
          </MotionDiv>
          <div className="mt-2 flex justify-center">
            <FlowButton text="进入分析控制台" href="/dashboard" />
          </div>
        </div>
        <div className="mt-20 w-full max-w-5xl mx-auto">
          <DashBoardView />
        </div>
      </div>

      <div className="absolute inset-0 bg-linear-to-t from-white/70 via-transparent to-white/40 dark:from-[#0b0b0b] dark:via-transparent dark:to-[#0b0b0b]/70 pointer-events-none" />
    </div>
  );
}
