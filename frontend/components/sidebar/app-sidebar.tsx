"use client";
import React from "react";
import { Sidebar, SidebarBody, SidebarLink } from "@/components/ui/sidebar";
import { LayoutDashboard, ClipboardList, FishingHook } from "lucide-react";
import { House } from "lucide-react";
import Link from "next/link";
import { cn } from "@/lib/utils";
import { usePathname } from "next/navigation";

export function SidebarDemo({ children }: { children?: React.ReactNode }) {
  const pathname = usePathname();
  const links = [
    {
      label: "主页",
      href: "/",
      icon: (
        <House className="text-sidebar-foreground/70 h-6 w-6 flex-shrink-0" />
      ),
    },
    {
      label: "数据总览",
      href: "/dashboard",
      icon: (
        <LayoutDashboard className="text-sidebar-foreground/70 h-6 w-6 flex-shrink-0" />
      ),
    },
    {
      label: "溯源分析",
      href: "/trace",
      icon: (
        <FishingHook className="text-sidebar-foreground/70 h-6 w-6 flex-shrink-0" />
      ),
    },
    {
      label: "溯源任务",
      href: "/analysis/tasks",
      icon: (
        <ClipboardList className="text-sidebar-foreground/70 h-6 w-6 flex-shrink-0" />
      ),
    },
  ];
  return (
    <div
      className={cn(
        "flex min-h-screen w-full flex-col md:flex-row bg-background text-foreground"
      )}
    >
      <Sidebar open={true} setOpen={() => {}} animate={false}>
        <SidebarBody className="justify-between gap-10">
          <div className="flex flex-col flex-1 overflow-y-auto overflow-x-hidden">
            <Logo />
            <div className="mt-8 flex flex-col gap-2">
              {links.map((link, idx) => {
                const isDashboard =
                  link.href === "/dashboard" &&
                  (pathname === "/dashboard" ||
                    pathname.startsWith("/dashboard/"));
                return (
                  <SidebarLink
                    key={idx}
                    link={link}
                    className={cn(
                      "rounded-md px-3 transition-colors",
                      isDashboard && "bg-sidebar-accent/60"
                    )}
                  />
                );
              })}
            </div>
          </div>
          <div></div>
        </SidebarBody>
      </Sidebar>
      <div className="flex flex-1">{children}</div>
    </div>
  );
}

export const Logo = () => {
  return (
    <Link
      href="#"
      className="font-normal flex items-center text-base text-sidebar-foreground py-1 relative z-20"
    >
      <span className="font-medium text-sidebar-foreground whitespace-pre">
        AttackTraceAnalyzer
      </span>
    </Link>
  );
};
