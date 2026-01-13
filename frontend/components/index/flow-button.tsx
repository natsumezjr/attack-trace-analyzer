"use client";

import Link from "next/link";
import { ArrowRight } from "lucide-react";

type FlowButtonProps = {
  text?: string;
  href?: string;
};

export function FlowButton({ text = "进入系统", href }: FlowButtonProps) {
  const className =
    "group relative flex items-center gap-2 overflow-hidden rounded-[100px] border-[1.5px] border-black bg-white px-10 py-4 text-base font-semibold text-[#111111] cursor-pointer transition-all duration-600 ease-[cubic-bezier(0.23,1,0.32,1)] hover:border-transparent hover:text-white hover:rounded-2xl active:scale-[0.95]";

  const content = (
    <>
      <ArrowRight className="absolute w-5 h-5 left-[-25%] stroke-[#111111] fill-none z-9 group-hover:left-4 group-hover:stroke-white transition-all duration-800 ease-[cubic-bezier(0.34,1.56,0.64,1)]" />
      <span className="relative z-1 -translate-x-3 group-hover:translate-x-3 transition-all duration-800 ease-out">
        {text}
      </span>
      <span className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-5 h-5 bg-[#111111] rounded-[50%] opacity-0 group-hover:w-55 group-hover:h-55 group-hover:opacity-100 transition-all duration-800 ease-[cubic-bezier(0.19,1,0.22,1)]"></span>
      <ArrowRight className="absolute w-5 h-5 right-4 stroke-[#111111] fill-none z-9 group-hover:right-[-25%] group-hover:stroke-white transition-all duration-800 ease-[cubic-bezier(0.34,1.56,0.64,1)]" />
    </>
  );

  if (href) {
    return (
      <Link href={href} className={className}>
        {content}
      </Link>
    );
  }

  return <button className={className}>{content}</button>;
}
