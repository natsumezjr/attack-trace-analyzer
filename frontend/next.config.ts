import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // 禁用 Turbopack，使用 Webpack（解决字体加载问题）
  // 保持现有字体不变
  // experimental: {
  //   turbo: false,
  // },
};

export default nextConfig;
