import type { NextConfig } from "next";

// 从环境变量读取后端 URL，默认值为 http://localhost:8001
const backendOrigin = process.env.BACKEND_BASE_URL || "http://localhost:8001";

const nextConfig: NextConfig = {
  async rewrites() {
    return [
      { source: "/api/:path*", destination: `${backendOrigin}/api/:path*` },
      { source: "/health", destination: `${backendOrigin}/health` },
    ];
  },
  images: {
    remotePatterns: [
      {
        protocol: "https",
        hostname: "assets.aceternity.com",
      },
    ],
  },
};

export default nextConfig;
