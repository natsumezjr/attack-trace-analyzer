import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { ThemeProvider } from "@/components/ui/theme-provider";
import { ModeToggle } from "@/components/mode-toggle";
// 1. 确保引入了你的 Providers 组件
import Providers from "./providers";
import { Toaster } from "@/components/ui/sonner";
const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Attack Trace Analyzer",
  description: "恶意攻击行为溯源分析系统",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        <ThemeProvider
          attribute="class"
          defaultTheme="system"
          enableSystem
          disableTransitionOnChange
        >
          {/* 2. 在这里插入 Providers，包裹住页面内容 */}
          <Providers>
            {/* ModeToggle 和 children 都放在 Providers 里面 */}
            <div className="fixed right-4 top-4 z-50 sm:right-6 sm:top-6">
              <ModeToggle />
            </div>

            {children}
          </Providers>
        </ThemeProvider>
      </body>
    </html>
  );
}
