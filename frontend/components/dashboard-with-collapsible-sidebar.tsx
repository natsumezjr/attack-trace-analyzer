"use client";
import React, { useEffect, useState } from "react";
import {
  DollarSign,
  ShoppingCart,
  Users,
  Moon,
  Sun,
  TrendingUp,
  Activity,
  Package,
  Bell,
  User,
  type LucideIcon,
} from "lucide-react";

type TrendItemColor = "green" | "blue" | "purple" | "orange" | "red";

type ExampleContentProps = {
  isDark: boolean;
  onToggleTheme: () => void;
};

type ActivityItem = {
  icon: LucideIcon;
  title: string;
  desc: string;
  time: string;
  color: TrendItemColor;
};

export const Example: React.FC = () => {
  const [isDark, setIsDark] = useState(false);

  useEffect(() => {
    const savedTheme = localStorage.getItem("theme");
    const prefersDark = window.matchMedia?.(
      "(prefers-color-scheme: dark)"
    ).matches;
    setIsDark(savedTheme ? savedTheme === "dark" : prefersDark);
  }, []);

  useEffect(() => {
    if (isDark) {
      document.documentElement.classList.add("dark");
      localStorage.setItem("theme", "dark");
    } else {
      document.documentElement.classList.remove("dark");
      localStorage.setItem("theme", "light");
    }
  }, [isDark]);

  return (
    <ExampleContent
      isDark={isDark}
      onToggleTheme={() => setIsDark((prev) => !prev)}
    />
  );
};

const ExampleContent: React.FC<ExampleContentProps> = ({
  isDark,
  onToggleTheme,
}) => {
  const activityItems: ActivityItem[] = [
    {
      icon: DollarSign,
      title: "新告警触发",
      desc: "高危命中：横向移动疑似行为",
      time: "2 分钟前",
      color: "green",
    },
    {
      icon: Users,
      title: "新增可疑主机",
      desc: "主机 H-24 出现异常登录",
      time: "5 分钟前",
      color: "blue",
    },
    {
      icon: Package,
      title: "流量异常更新",
      desc: "外联到可疑 C2 域名",
      time: "10 分钟前",
      color: "purple",
    },
    {
      icon: Activity,
      title: "溯源链路完成",
      desc: "攻击路径已拼接完成",
      time: "1 小时前",
      color: "orange",
    },
    {
      icon: Bell,
      title: "新增通知",
      desc: "处置工单已派发",
      time: "2 小时前",
      color: "red",
    },
  ];

  return (
    <div className="p-6 overflow-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-gray-100">
            攻击溯源分析控制台
          </h1>
          <p className="text-gray-600 dark:text-gray-400 mt-1">
            欢迎进入 attack-trace-analyzer 分析台
          </p>
        </div>
        <div className="flex items-center gap-4">
          <button className="relative p-2 rounded-lg bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100 transition-colors">
            <Bell className="h-5 w-5" />
            <span className="absolute -top-1 -right-1 h-3 w-3 bg-red-500 rounded-full"></span>
          </button>
          <button
            onClick={onToggleTheme}
            className="flex h-10 w-10 items-center justify-center rounded-lg border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 text-gray-600 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-800 hover:text-gray-900 dark:hover:text-gray-100 transition-colors"
          >
            {isDark ? (
              <Sun className="h-4 w-4" />
            ) : (
              <Moon className="h-4 w-4" />
            )}
          </button>
          <button className="p-2 rounded-lg bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100 transition-colors">
            <User className="h-5 w-5" />
          </button>
        </div>
      </div>

      {/* 统计概览 */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <div className="p-6 rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 shadow-sm hover:shadow-md transition-shadow">
          <div className="flex items-center justify-between mb-4">
            <div className="p-2 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
              <DollarSign className="h-5 w-5 text-blue-600 dark:text-blue-400" />
            </div>
            <TrendingUp className="h-4 w-4 text-green-500" />
          </div>
          <h3 className="font-medium text-gray-600 dark:text-gray-400 mb-1">
            告警总数
          </h3>
          <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">
            24,567
          </p>
          <p className="text-sm text-green-600 dark:text-green-400 mt-1">
            +12% 较上月
          </p>
        </div>

        <div className="p-6 rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 shadow-sm hover:shadow-md transition-shadow">
          <div className="flex items-center justify-between mb-4">
            <div className="p-2 bg-green-50 dark:bg-green-900/20 rounded-lg">
              <Users className="h-5 w-5 text-green-600 dark:text-green-400" />
            </div>
            <TrendingUp className="h-4 w-4 text-green-500" />
          </div>
          <h3 className="font-medium text-gray-600 dark:text-gray-400 mb-1">
            可疑主机
          </h3>
          <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">
            1,234
          </p>
          <p className="text-sm text-green-600 dark:text-green-400 mt-1">
            +5% 较上周
          </p>
        </div>

        <div className="p-6 rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 shadow-sm hover:shadow-md transition-shadow">
          <div className="flex items-center justify-between mb-4">
            <div className="p-2 bg-purple-50 dark:bg-purple-900/20 rounded-lg">
              <ShoppingCart className="h-5 w-5 text-purple-600 dark:text-purple-400" />
            </div>
            <TrendingUp className="h-4 w-4 text-green-500" />
          </div>
          <h3 className="font-medium text-gray-600 dark:text-gray-400 mb-1">
            高危事件
          </h3>
          <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">
            456
          </p>
          <p className="text-sm text-green-600 dark:text-green-400 mt-1">
            +8% 较昨日
          </p>
        </div>

        <div className="p-6 rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 shadow-sm hover:shadow-md transition-shadow">
          <div className="flex items-center justify-between mb-4">
            <div className="p-2 bg-orange-50 dark:bg-orange-900/20 rounded-lg">
              <Package className="h-5 w-5 text-orange-600 dark:text-orange-400" />
            </div>
            <TrendingUp className="h-4 w-4 text-green-500" />
          </div>
          <h3 className="font-medium text-gray-600 dark:text-gray-400 mb-1">
            处置闭环
          </h3>
          <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">
            89
          </p>
          <p className="text-sm text-green-600 dark:text-green-400 mt-1">
            本周新增 +3
          </p>
        </div>
      </div>

      {/* 内容区 */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* 最新动态 */}
        <div className="lg:col-span-2">
          <div className="rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 p-6 shadow-sm">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                最新告警与溯源
              </h3>
              <button className="text-sm text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 font-medium">
                查看全部
              </button>
            </div>
            <div className="space-y-4">
              {activityItems.map((activity, i) => (
                <div
                  key={i}
                  className="flex items-center space-x-4 p-3 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors cursor-pointer"
                >
                  <div
                    className={`p-2 rounded-lg ${
                      activity.color === "green"
                        ? "bg-green-50 dark:bg-green-900/20"
                        : activity.color === "blue"
                        ? "bg-blue-50 dark:bg-blue-900/20"
                        : activity.color === "purple"
                        ? "bg-purple-50 dark:bg-purple-900/20"
                        : activity.color === "orange"
                        ? "bg-orange-50 dark:bg-orange-900/20"
                        : "bg-red-50 dark:bg-red-900/20"
                    }`}
                  >
                    <activity.icon
                      className={`h-4 w-4 ${
                        activity.color === "green"
                          ? "text-green-600 dark:text-green-400"
                          : activity.color === "blue"
                          ? "text-blue-600 dark:text-blue-400"
                          : activity.color === "purple"
                          ? "text-purple-600 dark:text-purple-400"
                          : activity.color === "orange"
                          ? "text-orange-600 dark:text-orange-400"
                          : "text-red-600 dark:text-red-400"
                      }`}
                    />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-gray-900 dark:text-gray-100 truncate">
                      {activity.title}
                    </p>
                    <p className="text-xs text-gray-500 dark:text-gray-400 truncate">
                      {activity.desc}
                    </p>
                  </div>
                  <div className="text-xs text-gray-400 dark:text-gray-500">
                    {activity.time}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* 关键指标 */}
        <div className="space-y-6">
          <div className="rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 p-6 shadow-sm">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
              关键指标
            </h3>
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-600 dark:text-gray-400">
                  告警命中率
                </span>
                <span className="text-sm font-medium text-gray-900 dark:text-gray-100">
                  3.2%
                </span>
              </div>
              <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                <div
                  className="bg-blue-500 h-2 rounded-full"
                  style={{ width: "32%" }}
                ></div>
              </div>

              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-600 dark:text-gray-400">
                  误报率
                </span>
                <span className="text-sm font-medium text-gray-900 dark:text-gray-100">
                  45%
                </span>
              </div>
              <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                <div
                  className="bg-orange-500 h-2 rounded-full"
                  style={{ width: "45%" }}
                ></div>
              </div>

              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-600 dark:text-gray-400">
                  日志日均量
                </span>
                <span className="text-sm font-medium text-gray-900 dark:text-gray-100">
                  8.7k
                </span>
              </div>
              <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                <div
                  className="bg-green-500 h-2 rounded-full"
                  style={{ width: "87%" }}
                ></div>
              </div>
            </div>
          </div>

          <div className="rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 p-6 shadow-sm">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
              关键资产
            </h3>
            <div className="space-y-3">
              {[
                { name: "核心数据库节点", score: 92 },
                { name: "堡垒机网关", score: 88 },
                { name: "业务主机集群", score: 81 },
                { name: "办公终端域", score: 76 },
              ].map((product, i) => (
                <div key={i} className="flex items-center justify-between py-2">
                  <span className="text-sm text-gray-600 dark:text-gray-400">
                    {product.name}
                  </span>
                  <span className="text-sm font-medium text-gray-900 dark:text-gray-100">
                    风险分值 {product.score}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Example;
