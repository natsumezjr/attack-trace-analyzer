"use client";

import React from "react";

const THEME_STORAGE_KEY = "theme";

function applyThemeClass(isDark: boolean) {
  const root = document.documentElement;
  if (isDark) {
    root.classList.add("dark");
  } else {
    root.classList.remove("dark");
  }
}

export default function ThemeToggle() {
  const [mounted, setMounted] = React.useState(false);
  const [isDark, setIsDark] = React.useState(false);

  React.useEffect(() => {
    const saved = localStorage.getItem(THEME_STORAGE_KEY);
    const prefersDark = window.matchMedia?.(
      "(prefers-color-scheme: dark)"
    ).matches;
    const nextIsDark = saved ? saved === "dark" : prefersDark;
    setIsDark(nextIsDark);
    applyThemeClass(nextIsDark);
    setMounted(true);
  }, []);

  const handleToggle = () => {
    const nextIsDark = !isDark;
    setIsDark(nextIsDark);
    localStorage.setItem(THEME_STORAGE_KEY, nextIsDark ? "dark" : "light");
    applyThemeClass(nextIsDark);
  };

  return (
    <button
      type="button"
      onClick={handleToggle}
      aria-pressed={isDark}
      className="fixed right-4 top-4 z-50 rounded-full border border-border bg-background px-4 py-2 text-sm font-medium text-foreground shadow-sm transition-colors hover:bg-muted"
    >
      {mounted ? (isDark ? "浅色模式" : "深色模式") : "主题"}
    </button>
  );
}
