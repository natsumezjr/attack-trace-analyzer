#!/usr/bin/env bash
set -euo pipefail

# Compile PDFs for all 6 deliverable reports under reports/.
#
# Notes:
# - Runs XeLaTeX twice per report to stabilize TOC/labels.
# - Keeps build artifacts (main.aux/main.log/...) in each report folder;
#   they are ignored by each report's .gitignore.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

REPORT_DIRS=(
  "任务分工说明"
  "作品技术原理介绍"
  "概要设计报告"
  "详细设计报告"
  "测试分析报告"
  "程序编译和安装使用文档"
)

for d in "${REPORT_DIRS[@]}"; do
  echo
  echo "== build: $d =="
  (cd "$d" && xelatex -interaction=nonstopmode -halt-on-error main.tex >/tmp/ata_build_1.log 2>&1)
  (cd "$d" && xelatex -interaction=nonstopmode -halt-on-error main.tex >/tmp/ata_build_2.log 2>&1)
  echo "OK: $d/main.pdf"
done

echo
echo "OK: all PDFs compiled."

