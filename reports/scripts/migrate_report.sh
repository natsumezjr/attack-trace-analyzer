#!/usr/bin/env bash
set -euo pipefail

REPORT_DIR="${1:?需要指定报告目录名称}"
cd "$REPORT_DIR"

echo "🔄 迁移 $REPORT_DIR..."

# 创建新目录结构
mkdir -p chapters figures build

# 1. 合并内容层（generated + manual → chapters）
find generated/parts_tex manual/parts_tex -name "*.tex" -exec cp {} chapters/ \; 2>/dev/null || true

# 2. 创建 figures 目录和符号链接
for category_dir in ../assets/graphviz/*/; do
  category=$(basename "$category_dir")
  mkdir -p "figures/$category"

  # 为每个 PDF 创建符号链接
  for pdf in "$category_dir"*.pdf; do
    [ -f "$pdf" ] && ln -sf "$pdf" "figures/$category/"
  done
done

# 3. 移动编译产物到 build/
mv main.aux main.log main.out main.toc build/ 2>/dev/null || true
mkdir -p build && touch build/.gitkeep

# 4. 更新所有 .tex 文件中的路径引用
# 更新 main.tex
sed -i '' \
  -e 's|generated/parts_tex/|chapters/|g' \
  -e 's|manual/parts_tex/|chapters/|g' \
  -e 's|images/|figures/|g' \
  main.tex 2>/dev/null || true

# 更新 chapters/ 中的所有文件
find chapters -name "*.tex" -exec sed -i '' \
  -e 's|images/|figures/|g' {} \;

# 5. 保留 resources/（仅测试分析报告有内容）
# 其他报告的空 resources/ 将在清理阶段删除

echo "✅ $REPORT_DIR 迁移完成"
