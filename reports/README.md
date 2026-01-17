# Reports 文档与 PDF 编译指南

> **当前状态**：本项目已确定**不再使用 Markdown 作为内容源**，所有报告均以 `.tex` 文件为准进行修改与合并。

> **2026-01-17 统一更新**：所有六份报告现已使用**统一的 LaTeX 模板**，确保格式一致性。

---

## 📋 目录结构

```
reports/
├── README.md                          # 本文件：报告生成与维护指南
├── scripts/                           # 脚本与模板
│   └── templates/
│       └── main.tex.template          # 统一的 LaTeX 主文件模板
├── build_all_pdfs.sh                  # 编译所有 PDF 的入口脚本
├── 任务分工说明/
│   ├── main.pdf                       # 最终 PDF 报告（8 页）
│   ├── chapters/                      # 章节 .tex 文件
│   └── main.tex                       # LaTeX 主文件（使用统一模板）
├── 作品技术原理介绍/
│   ├── main.pdf                       # 最终 PDF 报告（10 页）
│   ├── chapters/
│   └── main.tex
├── 概要设计报告/
│   ├── main.pdf                       # 最终 PDF 报告（26 页）
│   ├── chapters/
│   └── main.tex
├── 详细设计报告/
│   ├── main.pdf                       # 最终 PDF 报告（137 页）
│   ├── chapters/
│   └── main.tex
├── 测试分析报告/
│   ├── main.pdf                       # 最终 PDF 报告（33 页）
│   ├── chapters/
│   └── main.tex
└── 程序编译和安装使用文档/
    ├── main.pdf                       # 最终 PDF 报告（49 页）
    ├── chapters/
    └── main.tex
```

---

## 🎯 当前工作方式（2026-01-17 统一更新）

### 核心原则

1. **统一模板**：所有六份报告使用相同的 `main.tex` 模板（位于 `scripts/templates/main.tex.template`）
2. **以 LaTeX 为准**：所有内容修改直接在 `.tex` 文件上进行
3. **章节结构**：每个报告的章节存放在 `chapters/*.tex`，通过 `index.tex` 统一引入
4. **双重编译**：每次编译需运行 XeLaTeX 两次以正确生成目录和交叉引用
5. **清理中间文件**：编译完成后清理 `.aux`, `.log`, `.out`, `.toc` 等中间文件

### 统一模板特性

所有报告的 `main.tex` 均包含以下增强功能：

- **表格溢出修复**：`tabularx`, `adjustbox`, longtable 优化
- **长路径/代码块处理**：`seqsplit`, 自动断行
- **版面优化**：段落间距、列表间距、容错设置
- **图表支持**：Graphviz PDF 图表自动引用

### 文件修改流程

**直接修改章节文件**：

1. 编辑 `chapters/*.tex` 文件进行内容修改
2. 编辑 `index.tex` 添加/删除章节引用
3. 编译 PDF（双重编译）
4. 清理中间文件

**模板更新流程**（如需修改全局样式）：

1. 修改 `scripts/templates/main.tex.template`
2. 将模板复制到各报告目录，替换 `main.tex`
3. 保持各报告的 `\DocTitle` 命令不变

---

## 📦 PDF 编译流程

### 编译单个报告（双重编译）

```bash
cd reports/<报告名>
xelatex -interaction=nonstopmode main.tex  # 第一遍
xelatex -interaction=nonstopmode main.tex  # 第二遍生成目录

# 清理中间文件
rm -f main.aux main.log main.out main.toc
```

### 编译所有报告

```bash
cd reports
for dir in */; do
  if [ -f "$dir/main.tex" ]; then
    echo "Compiling $dir"
    cd "$dir"
    xelatex -interaction=nonstopmode main.tex > /dev/null 2>&1
    xelatex -interaction=nonstopmode main.tex > /dev/null 2>&1
    cd ..
  fi
done

# 清理所有中间文件
for dir in */; do
  rm -f "$dir"/main.aux "$dir"/main.log "$dir"/main.out "$dir"/main.toc
done
```

### 依赖

```bash
# XeLaTeX（macOS 自带，或通过 MacTeX 安装）
# 检查：xelatex --version

# Graphviz（用于生成图表）
brew install graphviz
```

---

## 🔧 工具与模板

### main.tex.template

统一的 LaTeX 主文件模板，位于 `scripts/templates/main.tex.template`。

**包含特性**：
- 表格溢出修复（`tabularx`, `adjustbox`）
- 长路径/代码块处理（`seqsplit`, 自动断行）
- 版面优化（段落间距、列表间距、容错设置）
- 图表支持（Graphviz PDF）

**更新方法**：
如需修改全局样式，编辑模板文件后复制到各报告目录，确保 `\DocTitle` 正确。

### build_all_pdfs.sh

编译所有报告的 PDF。

**状态**：保留用于批量编译

---

## 🐛 常见问题

### Q: breakurl 包兼容性问题

**错误**：

```
! Undefined control sequence.
\burl@condpdflink ...
```

**解决**：
在 `main.tex` 中注释掉 breakurl 包：

```latex
% \usepackage{breakurl}  % 与 XeLaTeX + hyperref 不兼容
```

### Q: IP 地址斜杠显示问题

**错误**：

```
! Missing number, treated as zero.
\texttt{10.0.0.0/8}
```

**解决**：
使用 `\verb|10.0.0.0/8|` 代替 `\texttt{10.0.0.0/8}`

---

## 📊 当前报告状态

| 报告名称               | 页数 | 文件大小 | 最后更新   |
| ---------------------- | ---- | -------- | ---------- |
| 任务分工说明           | 8    | 152 KB   | 2026-01-17 |
| 作品技术原理介绍       | 10   | 186 KB   | 2026-01-17 |
| 概要设计报告           | 26   | 391 KB   | 2026-01-17 |
| 详细设计报告           | 137  | 726 KB   | 2026-01-17 |
| 测试分析报告           | 33   | 372 KB   | 2026-01-17 |
| 程序编译和安装使用文档 | 49   | 440 KB   | 2026-01-17 |

---

## 🔄 更新日志

### 2026-01-17 - 格式统一更新

- ✅ **统一模板**：所有六份报告使用相同的 `main.tex` 模板
- ✅ **增强功能**：添加表格溢出修复、长路径处理、版面优化
- ✅ **双重编译**：所有报告完成双重编译，生成完整目录
- ✅ **清理中间文件**：删除 `.aux`, `.log`, `.out`, `.toc` 等中间文件
- ✅ **目录结构**：统一使用 `chapters/ + index.tex → main.tex` 结构
- ✅ **自动编号**：所有报告使用 LaTeX 自动编号
- ✅ **Graphviz 图表**：所有报告使用 Graphviz PDF 图表
- ✅ **左对齐标题**：所有报告标题左对齐
- ✅ **编译成功**：所有六份报告编译成功，无错误
