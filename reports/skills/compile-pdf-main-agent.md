# 主 Agent PDF 编译技能

## 职责定义

主 Agent（当前会话）是**唯一**可以执行脚本和编译 PDF 的 Agent。

Subagents 只能读写文件，禁止执行任何脚本或命令。

## 编译权限

### 主 Agent（你）

- ✅ 允许：所有工具和脚本
- ✅ 可以执行 Bash 工具
- ✅ 可以运行编译脚本（`build_all_pdfs.sh`）
- ✅ 可以执行 XeLaTeX 编译

### Subagents

- ❌ 禁止：Bash 工具
- ❌ 禁止：任何脚本执行
- ❌ 禁止：命令行工具
- ✅ 允许：Read、Edit、Write 工具

## 编译流程

### 编译单个报告

```bash
cd reports/<报告目录>
xelatex -interaction=nonstopmode main.tex
xelatex -interaction=nonstopmode main.tex  # 第二遍生成目录
```

### 编译所有报告

```bash
cd reports
bash build_all_pdfs.sh
```

## 依赖检查

### XeLaTeX

```bash
# 检查版本
xelatex --version

# 如果未安装，macOS 使用 MacTeX
brew install --cask mactex
```

### Graphviz（图表生成）

```bash
# 检查版本
dot -V

# 如果未安装
brew install graphviz
```

## 常见问题修复

### 问题 1：breakurl 包兼容性错误

**错误**：
```
! Undefined control sequence.
\burl@condpdflink ...
```

**解决**：在 `main.tex` 中注释掉 breakurl 包：
```latex
% \usepackage{breakurl}  % 与 XeLaTeX + hyperref 不兼容
```

### 问题 2：IP 地址斜杠显示错误

**错误**：
```
! Missing number, treated as zero.
\texttt{10.0.0.0/8}
```

**解决**：使用 `\verb|10.0.0.0/8|` 代替 `\texttt{10.0.0.0/8}`

### 问题 3：图表未显示

**检查**：
1. 确认 `images/*.pdf` 文件存在
2. 检查 .tex 文件中的 `\includegraphics` 路径正确
3. 确认 Graphviz 图表已渲染：
   ```bash
   cd reports/<报告目录>/graphviz
   dot -Tpdf outline-40-01.dot -o ../images/outline-40-01.pdf
   ```

## 编译验证

### 检查 PDF 页数

```bash
cd reports/<报告目录>
pdfinfo main.pdf | grep Pages
```

### 检查 PDF 文件大小

```bash
ls -lh main.pdf
```

### 检查编译日志

```bash
# 查看编译错误
xelatex -interaction=nonstopmode main.tex 2>&1 | grep -A 5 "^!"
```

## 工作流示例

### 场景 1：Subagent 润色后重新编译

1. Subagent 完成润色（使用 Read/Edit/Write）
2. 主 Agent 运行编译脚本：
   ```bash
   cd reports
   bash build_all_pdfs.sh
   ```
3. 检查 PDF 生成结果

### 场景 2：修复编译错误

1. 主 Agent 识别编译错误
2. 主 Agent 直接修改 .tex 文件（或启动 Subagent 润色）
3. 主 Agent 重新编译验证

## 目录清理

编译成功后，可以清理中间文件：

```bash
cd reports/<报告目录>
rm -f *.aux *.log *.out *.toc *.lof *.lot
```

**注意**：不要删除 `.tex` 源文件和 `images/*.pdf` 图表。

---

**关键原则**：
- 只有主 Agent 可以执行编译
- Subagents 只能润色文件，不能运行脚本
- 编译前确保所有依赖已安装
- 编译后验证 PDF 完整性
