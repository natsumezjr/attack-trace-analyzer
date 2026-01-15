#!/usr/bin/env python3
"""
合并概要设计文档
将 docs/40-概要设计/ 下的所有 Markdown 文档合并为一个总文档
自动规范标题层级：只有一个一级标题，其余为二三四级
"""

import os
import re
from pathlib import Path
from typing import List, Tuple

# 配置
SOURCE_DIR = Path("docs/40-概要设计")
OUTPUT_FILE = Path("概要设计总文档.md")
DESKTOP = Path.home() / "Desktop"

# 定义文件合并顺序和章节映射
FILE_MAPPING = {
    "40-概要设计报告.md": {
        "title": "一、概要设计报告",
        "level": 1
    },
    "41-数据流与时序.md": {
        "title": "二、数据流与时序",
        "level": 1
    },
    "42-网络拓扑与网关规划.md": {
        "title": "三、网络拓扑与网关规划",
        "level": 1
    },
    "43-非功能设计.md": {
        "title": "四、非功能设计",
        "level": 1
    },
}


def extract_content(lines: List[str]) -> Tuple[List[str], int]:
    """
    提取正文内容，去掉元信息部分
    返回：(正文行列表, 原文一级标题数量)
    """
    content_start = False
    content_lines = []
    h1_count = 0

    for line in lines:
        # 跳过元信息部分
        if not content_start:
            if line.startswith("## ") or line.startswith("## "):  # 找到第一个二级标题
                content_start = True
            # 统计一级标题
            if line.startswith("# ") and not line.startswith("## "):
                h1_count += 1
            continue

        content_lines.append(line)

        # 统计正文中的标题
        if line.startswith("# ") and not line.startswith("## "):
            h1_count += 1

    return content_lines, h1_count


def adjust_heading_level(line: str, level_offset: int) -> str:
    """
    调整标题层级
    """
    if not line.startswith("#"):
        return line

    # 计算当前标题级别
    match = re.match(r'^(#{1,6})\s+(.+)$', line)
    if not match:
        return line

    current_level = len(match.group(1))
    content = match.group(2)

    # 计算新级别
    new_level = current_level + level_offset

    # 限制在 1-6 级之间
    if new_level < 1:
        new_level = 1
    elif new_level > 6:
        new_level = 6

    return "#" * new_level + " " + content


def process_file(filepath: Path, config: dict) -> str:
    """
    处理单个文件，返回合并后的内容
    """
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    # 提取正文内容
    content_lines, h1_count = extract_content(lines)

    # 如果原文没有一级标题，不需要降级
    if h1_count <= 1:
        level_offset = 0
    else:
        # 有多个一级标题，需要降级
        level_offset = 1

    # 添加章节标题
    result = []
    result.append(f"\n\n# {config['title']}\n\n")

    # 处理正文内容，调整标题层级
    for line in content_lines:
        adjusted_line = adjust_heading_level(line, level_offset)
        result.append(adjusted_line)

    return "".join(result)


def merge_outline_design():
    """
    合并所有概要设计文档
    """
    print("开始合并概要设计文档...")

    merged_content = []
    merged_content.append("# 攻击溯源分析系统概要设计\n\n")
    merged_content.append("> 本文档由以下文档合并而成：\n\n")

    # 添加文档列表
    for i, (filename, config) in enumerate(FILE_MAPPING.items(), 1):
        filepath = SOURCE_DIR / filename
        if not filepath.exists():
            print(f"警告：文件不存在 {filename}")
            continue

        merged_content.append(f"{i}. [{filename}]({filename})\n")

    merged_content.append("\n---\n\n")

    # 按顺序合并文件
    for filename, config in FILE_MAPPING.items():
        filepath = SOURCE_DIR / filename
        if not filepath.exists():
            continue

        print(f"  正在处理: {filename}")
        file_content = process_file(filepath, config)
        merged_content.append(file_content)

    # 写入输出文件
    output_path = SOURCE_DIR / OUTPUT_FILE
    with open(output_path, 'w', encoding='utf-8') as f:
        f.writelines(merged_content)

    print(f"\n✓ 合并完成: {output_path}")

    # 复制到桌面
    desktop_path = DESKTOP / OUTPUT_FILE
    import shutil
    shutil.copy(output_path, desktop_path)
    print(f"✓ 已复制到桌面: {desktop_path}")

    return output_path


if __name__ == "__main__":
    merge_outline_design()
