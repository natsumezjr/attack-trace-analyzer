#!/usr/bin/env python3
"""
合并详细设计文档
将 docs/50-详细设计/ 下的所有 Markdown 文档合并为一个总文档
自动规范标题层级：只有一个一级标题，其余为二三四级
"""

import os
import re
from pathlib import Path
from typing import List, Tuple

# 配置
SOURCE_DIR = Path("docs/50-详细设计")
OUTPUT_FILE = Path("详细设计总文档.md")
DESKTOP = Path.home() / "Desktop"

# 定义文件合并顺序和章节映射
# 格式: "子目录/文件名": {"title": "章节标题", "level": 基础层级}
FILE_MAPPING = {
    # 客户机模块
    "客户机/50-总体.md": {
        "title": "二、客户机模块",
        "section": "客户机",
        "level": 1
    },
    "客户机/51-Falco采集与ECS转换.md": {
        "title": "2.1 Falco 采集与 ECS 转换",
        "level": 2
    },
    "客户机/52-Suricata采集与ECS转换.md": {
        "title": "2.2 Suricata 采集与 ECS 转换",
        "level": 2
    },
    "客户机/53-Filebeat采集与ECS转换.md": {
        "title": "2.3 Filebeat 采集与 ECS 转换",
        "level": 2
    },
    "客户机/54-RabbitMQ缓冲与队列语义.md": {
        "title": "2.4 RabbitMQ 缓冲与队列语义",
        "level": 2
    },

    # 中心机模块
    "中心机/60-总体与代码结构.md": {
        "title": "三、中心机模块",
        "section": "中心机",
        "level": 1
    },
    "中心机/61-注册与轮询.md": {
        "title": "3.1 注册与轮询",
        "level": 2
    },
    "中心机/62-OpenSearch存储与索引治理.md": {
        "title": "3.2 OpenSearch 存储与索引治理",
        "level": 2
    },
    "中心机/63-检测与告警融合.md": {
        "title": "3.3 检测与告警融合",
        "level": 2
    },
    "中心机/64-Neo4j入图与图查询.md": {
        "title": "3.4 Neo4j 入图与图查询",
        "level": 2
    },
    "中心机/65-图谱回标与边属性.md": {
        "title": "3.5 图谱回标与边属性",
        "level": 2
    },

    # 分析模块
    "分析/70-任务模型与状态机.md": {
        "title": "四、分析模块",
        "section": "分析",
        "level": 1
    },
    "分析/71-候选路径构造与评分.md": {
        "title": "4.1 候选路径构造与评分",
        "level": 2
    },
    "分析/72-LLM选择器与回退机制.md": {
        "title": "4.2 LLM 选择器与回退机制",
        "level": 2
    },
    "分析/73-TTP相似度匹配.md": {
        "title": "4.3 TTP 相似度匹配",
        "level": 2
    },

    # 前端模块
    "前端/74-总体与页面结构.md": {
        "title": "五、前端模块",
        "section": "前端",
        "level": 1
    },
    "前端/75-图谱可视化与交互.md": {
        "title": "5.1 图谱可视化与交互",
        "level": 2
    },
    "前端/76-报告导出.md": {
        "title": "5.2 报告导出",
        "level": 2
    },
}


def extract_content(lines: List[str]) -> List[str]:
    """
    提取正文内容，去掉元信息部分
    """
    content_lines = []
    content_start = False
    metadata_sections = ["文档目的", "读者对象", "引用关系"]

    for line in lines:
        # 跳过元信息部分
        if not content_start:
            # 检查是否还在元信息部分
            is_metadata = any(section in line for section in metadata_sections)
            if is_metadata:
                continue
            # 找到第一个真正的章节标题（通常是 "## 1." 或 "## 1." 之类的）
            if re.match(r'^##\s+\d+\.', line) or re.match(r'^##\s+[一二三四五六七八九十]、', line):
                content_start = True
            elif line.startswith("## ") and not is_metadata:
                content_start = True
            else:
                continue

        content_lines.append(line)

    return content_lines


def adjust_heading_level(line: str, base_level: int) -> str:
    """
    调整标题层级到指定的基础层级
    base_level: 该文件的基础层级（1表示一级标题开始）
    """
    if not line.startswith("#"):
        return line

    # 计算当前标题级别
    match = re.match(r'^(#{1,6})\s+(.+)$', line)
    if not match:
        return line

    current_level = len(match.group(1))
    content = match.group(2)

    # 如果是数字编号的标题（如 "## 1. xxx"），需要保留编号
    # 我们将其转换为对应的层级
    if re.match(r'^\d+\.', content):
        # 保持原有编号，只调整层级
        new_level = base_level
    elif re.match(r'^[一二三四五六七八九十]、', content):
        # 中文编号
        new_level = base_level
    else:
        # 普通标题，需要降级
        if current_level == 1:
            new_level = base_level
        else:
            new_level = current_level + (base_level - 1)

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
    content_lines = extract_content(lines)

    # 添加章节标题
    result = []
    title = config.get('title', '')
    base_level = config.get('level', 1)

    # 如果是一级标题章节（模块标题），添加分隔线
    if base_level == 1:
        result.append("\n\n---\n\n")
        result.append(f"# {title}\n\n")
    else:
        result.append(f"\n## {title}\n\n")

    # 处理正文内容，调整标题层级
    for line in content_lines:
        adjusted_line = adjust_heading_level(line, base_level)
        result.append(adjusted_line)

    return "".join(result)


def merge_detailed_design():
    """
    合并所有详细设计文档
    """
    print("开始合并详细设计文档...")

    merged_content = []
    merged_content.append("# 攻击溯源分析系统详细设计\n\n")
    merged_content.append("> 本文档由以下文档合并而成：\n\n")

    # 按模块组织文档列表
    sections = {
        "客户机": [],
        "中心机": [],
        "分析": [],
        "前端": []
    }

    for rel_path, config in FILE_MAPPING.items():
        section = config.get('section', '')
        if section:
            sections[section].append(rel_path)

    # 添加文档列表
    for section_name, files in sections.items():
        if not files:
            continue
        merged_content.append(f"### {section_name}模块\n\n")
        for filepath in files:
            filename = Path(filepath).name
            merged_content.append(f"- [{filename}]({filepath})\n")
        merged_content.append("\n")

    merged_content.append("---\n\n")

    # 按顺序合并文件
    for rel_path, config in FILE_MAPPING.items():
        filepath = SOURCE_DIR / rel_path
        if not filepath.exists():
            print(f"警告：文件不存在 {rel_path}")
            continue

        print(f"  正在处理: {rel_path}")
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
    merge_detailed_design()
