#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


HEADING_CMD_RE = re.compile(r"^(\s*)\\(section|subsection|subsubsection)(\*?)\{")
LABEL_RE = re.compile(r"\\label\{")

CHINESE_NUM_PREFIX_RE = re.compile(r"^[一二三四五六七八九十]+[、\.．：:]\s*")
# Examples we want to strip:
# - "1. Title"
# - "2、Title"
# - "3.3 Title"
# - "2.0 Title"
ARABIC_NUM_PREFIX_WITH_PUNCT_RE = re.compile(r"^\d+(?:\.\d+)*[\.、．：:]\s*")
ARABIC_NUM_PREFIX_SPACE_RE = re.compile(r"^\d+(?:\.\d+)*\s+")


def _find_matching_brace(line: str, start_idx: int) -> int | None:
    """Given index after an opening '{', return index of its matching '}'."""
    depth = 1
    for idx in range(start_idx, len(line)):
        ch = line[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return idx
    return None


def _strip_manual_number_prefix(title: str) -> str:
    leading_ws = title[: len(title) - len(title.lstrip())]
    rest = title.lstrip()

    for pattern in (
        CHINESE_NUM_PREFIX_RE,
        ARABIC_NUM_PREFIX_WITH_PUNCT_RE,
        ARABIC_NUM_PREFIX_SPACE_RE,
    ):
        new_rest = pattern.sub("", rest, count=1)
        if new_rest != rest:
            rest = new_rest.lstrip()
            break

    return leading_ws + rest


def _normalize_heading_line(line: str) -> tuple[str, bool]:
    m = HEADING_CMD_RE.match(line)
    if not m:
        return line, False

    open_brace_idx = m.end() - 1  # points at '{'
    content_start = open_brace_idx + 1
    content_end = _find_matching_brace(line, content_start)
    if content_end is None:
        return line, False

    old_title = line[content_start:content_end]
    new_title = _strip_manual_number_prefix(old_title)
    if new_title == old_title:
        return line, False

    new_line = line[:content_start] + new_title + line[content_end:]
    return new_line, True


def _normalize_label_escapes(line: str) -> tuple[str, bool]:
    if "\\label{" not in line or "\\\\x" not in line:
        return line, False

    # Parse each \label{...} occurrence and rewrite only its argument.
    idx = 0
    changed = False
    out = []
    while True:
        pos = line.find(r"\label{", idx)
        if pos == -1:
            out.append(line[idx:])
            break
        out.append(line[idx : pos + len(r"\label{")])
        content_start = pos + len(r"\label{")
        content_end = _find_matching_brace(line, content_start)
        if content_end is None:
            out.append(line[content_start:])
            break
        content = line[content_start:content_end]
        new_content = content.replace(r"\\x", "ux")
        if new_content != content:
            changed = True
        out.append(new_content)
        out.append("}")
        idx = content_end + 1

    return "".join(out), changed


def normalize_tex_file(path: Path, *, apply: bool) -> bool:
    original = path.read_text(encoding="utf-8", errors="strict")
    lines = original.splitlines(keepends=True)

    changed = False
    new_lines: list[str] = []
    for line in lines:
        new_line, c1 = _normalize_heading_line(line)
        new_line, c2 = _normalize_label_escapes(new_line)
        changed = changed or c1 or c2
        new_lines.append(new_line)

    if not changed:
        return False

    if apply:
        path.write_text("".join(new_lines), encoding="utf-8")
    return True


def iter_report_chapter_tex_files(reports_dir: Path) -> list[Path]:
    files: list[Path] = []
    for report_dir in sorted(p for p in reports_dir.iterdir() if p.is_dir()):
        if not (report_dir / "main.tex").exists():
            continue
        chapters_dir = report_dir / "chapters"
        if not chapters_dir.exists():
            continue
        files.extend(sorted(chapters_dir.glob("*.tex")))
    return files


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Normalize LaTeX headings: remove manual numeric prefixes in \\section titles."
    )
    parser.add_argument(
        "--reports-dir",
        type=Path,
        default=Path("reports"),
        help="Path to reports/ directory (default: ./reports).",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Write changes back to files (default: dry run).",
    )
    args = parser.parse_args()

    reports_dir = args.reports_dir
    if not reports_dir.exists():
        print(f"ERROR: reports dir not found: {reports_dir}", file=sys.stderr)
        return 2

    files = iter_report_chapter_tex_files(reports_dir)
    if not files:
        print("No report chapter TeX files found.", file=sys.stderr)
        return 1

    touched = 0
    for path in files:
        if normalize_tex_file(path, apply=args.apply):
            touched += 1
            action = "UPDATED" if args.apply else "WOULD_UPDATE"
            print(f"{action}: {path}")

    if not args.apply:
        print()
        print(f"Dry run complete. {touched} files would be updated.")
        print("Re-run with --apply to write changes.")
    else:
        print()
        print(f"Done. Updated {touched} files.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

