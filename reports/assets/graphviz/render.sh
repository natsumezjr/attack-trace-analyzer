#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p images

for dot_file in graphviz/*.dot; do
  base="$(basename "$dot_file" .dot)"
  dot -Tpdf "$dot_file" -o "images/${base}.pdf"
done

echo "OK: rendered Graphviz figures to $ROOT_DIR/images/"

