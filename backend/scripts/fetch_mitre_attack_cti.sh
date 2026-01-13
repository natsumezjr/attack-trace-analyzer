#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# MITRE ATT&CK CTI 数据下载脚本
# ============================================================================
#
# 功能说明：
#   从 MITRE ATT&CK 官方仓库下载 Enterprise CTI (STIX 2.1) 数据包，
#   用于离线 TTP (Tactics, Techniques, and Procedures) 相似度分析。
#
# 使用场景：
#   - 初始化 TTP 相似度分析服务的数据源
#   - 更新 MITRE ATT&CK 数据到最新版本
#   - 离线环境部署时预先下载数据
#
# 默认输出路径：
#   backend/app/services/ttp_similarity/cti/enterprise-attack.json
#
# 自定义输出：
#   - 方式1：命令行参数传递路径
#     ./backend/scripts/fetch_mitre_attack_cti.sh /custom/path/enterprise-attack.json
#
#   - 方式2：环境变量 ATTACK_CTI_PATH（与后端服务共用）
#     ATTACK_CTI_PATH=/custom/path/enterprise-attack.json ./backend/scripts/fetch_mitre_attack_cti.sh
#
# 强制重新下载：
#   使用 --force 或 -f 参数强制重新下载，忽略已存在的文件
#   ./backend/scripts/fetch_mitre_attack_cti.sh --force
#
# 数据验证：
#   脚本会自动验证下载的文件：
#   - 检查是否为有效的 JSON 格式
#   - 验证是否为 STIX bundle 类型
#   - 检查 objects 数量（应 >= 1000）
#
# 依赖要求：
#   - curl：用于下载文件（macOS 自带）
#   - python3：用于验证 JSON 文件
#
# 使用示例：
#   # 1. 基本用法（使用默认路径）
#   cd backend
#   ./scripts/fetch_mitre_attack_cti.sh
#
#   # 2. 强制重新下载
#   ./scripts/fetch_mitre_attack_cti.sh --force
#
#   # 3. 自定义输出路径
#   ./scripts/fetch_mitre_attack_cti.sh /tmp/enterprise-attack.json
#
#   # 4. 使用环境变量
#   ATTACK_CTI_PATH=/custom/path/enterprise-attack.json ./scripts/fetch_mitre_attack_cti.sh
#
# 数据来源：
#   MITRE ATT&CK STIX Data Repository
#   URL: https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
#
# 相关文件：
#   - backend/app/services/ttp_similarity/service.py: TTP 相似度分析服务
#   - backend/app/services/ttp_similarity/cti/: CTI 数据存储目录
#
# ============================================================================

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

DEFAULT_OUT="${ROOT_DIR}/app/services/ttp_similarity/cti/enterprise-attack.json"
FORCE=0
if [[ "${1:-}" == "--force" || "${1:-}" == "-f" ]]; then
  FORCE=1
  shift
fi

OUT_PATH="${1:-${ATTACK_CTI_PATH:-${DEFAULT_OUT}}"

CTI_URL="https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"

if ! command -v curl >/dev/null 2>&1; then
  echo "错误: 未找到 curl 命令；请安装 curl（macOS 应该自带）" >&2
  exit 1
fi

OUT_DIR="$(dirname "${OUT_PATH}")"
mkdir -p "${OUT_DIR}"

TMP_PATH="${OUT_PATH}.tmp"

validate_bundle() {
  python3 - <<'PY' "$1"
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
try:
    data = json.loads(path.read_text(encoding="utf-8"))
except Exception as e:
    raise SystemExit(f"错误: 文件不是有效的 JSON 格式: {e}")

if not isinstance(data, dict) or data.get("type") != "bundle":
    raise SystemExit("错误: JSON 不是 STIX bundle 格式（type != 'bundle'）")

objs = data.get("objects")
if not isinstance(objs, list) or len(objs) < 1000:
    raise SystemExit("错误: STIX bundle 看起来太小；文件可能不完整")
print(f"验证通过: bundle objects={len(objs)}")
PY
}

if [[ "${FORCE}" -eq 0 && -f "${OUT_PATH}" ]]; then
  echo "发现已存在的 CTI bundle；正在验证（使用 --force 强制重新下载）..."
  echo "  输出: ${OUT_PATH}"
  validate_bundle "${OUT_PATH}"
  exit 0
fi

echo "正在下载 Enterprise ATT&CK STIX bundle..."
echo "  URL: ${CTI_URL}"
echo "  输出: ${OUT_PATH}"

curl -L \
  --fail \
  --show-error \
  --progress-bar \
  --retry 3 \
  --retry-delay 2 \
  -o "${TMP_PATH}" \
  "${CTI_URL}"

validate_bundle "${TMP_PATH}"

mv -f "${TMP_PATH}" "${OUT_PATH}"

SIZE_BYTES="$(stat -f "%z" "${OUT_PATH}" 2>/dev/null || wc -c <"${OUT_PATH}")"
echo "完成. (${SIZE_BYTES} bytes)"
