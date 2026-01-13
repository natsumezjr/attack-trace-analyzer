#!/usr/bin/env bash
set -euo pipefail

# Fetch MITRE ATT&CK Enterprise CTI (STIX 2.1) bundle for offline TTP similarity.
#
# Default output:
#   backend/app/services/ttp_similarity/cti/enterprise-attack.json
#
# Optional:
#   - pass a custom output path as $1
#   - or set ATTACK_CTI_PATH to override (same env var used by the backend)
#
# Usage:
#   ./scripts/fetch_attack_cti.sh
#   ./scripts/fetch_attack_cti.sh /path/to/enterprise-attack.json
#   ATTACK_CTI_PATH=/path/to/enterprise-attack.json ./scripts/fetch_attack_cti.sh

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

DEFAULT_OUT="${ROOT_DIR}/backend/app/services/ttp_similarity/cti/enterprise-attack.json"
FORCE=0
if [[ "${1:-}" == "--force" || "${1:-}" == "-f" ]]; then
  FORCE=1
  shift
fi

OUT_PATH="${1:-${ATTACK_CTI_PATH:-${DEFAULT_OUT}}}"

CTI_URL="https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"

if ! command -v curl >/dev/null 2>&1; then
  echo "error: curl not found; please install curl (macOS should include it)" >&2
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
    raise SystemExit(f"error: file is not valid JSON: {e}")

if not isinstance(data, dict) or data.get("type") != "bundle":
    raise SystemExit("error: JSON is not a STIX bundle (type != 'bundle')")

objs = data.get("objects")
if not isinstance(objs, list) or len(objs) < 1000:
    raise SystemExit("error: STIX bundle looks too small; file may be incomplete")
print(f"ok: bundle objects={len(objs)}")
PY
}

if [[ "${FORCE}" -eq 0 && -f "${OUT_PATH}" ]]; then
  echo "Found existing CTI bundle; validating (use --force to re-download)..."
  echo "  OUT: ${OUT_PATH}"
  validate_bundle "${OUT_PATH}"
  exit 0
fi

echo "Fetching Enterprise ATT&CK STIX bundle..."
echo "  URL: ${CTI_URL}"
echo "  OUT: ${OUT_PATH}"

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
echo "Done. (${SIZE_BYTES} bytes)"
