#!/usr/bin/env bash
set -euo pipefail

# Triage script: OpenSearch + Neo4j quick stats for a running center node.
#
# Usage:
#   OPENSEARCH_PASSWORD='...' NEO4J_PASSWORD='...' ./backend/scripts/triage_remote_state.sh
#
# Optional:
#   CENTER_IP=10.21.251.127 OPENSEARCH_USERNAME=admin NEO4J_USERNAME=neo4j ./backend/scripts/triage_remote_state.sh

CENTER_IP="${CENTER_IP:-10.21.251.127}"

OPENSEARCH_SCHEME="${OPENSEARCH_SCHEME:-https}"
OPENSEARCH_PORT="${OPENSEARCH_PORT:-9200}"
OPENSEARCH_USERNAME="${OPENSEARCH_USERNAME:-admin}"
OPENSEARCH_PASSWORD="${OPENSEARCH_PASSWORD:-}"

NEO4J_SCHEME="${NEO4J_SCHEME:-http}"
NEO4J_PORT="${NEO4J_PORT:-7474}"
NEO4J_USERNAME="${NEO4J_USERNAME:-neo4j}"
NEO4J_PASSWORD="${NEO4J_PASSWORD:-}"
NEO4J_DATABASE="${NEO4J_DATABASE:-neo4j}"

if [[ -z "${OPENSEARCH_PASSWORD}" ]]; then
  echo "ERROR: OPENSEARCH_PASSWORD is required" >&2
  exit 2
fi
if [[ -z "${NEO4J_PASSWORD}" ]]; then
  echo "ERROR: NEO4J_PASSWORD is required" >&2
  exit 2
fi

os() {
  curl -sS -k -u "${OPENSEARCH_USERNAME}:${OPENSEARCH_PASSWORD}" "$@"
}

neo() {
  local statement="$1"
  curl -sS -u "${NEO4J_USERNAME}:${NEO4J_PASSWORD}" \
    -H 'Content-Type: application/json' \
    -d "{\"statement\":$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "${statement}")}" \
    "${NEO4J_SCHEME}://${CENTER_IP}:${NEO4J_PORT}/db/${NEO4J_DATABASE}/query/v2"
}

agg_terms() {
  local index="$1"
  local label="$2"
  local field_primary="$3"
  local field_fallback="$4"
  local size="${5:-50}"

  local payload_primary
  payload_primary="$(printf '{"size":0,"aggs":{"%s":{"terms":{"field":"%s","size":%s}}}}' "${label}" "${field_primary}" "${size}")"
  local resp_primary
  resp_primary="$(os "${OPENSEARCH_SCHEME}://${CENTER_IP}:${OPENSEARCH_PORT}/${index}/_search" -H 'Content-Type: application/json' -d "${payload_primary}")"

  local n_primary
  n_primary="$(printf '%s' "${resp_primary}" | python3 -c 'import json,sys; label=sys.argv[1]; obj=json.load(sys.stdin); buckets=obj.get("aggregations",{}).get(label,{}).get("buckets",[]); print(len(buckets))' "${label}" 2>/dev/null || echo 0)"

  if [[ "${n_primary}" != "0" || -z "${field_fallback}" ]]; then
    printf '%s' "${resp_primary}"
    return 0
  fi

  local payload_fallback
  payload_fallback="$(printf '{"size":0,"aggs":{"%s":{"terms":{"field":"%s","size":%s}}}}' "${label}" "${field_fallback}" "${size}")"
  os "${OPENSEARCH_SCHEME}://${CENTER_IP}:${OPENSEARCH_PORT}/${index}/_search" -H 'Content-Type: application/json' -d "${payload_fallback}"
}

echo "== Center =="
echo "CENTER_IP=${CENTER_IP}"
echo

echo "== OpenSearch: cluster health =="
os "${OPENSEARCH_SCHEME}://${CENTER_IP}:${OPENSEARCH_PORT}/_cluster/health?pretty" | python3 -m json.tool | sed -n '1,60p'
echo

echo "== OpenSearch: indices (top 30 by docs.count) =="
os "${OPENSEARCH_SCHEME}://${CENTER_IP}:${OPENSEARCH_PORT}/_cat/indices?v&s=docs.count:desc" | sed -n '1,31p'
echo

latest_ecs="$(os "${OPENSEARCH_SCHEME}://${CENTER_IP}:${OPENSEARCH_PORT}/_cat/indices/ecs-events-*?h=index&s=index:desc" | head -n 1 | awk '{print $1}')"
latest_raw="$(os "${OPENSEARCH_SCHEME}://${CENTER_IP}:${OPENSEARCH_PORT}/_cat/indices/raw-findings-*?h=index&s=index:desc" | head -n 1 | awk '{print $1}')"
latest_canonical="$(os "${OPENSEARCH_SCHEME}://${CENTER_IP}:${OPENSEARCH_PORT}/_cat/indices/canonical-findings-*?h=index&s=index:desc" | head -n 1 | awk '{print $1}')"

echo "== OpenSearch: latest daily indices =="
echo "ecs-events:      ${latest_ecs:-<none>}"
echo "raw-findings:    ${latest_raw:-<none>}"
echo "canonical-findings: ${latest_canonical:-<none>}"
echo

if [[ -n "${latest_ecs}" ]]; then
  echo "== OpenSearch: ${latest_ecs} datasets =="
  agg_terms "${latest_ecs}" "datasets" "event.dataset.keyword" "event.dataset" 50 \
    | python3 -m json.tool | sed -n '1,200p'
  echo
fi

if [[ -n "${latest_raw}" ]]; then
  echo "== OpenSearch: ${latest_raw} datasets =="
  agg_terms "${latest_raw}" "datasets" "event.dataset.keyword" "event.dataset" 50 \
    | python3 -m json.tool | sed -n '1,240p'
  echo
fi

if [[ -n "${latest_canonical}" ]]; then
  echo "== OpenSearch: ${latest_canonical} providers =="
  agg_terms "${latest_canonical}" "providers" "custom.finding.providers.keyword" "custom.finding.providers" 20 \
    | python3 -m json.tool | sed -n '1,220p'
  echo
fi

echo "== Neo4j: labels =="
neo 'CALL db.labels()' | python3 -m json.tool | sed -n '1,200p'
echo

echo "== Neo4j: node counts by label =="
neo 'MATCH (n) RETURN labels(n) AS labels, count(n) AS c ORDER BY c DESC' | python3 -m json.tool | sed -n '1,220p'
echo

echo "== Neo4j: relationship counts by type =="
neo 'MATCH ()-[r]->() RETURN type(r) AS rel, count(r) AS c ORDER BY c DESC' | python3 -m json.tool | sed -n '1,240p'
echo

echo "== Neo4j: alarm relationship counts (r.is_alarm=true) =="
neo 'MATCH ()-[r]->() WHERE r.is_alarm = true RETURN type(r) AS rel, count(r) AS c ORDER BY c DESC' | python3 -m json.tool | sed -n '1,200p'
echo
