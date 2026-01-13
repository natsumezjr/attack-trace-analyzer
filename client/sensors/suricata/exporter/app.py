import json
import math
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from flask import Flask, Response, jsonify, stream_with_context

APP_VERSION = "0.1.0"

EVE_FILE = os.getenv("EVE_FILE", "/data/eve.json")
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "/data/output")
STATE_DIR = os.getenv("STATE_DIR", "/data/state")
DB_FILE = os.getenv("DB_FILE", os.path.join(OUTPUT_DIR, "events.db"))

HOST_ID = os.getenv("HOST_ID", "sensor-01")
HOST_NAME = os.getenv("HOST_NAME", "suricata-sensor")
AGENT_NAME = os.getenv("AGENT_NAME", "netflow-exporter")
AGENT_VERSION = os.getenv("AGENT_VERSION", APP_VERSION)

OFFSET_FILE = os.path.join(STATE_DIR, "offset.json")
EXPORT_OFFSET_FILE = os.path.join(STATE_DIR, "export_offset.json")

db_lock = threading.Lock()

app = Flask(__name__)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def normalize_timestamp(ts: Optional[str]) -> str:
    if not ts:
        return now_iso()
    if ts.endswith("+0000"):
        return ts[:-5] + "Z"
    return ts


def ensure_dirs() -> None:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(STATE_DIR, exist_ok=True)
    init_db()


def connect_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    return conn


def init_db() -> None:
    with db_lock:
        conn = connect_db()
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_json TEXT NOT NULL
            )
            """
        )
        conn.commit()
        conn.close()


def load_offset() -> Dict[str, Any]:
    if not os.path.exists(OFFSET_FILE):
        return {"offset": 0, "inode": None}
    try:
        with open(OFFSET_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"offset": 0, "inode": None}


def save_offset(offset: int, inode: Optional[int]) -> None:
    tmp = {"offset": offset, "inode": inode}
    with open(OFFSET_FILE, "w", encoding="utf-8") as f:
        json.dump(tmp, f)


def load_export_offset() -> int:
    if not os.path.exists(EXPORT_OFFSET_FILE):
        return 0
    try:
        with open(EXPORT_OFFSET_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return int(data.get("last_id", 0))
    except Exception:
        return 0


def save_export_offset(last_id: int) -> None:
    tmp = {"last_id": int(last_id)}
    with open(EXPORT_OFFSET_FILE, "w", encoding="utf-8") as f:
        json.dump(tmp, f)


def safe_list_add(items, value):
    if value and value not in items:
        items.append(value)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(s)
    ent = 0.0
    for count in counts.values():
        p = count / total
        ent -= p * math.log2(p)
    return ent


def base_event(event: Dict[str, Any], raw_line: str, kind: str, dataset: str) -> Dict[str, Any]:
    ecs = {
        "ecs.version": "9.2.0",
        "@timestamp": normalize_timestamp(event.get("timestamp")),
        "event.created": now_iso(),
        "event.ingested": now_iso(),
        "event.kind": kind,
        "event.dataset": dataset,
        "host.id": HOST_ID,
        "host.name": HOST_NAME,
        "agent.name": AGENT_NAME,
        "agent.version": AGENT_VERSION,
        "event.original": raw_line.strip(),
    }

    src_ip = event.get("src_ip")
    dst_ip = event.get("dest_ip")
    if src_ip:
        ecs["source.ip"] = src_ip
    if dst_ip:
        ecs["destination.ip"] = dst_ip

    if event.get("src_port") is not None:
        ecs["source.port"] = event.get("src_port")
    if event.get("dest_port") is not None:
        ecs["destination.port"] = event.get("dest_port")

    related_ips = []
    safe_list_add(related_ips, src_ip)
    safe_list_add(related_ips, dst_ip)
    if related_ips:
        ecs["related.ip"] = related_ips

    if event.get("flow_id") is not None:
        ecs["flow.id"] = str(event.get("flow_id"))

    community_id = event.get("community_id")
    if community_id:
        ecs["network.community_id"] = community_id

    proto = event.get("proto")
    if proto:
        ecs["network.transport"] = proto

    return ecs


def map_flow(event: Dict[str, Any], raw_line: str) -> Dict[str, Any]:
    ecs = base_event(event, raw_line, "event", "netflow.flow")
    ecs["event.category"] = ["network"]

    flow = event.get("flow", {})
    if flow.get("end"):
        ecs["event.type"] = ["end"]
        ecs["event.action"] = "flow_end"
    else:
        ecs["event.type"] = ["start"]
        ecs["event.action"] = "flow_start"

    app_proto = event.get("app_proto")
    if app_proto:
        ecs["network.protocol"] = app_proto

    bytes_to_client = flow.get("bytes_toclient") or 0
    bytes_to_server = flow.get("bytes_toserver") or 0
    packets_to_client = flow.get("pkts_toclient") or 0
    packets_to_server = flow.get("pkts_toserver") or 0

    total_bytes = bytes_to_client + bytes_to_server
    total_packets = packets_to_client + packets_to_server

    if total_bytes:
        ecs["network.bytes"] = total_bytes
    if total_packets:
        ecs["network.packets"] = total_packets

    return ecs


def map_dns(event: Dict[str, Any], raw_line: str) -> Dict[str, Any]:
    ecs = base_event(event, raw_line, "event", "netflow.dns")
    ecs["event.category"] = ["network"]
    ecs["event.type"] = ["protocol"]
    ecs["event.action"] = "dns_query"
    ecs["network.protocol"] = "dns"

    dns = event.get("dns", {})
    question = dns.get("rrname") or dns.get("query")
    if question:
        ecs["dns.question.name"] = question
    if dns.get("rrtype"):
        ecs["dns.question.type"] = dns.get("rrtype")
    if dns.get("rcode"):
        ecs["dns.response_code"] = dns.get("rcode")

    return ecs


def map_http(event: Dict[str, Any], raw_line: str) -> Dict[str, Any]:
    ecs = base_event(event, raw_line, "event", "netflow.http")
    ecs["event.category"] = ["network"]
    ecs["event.type"] = ["protocol"]
    ecs["event.action"] = "http_request"
    ecs["network.protocol"] = "http"

    http = event.get("http", {})
    if http.get("http_method"):
        ecs["http.request.method"] = http.get("http_method")

    hostname = http.get("hostname")
    url_path = http.get("url")
    if url_path:
        if url_path.startswith("http://") or url_path.startswith("https://"):
            ecs["url.full"] = url_path
        elif hostname:
            ecs["url.full"] = f"http://{hostname}{url_path}"
    if hostname:
        ecs["url.domain"] = hostname

    if http.get("status") is not None:
        ecs["http.response.status_code"] = http.get("status")

    if http.get("user_agent"):
        ecs["user_agent.original"] = http.get("user_agent")

    return ecs


def map_tls(event: Dict[str, Any], raw_line: str) -> Dict[str, Any]:
    ecs = base_event(event, raw_line, "event", "netflow.tls")
    ecs["event.category"] = ["network"]
    ecs["event.type"] = ["protocol"]
    ecs["event.action"] = "tls_handshake"
    ecs["network.protocol"] = "tls"

    tls = event.get("tls", {})
    if tls.get("sni"):
        ecs["tls.client.server_name"] = tls.get("sni")
    if tls.get("version"):
        ecs["tls.version"] = tls.get("version")
    if tls.get("subject"):
        ecs["tls.server.x509.subject.common_name"] = tls.get("subject")
    if tls.get("issuerdn"):
        ecs["tls.server.x509.issuer.common_name"] = tls.get("issuerdn")

    return ecs


def map_icmp(event: Dict[str, Any], raw_line: str) -> Dict[str, Any]:
    ecs = base_event(event, raw_line, "event", "netflow.icmp")
    ecs["event.category"] = ["network"]
    ecs["event.type"] = ["protocol"]
    ecs["network.transport"] = "icmp"

    icmp = event.get("icmp", {})
    icmp_type = icmp.get("type")
    if icmp_type is not None:
        ecs["icmp.type"] = icmp_type
    if icmp.get("code") is not None:
        ecs["icmp.code"] = icmp.get("code")

    if icmp_type in (0, 8):
        ecs["event.action"] = "icmp_echo"
    else:
        ecs["event.action"] = "icmp_message"

    if icmp.get("payload_size") is not None:
        ecs["custom.icmp.payload_size"] = icmp.get("payload_size")

    return ecs


def map_alert(event: Dict[str, Any], raw_line: str) -> Dict[str, Any]:
    ecs = base_event(event, raw_line, "alert", "netflow.alert")
    ecs["event.category"] = ["network"]
    ecs["event.type"] = ["info"]
    ecs["event.action"] = "suricata_alert"

    alert = event.get("alert", {})
    if alert.get("signature_id") is not None:
        ecs["rule.id"] = str(alert.get("signature_id"))
    if alert.get("signature"):
        ecs["rule.name"] = alert.get("signature")
    ecs["rule.ruleset"] = "suricata"

    severity = alert.get("severity")
    if severity is not None:
        score = max(0, 100 - (int(severity) - 1) * 20)
        ecs["risk.score"] = score

    tags = []
    metadata = alert.get("metadata") or {}
    if isinstance(metadata, dict):
        for key, val in metadata.items():
            if isinstance(val, list):
                for item in val:
                    safe_list_add(tags, str(item))
            elif val:
                safe_list_add(tags, str(val))

        def first_val(value):
            if isinstance(value, list):
                return value[0] if value else None
            return value

        tactic_id = first_val(metadata.get("mitre_tactic_id"))
        tactic_name = first_val(metadata.get("mitre_tactic_name"))
        technique_id = first_val(metadata.get("mitre_technique_id"))
        technique_name = first_val(metadata.get("mitre_technique_name"))
        sub_id = first_val(metadata.get("mitre_subtechnique_id"))

        if tactic_id:
            ecs["threat.framework"] = "MITRE ATT&CK"
            ecs["threat.tactic.id"] = str(tactic_id)
        if tactic_name:
            ecs["threat.tactic.name"] = str(tactic_name)
        if technique_id:
            ecs["threat.technique.id"] = str(technique_id)
        if technique_name:
            ecs["threat.technique.name"] = str(technique_name)
        if sub_id:
            ecs["threat.technique.subtechnique.id"] = str(sub_id)

    if tags:
        ecs["tags"] = tags

    return ecs


def build_dns_tunnel_alert(event: Dict[str, Any], raw_line: str) -> Optional[Dict[str, Any]]:
    dns = event.get("dns", {})
    question = dns.get("rrname") or dns.get("query")
    if not question:
        return None

    length = len(question)
    entropy = shannon_entropy(question)

    if length < 60 and entropy < 4.0:
        return None

    ecs = base_event(event, raw_line, "alert", "netflow.alert")
    ecs["event.category"] = ["network"]
    ecs["event.type"] = ["info"]
    ecs["event.action"] = "dns_tunnel_suspected"
    ecs["rule.id"] = "R-DNS-TUNNEL-HEURISTIC"
    ecs["rule.name"] = "DNS tunnel heuristic"
    ecs["rule.ruleset"] = "local"
    ecs["risk.score"] = 60
    ecs["tags"] = ["attack.t1071.004", "attack.ta0011"]
    ecs["network.protocol"] = "dns"
    ecs["dns.question.name"] = question
    ecs["custom.dns.query_length"] = length
    ecs["custom.dns.entropy"] = round(entropy, 3)
    return ecs


def insert_event(payload: Dict[str, Any]) -> None:
    line = json.dumps(payload, ensure_ascii=True)
    with db_lock:
        conn = connect_db()
        conn.execute(
            "INSERT INTO data (event_json) VALUES (?)",
            (
                line,
            ),
        )
        conn.commit()
        conn.close()


def process_event(event: Dict[str, Any], raw_line: str) -> None:
    etype = event.get("event_type")
    if etype == "flow":
        insert_event(map_flow(event, raw_line))
    elif etype == "dns":
        insert_event(map_dns(event, raw_line))
        alert = build_dns_tunnel_alert(event, raw_line)
        if alert:
            insert_event(alert)
    elif etype == "http":
        insert_event(map_http(event, raw_line))
    elif etype == "tls":
        insert_event(map_tls(event, raw_line))
    elif etype == "icmp":
        insert_event(map_icmp(event, raw_line))
    elif etype == "alert":
        insert_event(map_alert(event, raw_line))


def tail_eve() -> None:
    ensure_dirs()
    state = load_offset()
    offset = int(state.get("offset", 0))
    inode = state.get("inode")

    while True:
        try:
            if not os.path.exists(EVE_FILE):
                time.sleep(0.5)
                continue

            stat = os.stat(EVE_FILE)
            if inode and inode != stat.st_ino:
                offset = 0
            inode = stat.st_ino

            with open(EVE_FILE, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(offset)
                while True:
                    line = f.readline()
                    if not line:
                        offset = f.tell()
                        save_offset(offset, inode)
                        time.sleep(0.2)
                        if os.stat(EVE_FILE).st_size < offset:
                            offset = 0
                        break

                    raw_line = line
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    process_event(event, raw_line)
        except Exception:
            time.sleep(0.5)


def stream_events() -> Response:
    ensure_dirs()
    status = {"ok": False}
    lines = []
    max_id = 0

    with db_lock:
        conn = connect_db()
        last_id = load_export_offset()
        rows = conn.execute(
            "SELECT id, event_json FROM data WHERE id > ? ORDER BY id",
            (last_id,),
        ).fetchall()
        conn.close()

    for row_id, payload in rows:
        lines.append(payload.encode("utf-8") + b"\n")
        if row_id > max_id:
            max_id = row_id

    def generate():
        for chunk in lines:
            yield chunk
        status["ok"] = True

    resp = Response(stream_with_context(generate()), mimetype="application/x-ndjson")

    @resp.call_on_close
    def _mark_exported():
        if not status["ok"] or max_id == 0:
            return
        save_export_offset(max_id)

    return resp


def start_tail_thread() -> None:
    thread = threading.Thread(target=tail_eve, daemon=True)
    thread.start()


@app.get("/healthz")
def healthz():
    return jsonify({"status": "ok", "version": APP_VERSION})


@app.get("/export/networksql")
def export_networksql():
    return stream_events()


start_tail_thread()

if __name__ == "__main__":
    ensure_dirs()
    start_tail_thread()
    app.run(host="0.0.0.0", port=8080)
