#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

RABBITMQ_URL = os.getenv("RABBITMQ_URL", "amqp://guest:guest@rabbitmq:5672/")
QUEUE_NAME = os.getenv("RABBITMQ_QUEUE", "data.falco")

PRIORITY_RANK = {
    "DEBUG": 1,
    "INFORMATIONAL": 2,
    "NOTICE": 3,
    "WARNING": 4,
    "ERROR": 5,
    "CRITICAL": 6,
    "ALERT": 7,
    "EMERGENCY": 8,
}

PRIORITY_SEVERITY = {
    "EMERGENCY": 10,
    "ALERT": 9,
    "CRITICAL": 8,
    "ERROR": 6,
    "WARNING": 4,
    "NOTICE": 3,
    "INFORMATIONAL": 2,
    "DEBUG": 1,
}


def iso_utc(ts: Optional[str]) -> Optional[str]:
    if not ts:
        return None
    s = ts.strip()
    if not s:
        return None
    return s.replace("+00:00", "Z")


def to_int(x):
    try:
        return int(x)
    except Exception:
        return None


def priority_rank(priority: str) -> int:
    return PRIORITY_RANK.get((priority or "").upper(), 99)


def is_abnormal(priority: str, threshold: str) -> bool:
    return priority_rank(priority) >= priority_rank(threshold)


def parse_tags(tags_val):
    if tags_val is None:
        return []
    if isinstance(tags_val, list):
        return [str(t).strip() for t in tags_val if str(t).strip()]
    if isinstance(tags_val, str):
        raw = tags_val.replace(",", " ").split()
        return [t.strip() for t in raw if t.strip()]
    return [str(tags_val).strip()]


def parse_tag_kv(tag: str):
    if "=" in tag:
        key, val = tag.split("=", 1)
        return key.strip(), val.strip()
    if ":" in tag:
        key, val = tag.split(":", 1)
        return key.strip(), val.strip()
    return tag.strip(), ""


def extract_attack_from_tags(tags, attack_map: Dict):
    tactic_id = tactic_name = technique_id = technique_name = None
    for tag in tags:
        key, val = parse_tag_kv(tag)
        mapped = attack_map.get(tag) or attack_map.get(key)
        if isinstance(mapped, dict):
            tactic_id = mapped.get("tactic_id") or tactic_id
            tactic_name = mapped.get("tactic_name") or tactic_name
            technique_id = mapped.get("technique_id") or technique_id
            technique_name = mapped.get("technique_name") or technique_name

        if key in ("threat.tactic.id", "mitre.tactic.id", "attack.tactic.id", "tactic.id"):
            tactic_id = val or tactic_id
        if key in ("threat.tactic.name", "mitre.tactic.name", "attack.tactic", "tactic.name"):
            tactic_name = val or tactic_name
        if key in ("threat.technique.id", "mitre.technique.id", "attack.technique.id", "technique.id"):
            technique_id = val or technique_id
        if key in ("threat.technique.name", "mitre.technique.name", "attack.technique", "technique.name"):
            technique_name = val or technique_name

    return tactic_id, tactic_name, technique_id, technique_name


def falco_to_ecs(evt: Dict, abnormal: bool) -> Dict:
    out_fields = evt.get("output_fields") or {}
    ecs: Dict = {}

    ecs["@timestamp"] = (
        iso_utc(evt.get("time"))
        or datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    )
    ecs["ecs"] = {"version": "8.11.0"}
    ecs.setdefault("event", {})["dataset"] = "falco"

    rule = evt.get("rule")
    if rule:
        ecs.setdefault("rule", {})["name"] = rule
    # 如果存在规则到 ATT&CK 的本地映射，则优先使用它来填充 `threat.*`
    mapped = None
    rule_map = {}
    try:
        RULE_MAP_PATH = Path(__file__).parent / "rule_to_attack.json"
        if RULE_MAP_PATH.exists():
            with open(RULE_MAP_PATH, "r", encoding="utf-8") as _f:
                rule_map = json.load(_f) or {}
            mapped = rule_map.get(rule)
    except Exception:
        mapped = None
        rule_map = {}

    output = evt.get("output")
    if output:
        ecs["message"] = output

    host = out_fields.get("host.name") or out_fields.get("hostname") or evt.get("hostname")
    if host:
        ecs.setdefault("host", {})["name"] = host

    user = out_fields.get("user.name") or out_fields.get("user") or out_fields.get("user.name_raw")
    if user:
        ecs.setdefault("user", {})["name"] = user

    proc_name = out_fields.get("proc.name") or out_fields.get("process.name")
    if proc_name:
        ecs.setdefault("process", {})["name"] = proc_name

    pid = out_fields.get("proc.pid") or out_fields.get("process.pid")
    ppid = out_fields.get("proc.ppid") or out_fields.get("process.ppid")
    if pid is not None:
        ecs.setdefault("process", {})["pid"] = to_int(pid)
    if ppid is not None:
        ecs.setdefault("process", {})["parent"] = {"pid": to_int(ppid)}

    fd_name = out_fields.get("fd.name") or out_fields.get("file") or out_fields.get("file.path")
    if fd_name:
        ecs.setdefault("file", {})["path"] = fd_name

    evt_type = out_fields.get("evt.type") or out_fields.get("event.action")
    if evt_type:
        ecs.setdefault("event", {})["action"] = evt_type

    src_ip = out_fields.get("fd.sip") or out_fields.get("source.ip")
    src_port = out_fields.get("fd.sport") or out_fields.get("source.port")
    dst_ip = out_fields.get("fd.dip") or out_fields.get("destination.ip")
    dst_port = out_fields.get("fd.dport") or out_fields.get("destination.port")
    if src_ip:
        ecs.setdefault("source", {})["ip"] = src_ip
    if src_port:
        ecs.setdefault("source", {})["port"] = to_int(src_port)
    if dst_ip:
        ecs.setdefault("destination", {})["ip"] = dst_ip
    if dst_port:
        ecs.setdefault("destination", {})["port"] = to_int(dst_port)

    container_id = out_fields.get("container.id") or out_fields.get("container.id_raw")
    container_name = out_fields.get("container.name")
    if container_id or container_name:
        container = ecs.setdefault("container", {})
        if container_id:
            container["id"] = container_id
        if container_name:
            container["name"] = container_name

    k8s_ns = out_fields.get("k8s.ns.name")
    k8s_pod = out_fields.get("k8s.pod.name")
    if k8s_ns or k8s_pod:
        k8s = ecs.setdefault("kubernetes", {})
        if k8s_ns:
            k8s.setdefault("namespace", {})["name"] = k8s_ns
        if k8s_pod:
            k8s.setdefault("pod", {})["name"] = k8s_pod

    pri = (evt.get("priority") or "").upper()
    if pri:
        ecs.setdefault("event", {})["severity"] = PRIORITY_SEVERITY.get(pri, 3)
        ecs.setdefault("event", {})["risk_score"] = PRIORITY_SEVERITY.get(pri, 3) * 10

    if abnormal:
        ecs.setdefault("event", {})["kind"] = "alert"
        ecs.setdefault("event", {})["category"] = ["intrusion_detection"]
    else:
        ecs.setdefault("event", {})["kind"] = "event"
        ecs.setdefault("event", {})["category"] = ["host"]

    # Minimal ATT&CK enrichment: 填充 `threat.*` 字段。
    # 优先从 Falco 的 output_fields 中获取已有的 ATT&CK 信息，否则使用默认值。
    tactic_id = (
        out_fields.get("threat.tactic.id")
        or out_fields.get("mitre.tactic.id")
        or out_fields.get("attack.tactic.id")
        or out_fields.get("tactic.id")
    )
    tactic_name = (
        out_fields.get("threat.tactic.name")
        or out_fields.get("mitre.tactic.name")
        or out_fields.get("attack.tactic")
        or out_fields.get("tactic.name")
    )
    technique_id = (
        out_fields.get("threat.technique.id")
        or out_fields.get("mitre.technique.id")
        or out_fields.get("attack.technique.id")
        or out_fields.get("technique.id")
    )
    technique_name = (
        out_fields.get("threat.technique.name")
        or out_fields.get("mitre.technique.name")
        or out_fields.get("attack.technique")
        or out_fields.get("technique.name")
    )

    tags = parse_tags(evt.get("tags") or out_fields.get("tags"))
    if tags:
        t_id, t_name, te_id, te_name = extract_attack_from_tags(tags, rule_map)
        tactic_id = tactic_id or t_id
        tactic_name = tactic_name or t_name
        technique_id = technique_id or te_id
        technique_name = technique_name or te_name

    # 如果通过规则映射命中，则覆盖对应字段
    if mapped:
        try:
            tactic_id = mapped.get("tactic_id") or tactic_id
            tactic_name = mapped.get("tactic_name") or tactic_name
            technique_id = mapped.get("technique_id") or technique_id
            technique_name = mapped.get("technique_name") or technique_name
        except Exception:
            pass

    threat = ecs.setdefault("threat", {})
    threat["framework"] = "MITRE ATT&CK"
    threat.setdefault("tactic", {})["id"] = tactic_id or "TA0000"
    threat.setdefault("tactic", {})["name"] = tactic_name or "Unknown"
    threat.setdefault("technique", {})["id"] = technique_id or "T0000"
    threat.setdefault("technique", {})["name"] = technique_name or "Unknown"

    ecs["falco"] = evt
    return ecs


def read_lines_follow(path: str):
    while not os.path.exists(path):
        time.sleep(0.5)
    with open(path, "r", encoding="utf-8") as f:
        while True:
            line = f.readline()
            if line:
                yield line
                continue
            time.sleep(0.2)
            try:
                if os.path.getsize(path) < f.tell():
                    f.seek(0)
            except FileNotFoundError:
                break


def read_lines_once(path: str):
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            yield line


def parse_args():
    parser = argparse.ArgumentParser(description="Convert Falco JSON lines to ECS JSON lines.")
    parser.add_argument("--input", help="Input JSONL file (Falco output). If omitted, read stdin.")
    parser.add_argument("--normal", help="Output JSONL for normal behavior.")
    parser.add_argument("--abnormal", help="Output JSONL for abnormal behavior.")
    parser.add_argument(
        "--abnormal-priority",
        default="WARNING",
        help="Priority threshold treated as abnormal (default: WARNING).",
    )
    parser.add_argument(
        "--follow",
        action="store_true",
        help="Follow input file like tail -f (only valid with --input).",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Clear output files on startup.",
    )
    parser.add_argument(
        "--amqp-url",
        default=RABBITMQ_URL,
        help="RabbitMQ URL (default: env RABBITMQ_URL).",
    )
    parser.add_argument(
        "--queue",
        default=QUEUE_NAME,
        help="RabbitMQ queue name (default: env RABBITMQ_QUEUE).",
    )
    return parser.parse_args()

def build_publisher(amqp_url: str, queue_name: str):
    try:
        import pika
    except ImportError:
        print("Missing dependency: pika. Install it in the container.", file=sys.stderr)
        sys.exit(2)

    def _connect():
        params = pika.URLParameters(amqp_url)
        backoff = 1.0
        while True:
            try:
                connection = pika.BlockingConnection(params)
                channel = connection.channel()
                channel.queue_declare(queue=queue_name, durable=True)
                return connection, channel
            except Exception as exc:
                print(f"RabbitMQ connect failed: {exc}. retry in {backoff:.1f}s", file=sys.stderr)
                time.sleep(backoff)
                if backoff < 10:
                    backoff *= 2

    connection, channel = _connect()

    def publish(payload: Dict):
        nonlocal connection, channel
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        try:
            if connection.is_closed or channel.is_closed:
                connection, channel = _connect()
            channel.basic_publish(
                exchange="",
                routing_key=queue_name,
                body=body,
                properties=pika.BasicProperties(delivery_mode=2),
            )
        except Exception:
            connection, channel = _connect()
            channel.basic_publish(
                exchange="",
                routing_key=queue_name,
                body=body,
                properties=pika.BasicProperties(delivery_mode=2),
            )

    return publish


def main():
    args = parse_args()
    threshold = args.abnormal_priority.upper()

    if args.follow and not args.input:
        print("--follow requires --input", file=sys.stderr)
        sys.exit(2)

    if args.input:
        line_iter = read_lines_follow(args.input) if args.follow else read_lines_once(args.input)
    else:
        line_iter = sys.stdin

    if args.normal:
        os.makedirs(os.path.dirname(args.normal) or ".", exist_ok=True)
    if args.abnormal:
        os.makedirs(os.path.dirname(args.abnormal) or ".", exist_ok=True)

    if args.reset:
        if args.input:
            try:
                os.remove(args.input)
            except FileNotFoundError:
                pass
        for path in (args.normal, args.abnormal):
            if not path:
                continue
            try:
                os.remove(path)
            except FileNotFoundError:
                pass

    publish = build_publisher(args.amqp_url, args.queue)

    normal_f = open(args.normal, "a", encoding="utf-8") if args.normal else None
    abnormal_f = open(args.abnormal, "a", encoding="utf-8") if args.abnormal else None
    try:
        for line in line_iter:
            line = line.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                continue

            abnormal = is_abnormal(evt.get("priority", ""), threshold)
            ecs = falco_to_ecs(evt, abnormal)
            publish(ecs)

            out_f = abnormal_f if abnormal else normal_f
            if out_f:
                out_f.write(json.dumps(ecs, ensure_ascii=False) + "\n")
                out_f.flush()
    finally:
        if normal_f:
            normal_f.close()
        if abnormal_f:
            abnormal_f.close()


if __name__ == "__main__":
    main()

