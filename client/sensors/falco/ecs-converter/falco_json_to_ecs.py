#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import os
import sqlite3
import sys
import time
from datetime import datetime, timezone
from typing import Dict, Optional

TABLE_NAME = os.getenv("TABLE_NAME", "falco")

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
    return ts


def to_int(x):
    try:
        return int(x)
    except Exception:
        return None


def priority_rank(priority: str) -> int:
    return PRIORITY_RANK.get((priority or "").upper(), 99)


def is_abnormal(priority: str, threshold: str) -> bool:
    return priority_rank(priority) >= priority_rank(threshold)


def falco_to_ecs(evt: Dict, abnormal: bool) -> Dict:
    out_fields = evt.get("output_fields") or {}
    ecs: Dict = {}

    ecs["@timestamp"] = iso_utc(evt.get("time")) or datetime.now(timezone.utc).isoformat()
    ecs["ecs"] = {"version": "8.11.0"}
    ecs.setdefault("event", {})["dataset"] = "falco"

    rule = evt.get("rule")
    if rule:
        ecs.setdefault("rule", {})["name"] = rule

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
        "--sqlite",
        help="SQLite DB file path to store ECS events.",
    )
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
        help="Clear output files and sqlite db on startup.",
    )
    parser.add_argument(
        "--no-json",
        action="store_true",
        help="Skip writing JSONL files; only write to sqlite.",
    )
    return parser.parse_args()


def init_db(db_path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA busy_timeout=30000;")
    conn.execute(
        f"""
        CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_json TEXT
        )
        """
    )
    conn.commit()
    return conn


def insert_event(conn: sqlite3.Connection, ecs: Dict):
    payload = (json.dumps(ecs, ensure_ascii=False),)
    for _ in range(5):
        try:
            conn.execute(
                f"""
                INSERT INTO {TABLE_NAME} (event_json)
                VALUES (?)
                """,
                payload,
            )
            return
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).lower():
                raise
            time.sleep(0.2)
    raise sqlite3.OperationalError("database is locked")


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

    if args.no_json:
        if not args.sqlite:
            print("--no-json requires --sqlite", file=sys.stderr)
            sys.exit(2)
    else:
        if not args.normal or not args.abnormal:
            print("--normal and --abnormal are required unless --no-json is set", file=sys.stderr)
            sys.exit(2)
        os.makedirs(os.path.dirname(args.normal) or ".", exist_ok=True)
        os.makedirs(os.path.dirname(args.abnormal) or ".", exist_ok=True)

    if args.reset:
        if args.input:
            try:
                os.remove(args.input)
            except FileNotFoundError:
                pass
        if not args.no_json:
            for path in (args.normal, args.abnormal):
                try:
                    os.remove(path)
                except FileNotFoundError:
                    pass
        if args.sqlite:
            for suffix in ("", "-wal", "-shm"):
                try:
                    os.remove(args.sqlite + suffix)
                except FileNotFoundError:
                    pass

    conn = init_db(args.sqlite) if args.sqlite else None
    pending = 0
    last_commit = time.monotonic()
    if args.no_json:
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
            if conn:
                insert_event(conn, ecs)
                pending += 1
                if pending >= 100 or (time.monotonic() - last_commit) >= 2:
                    conn.commit()
                    pending = 0
                    last_commit = time.monotonic()
    else:
        with open(args.normal, "a", encoding="utf-8") as normal_f, open(
            args.abnormal, "a", encoding="utf-8"
        ) as abnormal_f:
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
                out_f = abnormal_f if abnormal else normal_f
                out_f.write(json.dumps(ecs, ensure_ascii=False) + "\n")
                out_f.flush()
                if conn:
                    insert_event(conn, ecs)
                    pending += 1
                    if pending >= 100 or (time.monotonic() - last_commit) >= 2:
                        conn.commit()
                        pending = 0
                        last_commit = time.monotonic()

    if conn:
        conn.commit()
        conn.close()


if __name__ == "__main__":
    main()


