# Network Traffic Analysis & Export Module (Suricata)

This module only handles traffic capture/analysis and exports ECS-formatted ndjson via HTTP.
It does not contain any central/server-side logic.

## Quick Start (PCAP Mode)

```bash
docker compose up --build
```

This uses `SURICATA_MODE=pcap` by default in the sample compose file and reads:

```
./data/pcap/sample.pcap
```

After startup, the exporter writes:

- `/data/output/events.db` (SQLite, all events in one table)

on the host at:

- `./data/output/events.db`

## Live Capture Mode

Suricata needs capture privileges inside the container:

- `cap_add: NET_ADMIN, NET_RAW`
- recommended: `network_mode: host` for full interface visibility

Update `docker-compose.yml` for live mode:

```yaml
services:
  suricata:
    environment:
      SURICATA_MODE: live
      SURICATA_IFACE: eth0
    network_mode: host
```

## API

- `GET /healthz`
- `GET /export/networksql`

Each export returns unexported rows from SQLite as `application/x-ndjson` and then
marks them exported on successful completion.

## PCAP Placement

Place pcaps in:

```
./data/pcap
```

Set `SURICATA_MODE=pcap` and `PCAP_FILE=/data/pcap/your.pcap`.

## Data Persistence

All runtime data lives under `./data`, mounted to `/data` in containers:

- `/data/eve.json`
- `/data/output/events.db` (table: `data`)
- `/data/state/offset.json`

## Minimal Demo

1. Start services:

```bash
docker compose up --build
```

2. Wait for database:

```
./data/output/events.db
```

3. Export:

```bash
curl http://localhost:8080/export/raw
curl http://localhost:8080/export/alerts
```

4. Verify rows are marked exported in SQLite (optional).
