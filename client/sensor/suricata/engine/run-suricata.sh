#!/bin/sh
set -e

MODE=${SURICATA_MODE:-live}

if [ "$MODE" = "pcap" ]; then
  PCAP=${PCAP_FILE:-/data/pcap/sample.pcap}
  exec suricata -c /etc/suricata/suricata.yaml -r "$PCAP"
fi

iface_exists() {
  [ -n "$1" ] && [ -d "/sys/class/net/$1" ]
}

detect_default_route_iface() {
  if [ ! -r /proc/net/route ]; then
    return 1
  fi

  # /proc/net/route format:
  # Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
  awk '$2 == "00000000" {print $1; exit}' /proc/net/route
}

detect_first_non_loopback_iface() {
  if [ ! -d /sys/class/net ]; then
    return 1
  fi

  for iface in $(ls /sys/class/net 2>/dev/null); do
    [ "$iface" = "lo" ] && continue
    echo "$iface"
    return 0
  done

  return 1
}

resolve_iface() {
  # Prefer documented env var name; keep legacy fallback for compatibility.
  requested_iface=${SURICATA_INTERFACE:-${SURICATA_IFACE:-}}

  # Allow explicit "auto" (or empty) to trigger detection.
  if [ -z "$requested_iface" ] || [ "$requested_iface" = "auto" ]; then
    requested_iface=""
  fi

  if iface_exists "$requested_iface"; then
    echo "$requested_iface"
    return 0
  fi

  if [ -n "$requested_iface" ]; then
    echo "WARN: interface '$requested_iface' not found; auto-detecting capture interface" >&2
  fi

  default_iface=$(detect_default_route_iface 2>/dev/null || true)
  if [ -n "$default_iface" ] && [ "$default_iface" != "lo" ] && iface_exists "$default_iface"; then
    echo "$default_iface"
    return 0
  fi

  if iface_exists "eth0"; then
    echo "eth0"
    return 0
  fi

  first_iface=$(detect_first_non_loopback_iface 2>/dev/null || true)
  if iface_exists "$first_iface"; then
    echo "$first_iface"
    return 0
  fi

  return 1
}

IFACE=$(resolve_iface)
if [ -z "$IFACE" ]; then
  echo "ERROR: no usable network interface found (available: $(ls /sys/class/net 2>/dev/null | tr '\n' ' '))" >&2
  exit 1
fi
echo "INFO: Suricata capture interface: $IFACE" >&2
exec suricata -c /etc/suricata/suricata.yaml -i "$IFACE"
