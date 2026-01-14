#!/bin/sh
set -e

MODE=${SURICATA_MODE:-live}

CONFIG_TEMPLATE=${SURICATA_CONFIG_TEMPLATE:-/etc/suricata/suricata.yaml.template}
CONFIG_PATH=${SURICATA_CONFIG_PATH:-/etc/suricata/suricata.yaml}

DEFAULT_HOME_NET_FALLBACK=${SURICATA_HOME_NET_FALLBACK:-"[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]"}

escape_sed_replacement() {
  # Escape replacement string for sed (delimiter |).
  # - backslash and ampersand are special in sed replacements
  # - delimiter must be escaped too
  printf '%s' "$1" | sed -e 's/[\\&|]/\\&/g'
}

if [ "$MODE" = "pcap" ]; then
  PCAP=${PCAP_FILE:-/data/pcap/sample.pcap}
  # HOME_NET can't be inferred from an interface in pcap mode. Use explicit value
  # (SURICATA_HOME_NET) or fall back to RFC1918 ranges.
  HOME_NET=${SURICATA_HOME_NET:-auto}
  if [ -z "$HOME_NET" ] || [ "$HOME_NET" = "auto" ]; then
    HOME_NET=$DEFAULT_HOME_NET_FALLBACK
  fi

  if [ -f "$CONFIG_TEMPLATE" ]; then
    HOME_NET_ESCAPED=$(escape_sed_replacement "$HOME_NET")
    sed "s|__HOME_NET__|$HOME_NET_ESCAPED|g" "$CONFIG_TEMPLATE" > "$CONFIG_PATH"
  fi

  echo "INFO: Suricata mode=pcap HOME_NET=$HOME_NET" >&2
  exec suricata -c "$CONFIG_PATH" -r "$PCAP"
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
    case "$iface" in
      lo|docker0|podman0|cni0|flannel.*|kube-ipvs0|kube-bridge|weave|virbr*|vboxnet*|vmnet*|lxc*|veth*|br-*|tun*|tap*|wg*|tailscale0|zt*|ip6tnl*|sit*)
        continue
        ;;
    esac
    echo "$iface"
    return 0
  done

  return 1
}

detect_first_global_ipv4_iface() {
  if ! command -v ip >/dev/null 2>&1; then
    return 1
  fi

  for iface in $(ip -o -4 addr show scope global 2>/dev/null | awk '{print $2}' | sort -u); do
    case "$iface" in
      lo|docker0|podman0|cni0|flannel.*|kube-ipvs0|kube-bridge|weave|virbr*|vboxnet*|vmnet*|lxc*|veth*|br-*|tun*|tap*|wg*|tailscale0|zt*|ip6tnl*|sit*)
        continue
        ;;
    esac
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

  ipv4_iface=$(detect_first_global_ipv4_iface 2>/dev/null || true)
  if [ -n "$ipv4_iface" ] && iface_exists "$ipv4_iface"; then
    echo "$ipv4_iface"
    return 0
  fi

  first_iface=$(detect_first_non_loopback_iface 2>/dev/null || true)
  if iface_exists "$first_iface"; then
    echo "$first_iface"
    return 0
  fi

  return 1
}

detect_home_net_from_iface() {
  iface="$1"
  [ -n "$iface" ] || return 1

  if ! command -v ip >/dev/null 2>&1; then
    return 1
  fi

  # Prefer the kernel's on-link routes for the capture interface.
  # Example output:
  #   192.168.1.0/24 proto kernel scope link src 192.168.1.10
  nets=$(ip -o -4 route show dev "$iface" scope link 2>/dev/null | awk '{print $1}' | sort -u || true)

  if [ -z "$nets" ]; then
    return 1
  fi

  count=0
  joined=""
  for cidr in $nets; do
    # Skip IPv4 link-local (usually irrelevant for IDS rules).
    case "$cidr" in
      169.254.*) continue ;;
    esac

    count=$((count + 1))
    if [ "$count" -eq 1 ]; then
      joined="$cidr"
    else
      joined="${joined},${cidr}"
    fi
  done

  [ -n "$joined" ] || return 1

  if [ "$count" -gt 1 ]; then
    echo "[$joined]"
  else
    echo "$joined"
  fi

  return 0
}

IFACE=$(resolve_iface)
if [ -z "$IFACE" ]; then
  echo "ERROR: no usable network interface found (available: $(ls /sys/class/net 2>/dev/null | tr '\n' ' '))" >&2
  exit 1
fi
echo "INFO: Suricata capture interface: $IFACE" >&2

HOME_NET=${SURICATA_HOME_NET:-auto}
if [ -z "$HOME_NET" ] || [ "$HOME_NET" = "auto" ]; then
  HOME_NET=$(detect_home_net_from_iface "$IFACE" 2>/dev/null || true)
fi
if [ -z "$HOME_NET" ]; then
  HOME_NET=$DEFAULT_HOME_NET_FALLBACK
  echo "WARN: could not auto-detect HOME_NET for iface '$IFACE'; falling back to $HOME_NET" >&2
fi

if [ -f "$CONFIG_TEMPLATE" ]; then
  HOME_NET_ESCAPED=$(escape_sed_replacement "$HOME_NET")
  sed "s|__HOME_NET__|$HOME_NET_ESCAPED|g" "$CONFIG_TEMPLATE" > "$CONFIG_PATH"
fi

echo "INFO: Suricata mode=live HOME_NET=$HOME_NET" >&2
exec suricata -c "$CONFIG_PATH" -i "$IFACE"
