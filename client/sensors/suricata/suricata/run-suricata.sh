#!/bin/sh
set -e

MODE=${SURICATA_MODE:-live}

if [ "$MODE" = "pcap" ]; then
  PCAP=${PCAP_FILE:-/data/pcap/sample.pcap}
  exec suricata -c /etc/suricata/suricata.yaml -r "$PCAP"
fi

IFACE=${SURICATA_IFACE:-eth0}
exec suricata -c /etc/suricata/suricata.yaml -i "$IFACE"