FROM swr.cn-north-4.myhuaweicloud.com/ddn-k8s/docker.io/xinghanxu/mcsm:ubuntu22.04

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y suricata iproute2 && \
    rm -rf /var/lib/apt/lists/*

COPY suricata.yaml /etc/suricata/suricata.yaml.template
COPY run-suricata.sh /run-suricata.sh
RUN mkdir -p /etc/suricata/rules
COPY suricata.rules /etc/suricata/rules/suricata.rules
RUN chmod +x /run-suricata.sh

CMD ["/bin/sh", "/run-suricata.sh"]
