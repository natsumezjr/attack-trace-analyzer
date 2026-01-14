FROM swr.cn-north-4.myhuaweicloud.com/ddn-k8s/docker.io/xinghanxu/mcsm:ubuntu22.04

WORKDIR /app

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY go-client /usr/local/bin/go-client
RUN chmod +x /usr/local/bin/go-client

EXPOSE 8888
ENTRYPOINT ["/usr/local/bin/go-client"]
CMD ["-db", "/data/data.db"]
