FROM swr.cn-north-4.myhuaweicloud.com/ddn-k8s/docker.io/xinghanxu/mcsm:ubuntu22.04

WORKDIR /app

COPY go-client /app/go-client
RUN chmod +x /app/go-client

EXPOSE 8888
CMD ["/app/go-client", "-db", "/data/data.db"]
