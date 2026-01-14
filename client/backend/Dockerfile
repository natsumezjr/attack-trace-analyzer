ARG IMAGE=registry.k8s.io/build-image/go-runner:v2.3.1-go1.22.8-bookworm.0

FROM ${IMAGE}

WORKDIR /src

# sqlite driver uses CGO (github.com/mattn/go-sqlite3) -> needs a C toolchain
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates \
      gcc \
      libc6-dev \
    && rm -rf /var/lib/apt/lists/*

# China-friendly module proxy settings
ENV GOPROXY=https://goproxy.cn,direct \
    GOSUMDB=sum.golang.google.cn

COPY go.mod go.sum ./
RUN go mod tidy

COPY . ./
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /usr/local/bin/go-client ./

EXPOSE 8888
ENTRYPOINT ["/usr/local/bin/go-client"]
CMD ["-db", "/data/data.db"]
