ARG GO_IMAGE=golang:1.25.5-bookworm
ARG RUNTIME_IMAGE=debian:bookworm-slim

FROM ${GO_IMAGE} AS builder

WORKDIR /src

# sqlite driver uses CGO (github.com/mattn/go-sqlite3) -> needs a C toolchain
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates \
      gcc \
      libc6-dev \
    && rm -rf /var/lib/apt/lists/*

COPY go.mod go.sum ./
RUN go mod download

COPY . ./
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/go-client ./

FROM ${RUNTIME_IMAGE} AS runtime

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/go-client /usr/local/bin/go-client

EXPOSE 8888
ENTRYPOINT ["/usr/local/bin/go-client"]
CMD ["-db", "/data/data.db"]
