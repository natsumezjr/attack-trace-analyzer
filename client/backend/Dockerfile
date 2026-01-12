# syntax=docker/dockerfile:1

FROM golang:1.22-alpine AS build

WORKDIR /src

RUN apk add --no-cache ca-certificates git

COPY go.mod ./
RUN go mod download

COPY . .

RUN go build -trimpath -o /out/client-backend ./cmd/client-backend

FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY --from=build /out/client-backend /usr/local/bin/client-backend

EXPOSE 18080

ENTRYPOINT ["client-backend"]
