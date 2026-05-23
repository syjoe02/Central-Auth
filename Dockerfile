FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -o central-auth ./cmd/server

FROM alpine:3.19

RUN wget -qO /bin/grpc-health-probe \
    https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/v0.4.28/grpc_health_probe-linux-amd64 \
    && chmod +x /bin/grpc-health-probe

WORKDIR /app

COPY --from=builder /app/central-auth .

EXPOSE 8081
EXPOSE 9091
EXPOSE 50051

CMD ["./central-auth"]