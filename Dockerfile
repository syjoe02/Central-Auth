FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o central-auth ./cmd/server

FROM alpine:3.19

WORKDIR /app

COPY --from=builder /app/central-auth .

EXPOSE 8081

CMD ["./central-auth"]