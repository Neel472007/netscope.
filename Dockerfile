FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o netscope ./cmd/netscope

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY --from=builder /app/netscope ./
COPY --from=builder /app/web ./web
EXPOSE 8199
CMD ["./netscope", "serve"]
