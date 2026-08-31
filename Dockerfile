# NetScope — Multi-stage Docker build
# Build stage: compile Go binary
FROM golang:1.22-alpine AS builder
RUN apk --no-cache add git ca-certificates
WORKDIR /app
COPY go.mod ./
RUN go mod download || true
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /netscope ./cmd/netscope

# Runtime stage: minimal image
FROM alpine:latest
RUN apk --no-cache add ca-certificates tzdata
RUN adduser -D -u 1001 netscope
WORKDIR /app
COPY --from=builder /netscope ./netscope
COPY --from=builder /app/web ./web
COPY --from=builder /app/docs ./docs
RUN chown -R netscope:netscope /app
USER netscope
EXPOSE 8199
ENV PORT=8199
CMD ["./netscope", "serve", "-addr=:8199"]
