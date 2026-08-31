FROM golang:1.21-alpine
WORKDIR /app
COPY . .
RUN go build -o netscope ./cmd/netscope
EXPOSE 8199
CMD ["./netscope", "serve"]