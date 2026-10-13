# Build stage
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /app/gear ./cmd/gear/

# Run stage
FROM alpine:3.19
WORKDIR /app
COPY --from=builder /app/gear /app/gear
EXPOSE 8080 8443
ENTRYPOINT ["/app/gear"]
