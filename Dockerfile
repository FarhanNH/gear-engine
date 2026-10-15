# Build stage
FROM golang:1.26-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /app/gear ./cmd/gear/

# Run stage
FROM alpine:3.23
RUN apk add --no-cache ca-certificates curl
WORKDIR /app
COPY --from=builder /app/gear /app/gear
EXPOSE 8080 8443
ENTRYPOINT ["/app/gear"]
CMD ["serve"]
