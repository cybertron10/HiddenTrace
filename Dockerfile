# Multi-stage build for ViduSec Web Application
FROM golang:1.21-alpine AS builder

# Install git and ca-certificates
RUN apk add --no-cache git ca-certificates

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
COPY web/go.mod web/go.sum ./web/

# Download dependencies
RUN go mod download
RUN cd web && go mod download

# Copy source code
COPY . .

# Build the web application
WORKDIR /app/web
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o vidusec-web main.go

# Final stage
FROM alpine:latest

# Install ca-certificates and sqlite
RUN apk --no-cache add ca-certificates sqlite

# Create app user
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/web/vidusec-web .

# Copy templates and static files
COPY --from=builder /app/web/templates ./templates
COPY --from=builder /app/web/static ./static

# Create data directory
RUN mkdir -p data/scans && \
    chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/ || exit 1

# Run the application
CMD ["./vidusec-web"]
