#!/bin/bash

# Simple HiddenTrace Startup Script
# Minimal version for quick startup

# Load environment variables
if [ -f .env ]; then
    source .env
fi

# Pull latest changes
git pull origin main

# Download dependencies
go mod download
go mod tidy

# Build application
go build -o HiddenTrace-web web/main.go

# Set JWT secret if not set
export JWT_SECRET=${JWT_SECRET:-"$(openssl rand -base64 64)"}

# Start server
echo "🚀 Starting HiddenTrace on ${HOST:-0.0.0.0}:${PORT:-8080}"
./HiddenTrace-web
