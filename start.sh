#!/bin/bash

# HiddenTrace Web Server Startup Script
# This script handles environment loading, updates, and server startup

set -e  # Exit on any error

echo "🚀 Starting HiddenTrace Web Server..."

# Load environment variables if .env file exists
if [ -f .env ]; then
    echo "📋 Loading environment variables from .env..."
    source .env
else
    echo "⚠️  Warning: .env file not found. Using default settings."
    echo "   Create a .env file with your configuration for production use."
fi

# Set default values if not set in .env
export HOST=${HOST:-"0.0.0.0"}
export PORT=${PORT:-"8080"}
export JWT_SECRET=${JWT_SECRET:-"$(openssl rand -base64 64)"}
export ENVIRONMENT=${ENVIRONMENT:-"development"}

echo "🔧 Configuration:"
echo "   Host: $HOST"
echo "   Port: $PORT"
echo "   Environment: $ENVIRONMENT"
echo "   JWT Secret: ${JWT_SECRET:0:20}..." # Show only first 20 chars for security

# Pull latest changes from repository
echo "📥 Pulling latest changes from repository..."
if git pull origin main; then
    echo "✅ Repository updated successfully"
else
    echo "⚠️  Warning: Failed to pull latest changes. Continuing with current version."
fi

# Download and tidy Go dependencies
echo "📦 Updating Go dependencies..."
if go mod download && go mod tidy; then
    echo "✅ Dependencies updated successfully"
else
    echo "❌ Error: Failed to update dependencies"
    exit 1
fi

# Build the web application
echo "🔨 Building HiddenTrace web application..."
if go build -o vidusec-web web/main.go; then
    echo "✅ Application built successfully"
else
    echo "❌ Error: Failed to build application"
    exit 1
fi

# Create data directory if it doesn't exist
mkdir -p data

# Set proper permissions for data directory
chmod 755 data

# Check if port is already in use
if lsof -Pi :$PORT -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo "⚠️  Warning: Port $PORT is already in use."
    echo "   You may need to stop the existing process or change the PORT in .env"
    echo "   To find and kill the process using port $PORT:"
    echo "   sudo lsof -ti:$PORT | xargs sudo kill -9"
    echo ""
    read -p "Do you want to continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "❌ Startup cancelled by user"
        exit 1
    fi
fi

# Start the server
echo "🌟 Starting HiddenTrace web server on $HOST:$PORT..."
echo "   Access your application at: http://$HOST:$PORT"
echo "   Press Ctrl+C to stop the server"
echo ""

# Run the application with proper error handling
if [ "$ENVIRONMENT" = "production" ]; then
    echo "🔒 Running in PRODUCTION mode"
    ./vidusec-web
else
    echo "🛠️  Running in DEVELOPMENT mode"
    ./vidusec-web
fi
