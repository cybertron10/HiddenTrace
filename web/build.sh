#!/bin/bash

# HiddenTrace Web Application Build Script

echo "🚀 Building HiddenTrace Web Application..."

# Create data directory
mkdir -p data/scans

# Install dependencies
echo "📦 Installing dependencies..."
go get github.com/google/uuid
go mod tidy

# Build the application
echo "🔨 Building application..."
go build -o vidusec-web main.go

if [ $? -eq 0 ]; then
    echo "✅ Build successful!"
    echo "📁 Binary created: vidusec-web"
    echo ""
    echo "🚀 To run the application:"
    echo "   ./vidusec-web"
    echo ""
    echo "🌐 Then open: http://localhost:8080"
else
    echo "❌ Build failed!"
    exit 1
fi
