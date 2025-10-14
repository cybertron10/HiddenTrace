#!/bin/bash

# ViduSec EC2 Deployment Script
# This script sets up and runs ViduSec on EC2 Ubuntu

echo "🚀 ViduSec EC2 Deployment Script"
echo "================================="

# Update system
echo "📦 Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install Go if not present
if ! command -v go &> /dev/null; then
    echo "🔧 Installing Go..."
    wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    export PATH=$PATH:/usr/local/go/bin
    rm go1.21.5.linux-amd64.tar.gz
fi

# Install Git if not present
if ! command -v git &> /dev/null; then
    echo "🔧 Installing Git..."
    sudo apt install -y git
fi

# Install curl if not present
if ! command -v curl &> /dev/null; then
    echo "🔧 Installing curl..."
    sudo apt install -y curl
fi

# Clone or update repository
if [ -d "vidusec" ]; then
    echo "📁 Updating existing repository..."
    cd vidusec
    git pull origin main
else
    echo "📁 Cloning repository..."
    git clone https://github.com/cybertron10/vidusec.git
    cd vidusec
fi

# Go to web directory
cd web

# Make scripts executable
chmod +x build.sh run.sh

# Build and run
echo "🔨 Building and starting ViduSec..."
./run.sh
