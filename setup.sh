#!/bin/bash

# OpenClaw Shield Setup Script
# This script helps you set up the OpenClaw Shield environment

set -e

echo "=================================="
echo "OpenClaw Shield Setup"
echo "=================================="
echo ""

# Check prerequisites
echo "Checking prerequisites..."

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.9 or higher."
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
echo "✅ Python $PYTHON_VERSION found"

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "⚠️  Docker is not installed. Docker is required for containerized deployment."
    echo "   You can still use OpenClaw Shield without Docker, but some features may be limited."
else
    echo "✅ Docker found"
fi

# Check Docker Compose
if ! command -v docker-compose &> /dev/null; then
    echo "⚠️  Docker Compose is not installed."
else
    echo "✅ Docker Compose found"
fi

echo ""
echo "=================================="
echo "Configuration"
echo "=================================="
echo ""

# Check for .env file
if [ ! -f .env ]; then
    echo "Creating .env file from template..."
    cp .env.example .env
    echo "✅ .env file created"
    echo ""
    echo "⚠️  IMPORTANT: Edit .env file with your Azure credentials"
    echo "   Required variables:"
    echo "   - AZURE_CONTENT_SAFETY_ENDPOINT"
    echo "   - AZURE_CONTENT_SAFETY_KEY"
    echo ""
    read -p "Press Enter to open .env file in editor..."
    ${EDITOR:-nano} .env
else
    echo "✅ .env file already exists"
fi

echo ""
echo "=================================="
echo "Installation"
echo "=================================="
echo ""

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
    echo "✅ Virtual environment created"
else
    echo "✅ Virtual environment already exists"
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt
echo "✅ Dependencies installed"

# Create necessary directories
echo ""
echo "Creating directories..."
mkdir -p workspace
mkdir -p tmp
mkdir -p quarantine
mkdir -p logs
mkdir -p logs/squid
mkdir -p config
echo "✅ Directories created"

# Set permissions
chmod 700 quarantine
chmod 755 workspace tmp

echo ""
echo "=================================="
echo "Configuration Check"
echo "=================================="
echo ""

# Load .env
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# Check Azure credentials
if [ -z "$AZURE_CONTENT_SAFETY_ENDPOINT" ] || [ -z "$AZURE_CONTENT_SAFETY_KEY" ]; then
    echo "⚠️  Azure AI Content Safety credentials not configured"
    echo "   Please edit .env file and add:"
    echo "   - AZURE_CONTENT_SAFETY_ENDPOINT"
    echo "   - AZURE_CONTENT_SAFETY_KEY"
else
    echo "✅ Azure AI Content Safety configured"
fi

# Check Purview (optional)
if [ -z "$PURVIEW_ENDPOINT" ]; then
    echo "ℹ️  Microsoft Purview not configured (optional)"
else
    echo "✅ Microsoft Purview configured"
fi

echo ""
echo "=================================="
echo "Docker Setup (Optional)"
echo "=================================="
echo ""

if command -v docker &> /dev/null; then
    read -p "Do you want to build the Docker image? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Building Docker image..."
        docker build -t openclaw-shield:latest .
        echo "✅ Docker image built"
    fi
fi

echo ""
echo "=================================="
echo "Setup Complete!"
echo "=================================="
echo ""
echo "Next steps:"
echo ""
echo "1. Review and update .env file with your credentials"
echo ""
echo "2. Test the installation:"
echo "   python3 -c 'from openclaw_shield import SecureToolExecutor; print(\"✅ OpenClaw Shield installed successfully\")'"
echo ""
echo "3. Run with Docker Compose:"
echo "   docker-compose up -d"
echo ""
echo "4. Or run standalone:"
echo "   source venv/bin/activate"
echo "   python -m openclaw_shield.main"
echo ""
echo "5. Read the documentation:"
echo "   docs/README.md"
echo "   docs/api-reference.md"
echo "   docs/purview-integration.md"
echo ""
echo "For support: https://github.com/junhao-bitpulse/openclaw-shield/issues"
echo ""
