#!/bin/bash
# setup.sh — Bug Bounty Professional Framework Setup

set -e

echo "=========================================="
echo "  Bug Bounty Professional Framework v3.0"
echo "  Complete Installation Script"
echo "=========================================="
echo ""

# Check Python
PYTHON_VERSION=$(python3 --version 2>&1 | grep -oP '\d+\.\d+')
if (( $(echo "$PYTHON_VERSION < 3.8" | bc -l) )); then
    echo "[!] Python 3.8+ required. Found: $PYTHON_VERSION"
    exit 1
fi
echo "[+] Python $PYTHON_VERSION detected"

# Create virtual environment (optional but recommended)
if [ ! -d "venv" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
    echo "[+] Virtual environment created"
fi

# Install dependencies
echo "[*] Installing Python dependencies..."
pip install --upgrade pip setuptools wheel
pip install customtkinter Pillow requests aiohttp beautifulsoup4 lxml
pip install dnspython urllib3 colorama markdown tldextract pyjwt cryptography jsbeautifier

# Install optional system dependencies
echo "[*] Installing optional system dependencies..."
if command -v apt-get &>/dev/null; then
    sudo apt-get update -qq
    sudo apt-get install -y -qq python3-dnspython wkhtmltopdf 2>/dev/null || true
fi

# Create directory structure
echo "[*] Creating directory structure..."
mkdir -p scanners utils reports assets

# Verify installation
echo "[*] Verifying installation..."
python3 -c "
import customtkinter
import requests
import bs4
import dns.resolver
print('[+] All imports verified successfully')
print(f'[+] CustomTkinter: {customtkinter.__version__}')
" 2>/dev/null || {
    echo "[!] Some dependencies failed to import. Check pip install output."
}

echo ""
echo "=========================================="
echo "  Setup Complete!"
echo "=========================================="
echo ""
echo "  To run the framework:"
echo "    python3 main.py"
echo ""
echo "  Reports are saved to: reports/"
echo "=========================================="