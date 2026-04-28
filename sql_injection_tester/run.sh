#!/bin/bash

# SQL Injection Scanner - Unix/Linux/Mac Runner
# This script makes it easier to run the SQL Injection Scanner on Unix-like systems

echo ""
echo "==================================================="
echo "  SQL Injection Scanner - Unix/Linux/Mac Runner"
echo "==================================================="
echo ""

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 is not installed"
    echo "Please install Python 3.7+ using:"
    echo "  Ubuntu/Debian: sudo apt-get install python3 python3-pip"
    echo "  macOS: brew install python3"
    echo "  CentOS/RHEL: sudo yum install python3 python3-pip"
    exit 1
fi

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "[ERROR] pip3 is not installed"
    exit 1
fi

# Check if dependencies are installed
python3 -c "import click" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "[*] Installing required dependencies..."
    pip3 install -r requirements.txt
    if [ $? -ne 0 ]; then
        echo "[ERROR] Failed to install dependencies"
        exit 1
    fi
fi

# Make the script executable
chmod +x main.py
chmod +x example_usage.py

# Run the main script with all arguments passed through
python3 main.py "$@"
