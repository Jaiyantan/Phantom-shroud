#!/bin/bash
# Network Inspection System - Phase 1 Setup Script

set -e

echo "============================================================"
echo "Network Inspection System - Phase 1 Setup"
echo "============================================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    echo -e "${YELLOW}Warning: Running as root. Consider using a virtual environment.${NC}"
    echo ""
fi

echo "[1/5] Checking Python version..."
python3 --version
if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Python 3 not found${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Python 3 found${NC}"
echo ""

echo "[2/5] Installing system dependencies..."
if command -v apt-get &> /dev/null; then
    echo "Detected Debian/Ubuntu system"
    sudo apt-get update
    sudo apt-get install -y python3-pip python3-venv libpcap-dev
elif command -v dnf &> /dev/null; then
    echo "Detected Fedora/RHEL system"
    sudo dnf install -y python3-pip python3-virtualenv libpcap-devel
elif command -v pacman &> /dev/null; then
    echo "Detected Arch system"
    sudo pacman -S --noconfirm python-pip libpcap
else
    echo -e "${YELLOW}Warning: Unknown system. Please install libpcap manually.${NC}"
fi
echo -e "${GREEN}✓ System dependencies installed${NC}"
echo ""

echo "[3/5] Creating virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "${GREEN}✓ Virtual environment created${NC}"
else
    echo -e "${YELLOW}Virtual environment already exists${NC}"
fi
echo ""

echo "[4/5] Installing Python dependencies..."
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
echo -e "${GREEN}✓ Python dependencies installed${NC}"
echo ""

echo "[5/5] Setting up packet capture permissions..."
echo "Granting network capabilities to VENV Python..."

# Prefer granting capabilities to the virtualenv interpreter so you can run without sudo
if [ -x "venv/bin/python" ]; then
    VENV_PY=$(readlink -f venv/bin/python)
    echo "Using venv interpreter: $VENV_PY"
    if command -v setcap >/dev/null 2>&1; then
        sudo setcap cap_net_raw,cap_net_admin=eip "$VENV_PY" 2>/dev/null && \
            echo -e "${GREEN}✓ Capabilities granted to venv Python${NC}" || \
            echo -e "${YELLOW}Warning: Could not grant capabilities to venv Python. You may need to run with sudo.${NC}"
    else
        echo -e "${YELLOW}setcap not found. Install libcap2/compat tools to enable capabilities (optional).${NC}"
    fi
else
    echo -e "${YELLOW}Virtualenv python not found. Skipping capability grant.${NC}"
fi
echo ""

echo "============================================================"
echo "Setup Complete!"
echo "============================================================"
echo ""
echo "Next steps:"
echo ""
echo "1. Activate virtual environment:"
echo "   source venv/bin/activate"
echo ""
echo "2. Run the demo (no sudo needed if capabilities applied):"
echo "   ./venv/bin/python scripts/demo_network_inspection.py"
echo "   # or, if you must use sudo, ensure you call the venv interpreter explicitly:"
echo "   sudo ./venv/bin/python scripts/demo_network_inspection.py"
echo ""
echo "3. Or start the API server:"
echo "   ./venv/bin/python api/app.py"
echo "   # or, with sudo if capabilities not set:"
echo "   sudo ./venv/bin/python api/app.py"
echo ""
echo "4. Run tests:"
echo "   pytest tests/test_network_inspection.py -v"
echo ""
echo "============================================================"
echo ""
echo -e "${GREEN}Phase 1 is ready to use!${NC}"
echo ""
