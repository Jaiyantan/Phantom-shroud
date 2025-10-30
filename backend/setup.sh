#!/bin/bash
# Phantom-shroud Quick Setup Script
# 24-Hour Hackathon MVP

echo "==================================="
echo "Phantom-shroud Setup"
echo "==================================="
echo ""

# Check Python version
echo "[1/6] Checking Python version..."
python3 --version || { echo "Error: Python 3 not found"; exit 1; }

# Create virtual environment
echo "[2/6] Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
echo "[3/6] Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "[4/6] Installing Python dependencies..."
pip install -r requirements.txt

# Create directories
echo "[5/6] Creating data directories..."
mkdir -p logs
mkdir -p data
mkdir -p models

# Set permissions (for packet capture)
echo "[6/6] Setup complete!"
echo ""
echo "==================================="
echo "Next Steps:"
echo "==================================="
echo "1. Activate virtual environment:"
echo "   source venv/bin/activate"
echo ""
echo "2. Add OpenVPN configuration:"
echo "   Edit config/vpn_profiles/default.ovpn"
echo ""
echo "3. (Optional) Add pre-trained model:"
echo "   Place isolation_forest.pkl in models/"
echo ""
echo "4. Start API server:"
echo "   python api/app.py"
echo ""
echo "5. Start dashboard (separate terminal):"
echo "   cd dashboard && npm install && npm run dev"
echo ""
echo "==================================="
