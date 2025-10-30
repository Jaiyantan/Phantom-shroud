# Phantom-shroud - Quick Start Guide

⏱️ **24-Hour Hackathon MVP - Get Running in 10 Minutes**

## Prerequisites

- Python 3.10+ with pip
- Node.js 18+ with npm
- OpenVPN installed (`sudo apt install openvpn` on Ubuntu)
- Root/sudo access (required for packet capture and VPN)

## Step 1: Initial Setup (3 minutes)

```bash
# Make setup script executable and run it
chmod +x setup.sh
./setup.sh

# This will:
# 1. Create Python virtual environment
# 2. Install all Python dependencies
# 3. Create necessary directories
# 4. Set up logging
# 5. Install frontend dependencies
# 6. Display next steps
```

## Step 2: Add Your VPN Configuration (2 minutes)

```bash
# Replace the placeholder with your actual OpenVPN config
cp your-vpn-config.ovpn config/vpn_profiles/default.ovpn

# Or edit the placeholder:
nano config/vpn_profiles/default.ovpn
```

**Important**: Your VPN config must include authentication credentials or reference a separate auth file.

## Step 3: Start the Backend (1 minute)

```bash
# Activate virtual environment
source venv/bin/activate

# Start the API server (run as root for packet capture)
sudo venv/bin/python api/app.py
```

The backend will start on `http://localhost:5000`

## Step 4: Start the Dashboard (1 minute)

In a new terminal:

```bash
cd dashboard
npm run dev
```

The dashboard will start on `http://localhost:5173`

## Step 5: Test the System (3 minutes)

1. **Open Dashboard**: Navigate to `http://localhost:5173` in your browser
2. **Check Network Status**: Should show "Monitoring" with live packet counts
3. **Connect VPN**: Click "Connect VPN" button in VPN Control panel
4. **Generate Traffic**: Browse websites, run `ping google.com`, etc.
5. **Watch Threats**: Threat feed should populate with detected events

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    React Dashboard                       │
│              (http://localhost:5173)                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │  Network    │  │   Threat    │  │     VPN     │     │
│  │   Status    │  │    Feed     │  │   Control   │     │
│  └─────────────┘  └─────────────┘  └─────────────┘     │
└────────────────────────────┬────────────────────────────┘
                             │ WebSocket + REST API
                             ↓
┌─────────────────────────────────────────────────────────┐
│              Flask API Server (Port 5000)                │
│                                                           │
│  ┌─────────────────────────────────────────────────┐   │
│  │              Core Security Modules               │   │
│  │                                                   │   │
│  │  ┌──────────────┐      ┌──────────────┐        │   │
│  │  │   Network    │─────→│  DPI Engine  │        │   │
│  │  │  Inspector   │      │              │        │   │
│  │  └──────────────┘      └──────────────┘        │   │
│  │         │                      │                │   │
│  │         ↓                      ↓                │   │
│  │  ┌──────────────┐      ┌──────────────┐        │   │
│  │  │   Anomaly    │      │    Threat    │        │   │
│  │  │   Detector   │─────→│   Analyzer   │        │   │
│  │  └──────────────┘      └──────────────┘        │   │
│  │         ↓                                       │   │
│  │  ┌──────────────┐      ┌──────────────┐        │   │
│  │  │     VPN      │      │   Honeypot   │        │   │
│  │  │   Manager    │      │              │        │   │
│  │  └──────────────┘      └──────────────┘        │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

## API Endpoints Reference

### Network Monitoring
- `GET /api/status` - System status and network stats
- `GET /api/network/flows` - Active network flows

### Threat Detection
- `GET /api/threats/recent?limit=10` - Recent threat alerts
- `GET /api/threats/incidents` - Correlated security incidents
- `GET /api/stats/summary` - Overall statistics

### VPN Control
- `POST /api/vpn/connect` - Connect to VPN
- `POST /api/vpn/disconnect` - Disconnect from VPN
- `GET /api/vpn/status` - Current VPN status

### Honeypot
- `GET /api/honeypot/logs` - Honeypot interaction logs

### WebSocket Events
- `connect` - Client connected
- `disconnect` - Client disconnected
- `request_update` - Force immediate data push
- `network_update` - Network stats pushed to client
- `threat_update` - New threats pushed to client

## Configuration

Edit `config/config.yaml` to customize:

```yaml
network_inspector:
  interface: "eth0"           # Change to your network interface
  capture_filter: "ip"        # BPF filter for packet capture
  max_flows: 1000            # Maximum flows to track

anomaly_detector:
  sensitivity: 0.7            # Detection sensitivity (0.0-1.0)
  model_path: "models/isolation_forest.pkl"

vpn_manager:
  config_path: "config/vpn_profiles/default.ovpn"
  kill_switch_enabled: true   # Block non-VPN traffic

honeypot:
  ports: [22, 80, 443]       # Ports to listen on
  log_file: "data/honeypot_logs.json"
```

## Development Workflow (24-Hour Sprint)

### Phase 1: Core Functionality (Hours 0-12)

1. **Network Inspector** (`core/network_inspector.py`):
   - Implement actual Scapy packet capture in TODO sections
   - Test with: `sudo python -m core.network_inspector`

2. **DPI Engine** (`core/dpi_engine.py`):
   - Implement feature extraction for protocols
   - Test with sample PCAP files

3. **Anomaly Detector** (`core/anomaly_detector.py`):
   - Implement rule-based detection logic
   - Train Isolation Forest model if needed

4. **VPN Manager** (`core/vpn_manager.py`):
   - Implement OpenVPN subprocess management
   - Implement iptables kill switch

5. **Honeypot** (`core/honeypot.py`):
   - Customize fake banners
   - Implement interaction logging

6. **Threat Analyzer** (`core/threat_analyzer.py`):
   - Implement event correlation logic
   - Test incident creation

### Phase 2: Integration (Hours 12-18)

1. **API Routes** (`api/routes.py`):
   - Register blueprint in `app.py`
   - Test all endpoints with curl/Postman

2. **WebSocket** (`api/app.py`):
   - Test real-time updates
   - Verify data push timing

3. **Dashboard Components**:
   - Integrate real data in `Stats.jsx` with Chart.js
   - Test all component interactions

### Phase 3: Testing & Polish (Hours 18-24)

1. Run unit tests: `python -m pytest tests/`
2. Integration testing with real traffic
3. Fix bugs and edge cases
4. Documentation updates
5. Demo preparation

## Troubleshooting

### "Permission denied" when starting backend
```bash
# Run with sudo (required for packet capture)
sudo venv/bin/python api/app.py
```

### "Module not found" errors
```bash
# Ensure virtual environment is activated
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt
```

### VPN connection fails
```bash
# Test OpenVPN manually first
sudo openvpn config/vpn_profiles/default.ovpn

# Check OpenVPN logs
sudo journalctl -u openvpn -f
```

### Dashboard not connecting to backend
1. Check backend is running: `curl http://localhost:5000/api/status`
2. Check CORS configuration in `api/app.py`
3. Check WebSocket connection in browser console

### No packets captured
```bash
# List network interfaces
ip link show

# Update interface in config.yaml
nano config/config.yaml

# Verify permissions
sudo setcap cap_net_raw,cap_net_admin=eip venv/bin/python
```

## Performance Tips

1. **Reduce Packet Capture**: Use more specific BPF filters in config
2. **Limit Flow Tracking**: Reduce `max_flows` in config
3. **Adjust Detection Sensitivity**: Lower `sensitivity` if too many false positives
4. **Disable Unused Features**: Comment out modules in `api/app.py`

## Testing Checklist

- [ ] Backend starts without errors
- [ ] Dashboard loads and connects via WebSocket
- [ ] Network stats update in real-time
- [ ] VPN connects and disconnects successfully
- [ ] Kill switch blocks traffic when VPN disconnected
- [ ] Threats are detected and logged
- [ ] Honeypot logs attacker interactions
- [ ] All API endpoints return valid JSON
- [ ] Unit tests pass

## File Structure Quick Reference

```
Phantom-shroud/
├── core/                    # Security modules (6 files)
│   ├── network_inspector.py # Packet capture
│   ├── dpi_engine.py       # Protocol identification
│   ├── anomaly_detector.py # Threat detection
│   ├── vpn_manager.py      # VPN control
│   ├── honeypot.py         # Deception layer
│   └── threat_analyzer.py  # Event correlation
├── api/                     # Flask backend (2 files)
│   ├── app.py              # Flask + SocketIO setup
│   └── routes.py           # REST API endpoints
├── dashboard/               # React frontend
│   └── src/
│       ├── components/     # 5 React components
│       └── utils/          # API client
├── config/                  # Configuration files
├── tests/                   # Unit tests
└── setup.sh                # One-command setup
```

## Next Steps After Setup

1. **Run the system** and verify all components work
2. **Generate test traffic** to see detection in action
3. **Customize detection rules** in `anomaly_detector.py`
4. **Train ML model** if using Isolation Forest
5. **Implement TODO sections** following 24-hour timeline
6. **Test with real attacks** (in safe environment!)
7. **Prepare demo** for hackathon presentation

## Support

- Check `ARCHITECTURE.md` for detailed technical documentation
- Check `PROPOSED_STRUCTURE.md` for implementation timeline
- Review TODO comments in source files for specific tasks
- Check logs in `logs/` directory for debugging

---

**⚡ Quick Commands Summary**

```bash
# Setup
./setup.sh

# Start Backend (Terminal 1)
source venv/bin/activate
sudo venv/bin/python api/app.py

# Start Frontend (Terminal 2)
cd dashboard && npm run dev

# Run Tests
python -m pytest tests/

# Check Logs
tail -f logs/phantom_shroud.log
```

**Good luck with your 24-hour hackathon! 🚀**
