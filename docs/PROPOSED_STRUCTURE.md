# Phantom-shroud: MVP Directory Structure (24-Hour Build)

This document outlines the **simplified directory structure** for the 24-hour hackathon MVP of the Privacy Guard project.

## MVP Directory Tree (Streamlined for Speed)

```
Phantom-shroud/                           # 24-Hour MVP Structure
│
├── 📄 README.md                          # Updated for 24h hackathon
├── 📄 LICENSE                            # MIT License
├── 📄 requirements.txt                   # Minimal dependencies (~10 packages)
├── 📄 .gitignore                         # Git ignore
├── 📄 setup.sh                           # Quick setup script
│
├── � config/                            # Configuration (simplified)
│   ├── 📄 config.yaml                    # Single config file
│   └── � vpn_profiles/
│       └── 📄 default.ovpn               # OpenVPN config only
│
├── 📁 core/                              # Core modules (6 files)
│   ├── 📄 __init__.py
│   │
│   ├── 📄 network_inspector.py           # ~200 lines
│   │   └── class NetworkInspector
│   │       ├── start_capture()           # Scapy sniffing
│   │       ├── process_packet()          # Basic flow tracking
│   │       └── get_stats()               # Return metrics
│   │
│   ├── 📄 dpi_engine.py                  # ~150 lines
│   │   └── class DPIEngine
│   │       ├── analyze_packet()          # Protocol ID
│   │       ├── extract_features()        # 15-20 features
│   │       └── identify_protocol()       # HTTP/HTTPS/DNS
│   │
│   ├── 📄 anomaly_detector.py            # ~200 lines
│   │   └── class AnomalyDetector
│   │       ├── load_model()              # Load pre-trained
│   │       ├── detect()                  # Rule + ML check
│   │       ├── check_arp_spoof()         # Rule-based
│   │       └── check_dns_hijack()        # Rule-based
│   │
│   ├── 📄 vpn_manager.py                 # ~150 lines
│   │   └── class VPNManager
│   │       ├── connect()                 # Start OpenVPN
│   │       ├── disconnect()              # Stop OpenVPN
│   │       ├── enable_kill_switch()      # iptables
│   │       └── is_connected()            # Status check
│   │
│   ├── 📄 honeypot.py                    # ~100 lines
│   │   └── class Honeypot
│   │       ├── start()                   # Listen on port
│   │       ├── log_interaction()         # Save attacker IP
│   │       └── send_fake_banner()        # Fake SSH/HTTP
│   │
│   └── 📄 threat_analyzer.py             # ~150 lines
│       └── class ThreatAnalyzer
│           ├── add_event()               # Collect events
│           ├── correlate_events()        # Group by IP/time
│           └── get_incidents()           # Return timeline
│
├── 📁 models/                            # Pre-trained models
│   └── 📄 isolation_forest.pkl           # Scikit-learn model (~1MB)
│
├── 📁 utils/                             # Helper modules (3 files)
│   ├── 📄 __init__.py
│   ├── 📄 logger.py                      # Simple file logging (~50 lines)
│   └── 📄 network_utils.py               # Helper functions (~50 lines)
│
│
├── � api/                               # Flask API (2 files)
│   ├── 📄 app.py                         # Main Flask app (~200 lines)
│   │   ├── Flask + Flask-SocketIO setup
│   │   ├── CORS configuration
│   │   └── WebSocket event handlers
│   │
│   └── 📄 routes.py                      # API endpoints (~150 lines)
│       ├── GET  /api/status              # System status
│       ├── GET  /api/threats/recent      # Recent threats
│       ├── POST /api/vpn/connect         # VPN control
│       ├── POST /api/vpn/disconnect
│       └── GET  /api/honeypot/logs       # Honeypot interactions
│
├── � dashboard/                         # React dashboard (simplified)
│   ├── � package.json                   # ~10 dependencies
│   ├── 📄 vite.config.js                 # Vite configuration
│   ├── 📄 index.html                     # Entry point
│   ├── � tailwind.config.js             # Tailwind CSS
│   │
│   ├── � src/
│   │   ├── 📄 main.jsx                   # React entry (~20 lines)
│   │   ├── 📄 App.jsx                    # Main component (~150 lines)
│   │   │   ├── Layout and routing
│   │   │   ├── WebSocket connection
│   │   │   └── State management
│   │   │
│   │   ├── 📄 App.css                    # Global styles (~50 lines)
│   │   │
│   │   ├── 📁 components/                # UI components (5 files)
│   │   │   ├── 📄 NetworkStatus.jsx      # Live stats (~100 lines)
│   │   │   ├── 📄 ThreatFeed.jsx         # Threat list (~120 lines)
│   │   │   ├── 📄 VPNControl.jsx         # VPN button (~80 lines)
│   │   │   ├── 📄 Stats.jsx              # Charts (~100 lines)
│   │   │   └── 📄 AlertPanel.jsx         # Notifications (~60 lines)
│   │   │
│   │   └── � utils/
│   │       └── � api.js                 # API client (~80 lines)
│   │
│   └── 📁 public/
│       └── 📄 favicon.ico
│
├── 📁 tests/                             # Basic tests (optional for 24h)
│   └── 📄 test_core.py                   # Smoke tests (~100 lines)
│
├── � logs/                              # Log files (auto-generated)
│   └── 📄 events.log
│
└── 📁 data/                              # Runtime data (auto-generated)
    ├── 📄 threats.json                   # Threat history
    └── 📄 honeypot_logs.json             # Attacker interactions

## MVP File Count Summary

**Total Files**: ~30 files  
**Total Lines of Code**: ~2,850 lines

### Breakdown by Component

| Component | Files | Lines | Description |
|-----------|-------|-------|-------------|
| **Core Modules** | 6 | ~950 | Security engines |
| **Models** | 1 | N/A | Pre-trained ML model |
| **Utils** | 3 | ~100 | Helper functions |
| **API Backend** | 2 | ~350 | Flask REST + WebSocket |
| **Dashboard** | 11 | ~900 | React frontend |
| **Config** | 4 | ~200 | Settings & scripts |
| **Tests** | 1 | ~100 | Basic smoke tests |
| **Documentation** | 3 | ~250 | README, docs |
| **TOTAL** | **~30** | **~2,850** | Complete MVP |

### Core Components Detail
- `network_inspector.py` - ~200 lines (packet capture)
- `dpi_engine.py` - ~150 lines (protocol analysis)
- `anomaly_detector.py` - ~200 lines (threat detection)
- `vpn_manager.py` - ~150 lines (VPN control)
- `honeypot.py` - ~100 lines (deception)
- `threat_analyzer.py` - ~150 lines (correlation)

---

## MVP vs Full Version Comparison

| Aspect | MVP (24 Hours) | Full Version (16 Weeks) |
|--------|---------------|------------------------|
| **Files** | ~30 files | 120-150 files |
| **Code** | ~2,850 lines | ~22,500 lines |
| **ML Models** | 1 pre-trained | 3+ trained models |
| **Dashboard** | 5 components | 30+ components |
| **Storage** | JSON files | PostgreSQL + Redis |
| **VPN** | OpenVPN only | OpenVPN + WireGuard |
| **Tests** | Basic smoke | Comprehensive suite |
| **Deployment** | Local/Docker | Kubernetes cluster |

---

*This MVP structure prioritizes demonstrable functionality over production scalability, enabling rapid development for a 24-hour hackathon environment.*
