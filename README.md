# Phantom-shroud: Privacy Guard for Public Wi-Fi Networks

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Hackathon](https://img.shields.io/badge/hackathon-24h-orange.svg)]()
[![Status](https://img.shields.io/badge/status-MVP%20Development-yellow.svg)]()

## 🛡️ Overview

**Phantom-shroud** is a security solution designed and built within a **24-hour hackathon** to protect users on public Wi-Fi networks. The system detects insecure networks, monitors for man-in-the-middle (MITM) attacks, and provides automated protection through VPN encryption. Taking inspiration from the **Wii-Secure** project, Phantom-shroud delivers an MVP implementation with core defence mechanisms: network inspection, threat detection, VPN tunneling, deception capabilities, and a real-time monitoring dashboard.

### Key Capabilities (24-Hour MVP)

- **🔍 Network Inspection**: Real-time packet capture and basic flow tracking
- **🔬 Deep Packet Inspection (DPI)**: Essential protocol analysis and feature extraction
- **🤖 Anomaly Detection**: Rule-based + lightweight ML threat detection
- **🔐 VPN Tunneling**: Automatic encrypted tunnel with OpenVPN
- **🎭 Deception Layer**: Basic honeypot implementation
- **🧠 Threat Analysis**: Simple correlation and threat classification
- **📊 Admin Dashboard**: Real-time monitoring and alert interface

---

## ⏱️ 24-Hour Hackathon Challenge

**Time Constraint**: Built from scratch in 24 hours  
**Approach**: MVP (Minimum Viable Product) with core defence mechanisms  
**Focus**: Demonstrable protection, functional prototypes, rapid iteration

### Hackathon Timeline

- **Hours 0-6**: Core infrastructure, network inspection, DPI engine
- **Hours 6-12**: Anomaly detection, VPN integration, deception layer
- **Hours 12-18**: API backend, threat correlation, basic causal analysis
- **Hours 18-24**: Admin dashboard, integration, testing, demo prep

### Documentation

**Architecture Documentation**:
1. **[ARCHITECTURE.md](ARCHITECTURE.md)** - 24-hour implementation architecture
2. **[PROPOSED_STRUCTURE.md](PROPOSED_STRUCTURE.md)** - Simplified MVP directory structure

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                   Phantom-shroud                         │
│                                                          │
│  ┌──────────────┐    ┌──────────────┐                  │
│  │   Network    │───▶│     DPI      │                  │
│  │  Inspector   │    │   Engine     │                  │
│  └──────────────┘    └──────────────┘                  │
│                             │                            │
│                             ▼                            │
│                  ┌──────────────────┐                   │
│                  │    Anomaly       │                   │
│                  │    Detector      │                   │
│                  └──────────────────┘                   │
│                             │                            │
│          ┌─────────────────┼─────────────────┐         │
│          ▼                  ▼                 ▼         │
│   ┌──────────┐      ┌──────────┐     ┌──────────┐     │
│   │   VPN    │      │Deception │     │  Causal  │     │
│   │ Manager  │      │   Loop   │     │Inference │     │
│   └──────────┘      └──────────┘     └──────────┘     │
│                                                          │
│  ┌──────────────────────────────────────────────────┐  │
│  │              API Layer (Flask)                    │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
              ┌───────────────────────┐
              │   Admin Dashboard     │
              │   (React + Vite)      │
              └───────────────────────┘
```

---

## 🎯 Defence-Side Components (MVP Focus)

### 1. Network Inspection System (Hours 0-3)
**MVP Scope**:
- Basic packet capture using Scapy
- Simple flow tracking (src/dst IP, ports)
- Single interface monitoring
- Target: 1,000+ packets/second

### 2. Deep Packet Inspection (Hours 3-6)
**MVP Scope**:
- Protocol identification (HTTP, HTTPS, DNS)
- Basic SSL/TLS validation
- Essential feature extraction (~20 features)
- Payload size and frequency analysis

### 3. Anomaly Detection (Hours 6-10)
**MVP Scope**:
- Rule-based detection (ARP spoofing, DNS hijacking)
- Simple statistical anomaly detection (Isolation Forest)
- Signature matching for known attacks
- Real-time alerting
- Target: <2s detection latency

### 4. VPN Tunneling (Hours 10-12)
**MVP Scope**:
- OpenVPN integration
- Manual and automatic connection triggers
- Basic kill switch (iptables rules)
- Connection status monitoring

### 5. Deception Layer (Hours 12-14)
**MVP Scope**:
- Basic honeypot (SSH, HTTP)
- Connection logging
- Simple attacker IP tracking
- Alert generation on interaction

### 6. Threat Analysis (Hours 14-16)
**MVP Scope**:
- Event correlation by time/IP
- Simple attack chain identification
- Threat severity scoring
- Basic incident timeline

### 7. Admin Dashboard (Hours 16-24)
**MVP Scope**:
- Real-time network status display
- Live threat feed
- VPN control interface
- Alert notifications
- Basic statistics and charts

---

## 📁 MVP Directory Structure (24-Hour Build)

```
Phantom-shroud/
├── core/                      # Core security modules (simplified)
│   ├── network_inspector.py   # Scapy-based packet capture
│   ├── dpi_engine.py          # Basic protocol analysis
│   ├── anomaly_detector.py    # Rule-based + simple ML
│   ├── vpn_manager.py         # OpenVPN controller
│   ├── honeypot.py            # Basic honeypot services
│   └── threat_analyzer.py     # Event correlation
├── models/                    # Pre-trained ML models
│   └── isolation_forest.pkl    # Pre-trained model
├── api/                       # Flask backend (lightweight)
│   ├── app.py                 # Main API server
│   └── routes.py              # API endpoints
├── dashboard/                 # React admin dashboard
│   ├── src/
│   │   ├── App.jsx            # Main component
│   │   ├── components/        # UI components
│   │   └── utils/             # Helper functions
│   └── package.json
├── utils/                     # Shared utilities
│   ├── logger.py
│   └── network_utils.py
├── config/                    # Configuration
│   ├── config.yaml            # System config
│   └── vpn_profiles/          # VPN configs
└── requirements.txt           # Python dependencies
```

See [PROPOSED_STRUCTURE.md](PROPOSED_STRUCTURE.md) for detailed structure.

---

## 🚀 24-Hour Development Sprint

**Total Duration**: 24 hours (MVP approach)

| Sprint | Duration | Components | Status |
|--------|----------|------------|--------|
| **Sprint 1** | Hours 0-6 | Network Inspector + DPI Engine | 🎯 Core Foundation |
| **Sprint 2** | Hours 6-12 | Anomaly Detection + VPN Manager | 🛡️ Protection Layer |
| **Sprint 3** | Hours 12-18 | Honeypot + Threat Analyzer + API | 🎭 Intelligence Layer |
| **Sprint 4** | Hours 18-24 | Admin Dashboard + Integration | 📊 Visualization & Demo |

### Implementation Strategy

**Parallel Development Tracks**:
- **Track 1 (Hours 0-12)**: Backend core (Network + Detection + VPN)
- **Track 2 (Hours 12-18)**: API + Data flow + Integration
- **Track 3 (Hours 18-24)**: Frontend dashboard + Final testing

---

## 🛠️ Technology Stack (MVP)

### Backend (Python)
- **Packet Processing**: Scapy (no NetfilterQueue initially)
- **ML**: Scikit-learn (Isolation Forest pre-trained)
- **API**: Flask (lightweight, quick setup)
- **VPN**: OpenVPN subprocess management

### Frontend (JavaScript)
- **Framework**: React + Vite (fast dev server)
- **UI**: Tailwind CSS (utility-first, rapid styling)
- **Charts**: Chart.js (simple, quick integration)
- **Real-time**: WebSocket (Flask-SocketIO)

### Deployment
- **Local**: Python venv + npm
- **Docker**: Optional for demo

---

## 🎯 MVP Success Criteria (24-Hour Goal)

### Functional Requirements
- ✅ Capture and analyze network packets in real-time
- ✅ Detect at least 3 common attacks (ARP spoofing, DNS hijacking, suspicious traffic)
- ✅ Automatic VPN activation on threat detection
- ✅ Basic honeypot logging attacker interactions
- ✅ Live dashboard showing network status and threats

### Performance Targets (Realistic for 24h)
- **Packet Processing**: 1,000+ packets/second
- **Detection Latency**: <2 seconds
- **Dashboard Updates**: Real-time (1-2 second refresh)
- **System Overhead**: <10% CPU usage

### Demo Deliverables
1. Live network monitoring display
2. Simulated attack detection demonstration
3. Automatic VPN protection trigger
4. Attack event timeline visualization
5. System architecture presentation

---

## � Inspiration: Wii-Secure

This project builds upon concepts from **Wii-Secure**, a network security toolkit featuring:
- VPN integration for secure connections
- Network traffic monitoring
- Desktop client interface

**Phantom-shroud's Innovation**:
- Adds real-time threat detection
- Implements active defence with honeypots
- Provides automated protection responses
- Includes comprehensive admin dashboard
- Built for rapid deployment (24-hour MVP)

---

## � Quick Start (Post-Hackathon)

```bash
# Clone repository
git clone https://github.com/Jaiyantan/Phantom-shroud.git
cd Phantom-shroud

# Backend setup
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Start backend services
python api/app.py

# Frontend setup (separate terminal)
cd dashboard
npm install
npm run dev

# Access dashboard
open http://localhost:5173
```

---

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- **Wii-Secure**: Foundation and inspiration
- **CICADA'25 Hackathon**: Platform and challenge
- **Open Source Community**: Tools and libraries

---

**Built with ❤️ in 24 hours for CICADA'25 Hackathon**

---

## 👥 Team
- **Jaiyantan S** 
- **Thirumurugan K**
- **Kabelan G K**
- **Ranen Joseph Solomon**

---

*Last Updated: October 30, 2025*  
*Status: Active Development - 24-Hour Sprint*
