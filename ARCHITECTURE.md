# Privacy Guard for Public Wi-Fi Networks - 24-Hour MVP Architecture

## Executive Summary

**Phantom-shroud** is a security solution designed and built within a **24-hour hackathon** to protect users on public Wi-Fi networks. This document outlines the MVP architecture focusing on rapid implementation of core defence mechanisms: network inspection, threat detection, VPN protection, deception capabilities, and real-time monitoring.

**Inspired by**: Wii-Secure project  
**Time Constraint**: 24 hours  
**Approach**: Functional MVP with demonstrable security features  
**Goal**: Protect public Wi-Fi users with automated threat detection and response

---

## MVP Directory Structure (24-Hour Build)

```
Phantom-shroud/
├── README.md                      # Project overview
├── LICENSE
├── requirements.txt               # Minimal dependencies
├── config/
│   ├── config.yaml                # System configuration
│   └── vpn_profiles/
│       └── default.ovpn           # OpenVPN config
├── core/                          # Core modules (simplified)
│   ├── __init__.py
│   ├── network_inspector.py       # Scapy packet capture
│   ├── dpi_engine.py              # Basic protocol analysis
│   ├── anomaly_detector.py        # Rule + simple ML detection
│   ├── vpn_manager.py             # OpenVPN controller
│   ├── honeypot.py                # Basic honeypot
│   └── threat_analyzer.py         # Event correlation
├── models/
│   └── isolation_forest.pkl       # Pre-trained anomaly detector
├── utils/
│   ├── __init__.py
│   ├─�� logger.py                  # Simple logging
│   └── network_utils.py           # Helper functions
├── api/
│   ├── app.py                     # Flask API server
│   └── routes.py                  # API endpoints
├── dashboard/                     # React dashboard (simplified)
│   ├── package.json
│   ├── vite.config.js
│   ├── index.html
│   ├── src/
│   │   ├── App.jsx                # Main component
│   │   ├── main.jsx
│   │   ├── components/
│   │   │   ├── NetworkStatus.jsx  # Live network display
│   │   │   ├── ThreatFeed.jsx     # Real-time threats
│   │   │   ├── VPNControl.jsx     # VPN on/off
│   │   │   ├── Stats.jsx          # Charts and metrics
│   │   │   └── AlertPanel.jsx     # Notifications
│   │   └── utils/
│   │       └── api.js             # API client
│   └── public/
├── tests/                         # Basic tests (optional)
│   └── test_core.py               # Smoke tests
├── logs/                          # Log files (auto-generated)
│   └── events.log
└── data/                          # Runtime data (auto-generated)
    ├── threats.json
    └── honeypot_logs.json
```

**File Count**: ~30 files (vs 150+ in full version)  
**Code Estimate**: ~2,850 lines (achievable in 24h)

---

## 24-Hour Component Architecture

### 1. Network Inspection System (`core/network_inspector.py`) - Hours 0-3

**MVP Scope**: Basic packet capture and flow tracking

**Key Features**:
- Scapy-based packet sniffing (no raw sockets needed)
- Single interface monitoring (auto-detect default)
- Basic flow tracking (src_ip, dst_ip, protocol)
- Queue packets for DPI processing

**Implementation** (Simplified):
```python
class NetworkInspector:
    def __init__(self):
        self.interface = self.detect_interface()
        self.flows = {}
    
    def start_capture(self):
        # Simple Scapy sniff
        sniff(iface=self.interface, prn=self.process_packet)
    
    def process_packet(self, packet):
        # Extract basic info and queue for DPI
        flow_id = (packet[IP].src, packet[IP].dst)
        self.flows[flow_id] = self.flows.get(flow_id, 0) + 1
```

**Time**: 3 hours  
**Complexity**: Low  
**Dependencies**: Scapy

---

### 2. Deep Packet Inspection Engine (`core/dpi_engine.py`) - Hours 3-6

**MVP Scope**: Essential protocol analysis

**Key Features**:
- Protocol identification (HTTP, HTTPS, DNS)
- Basic SSL/TLS check (port 443 detection)
- Simple feature extraction (~15 features)
- DNS query logging

**Implementation** (Simplified):
```python
class DPIEngine:
    def analyze_packet(self, packet):
        features = {
            'protocol': self.identify_protocol(packet),
            'size': len(packet),
            'ports': (packet.sport, packet.dport),
            'flags': packet.flags if TCP in packet else None
        }
        return features
    
    def identify_protocol(self, packet):
        if packet.haslayer(TCP):
            if packet[TCP].dport == 80: return 'HTTP'
            if packet[TCP].dport == 443: return 'HTTPS'
        if packet.haslayer(DNS): return 'DNS'
        return 'UNKNOWN'
```

**Time**: 3 hours  
**Complexity**: Low-Medium  
**Dependencies**: Scapy

---

### 3. Anomaly Detection (`core/anomaly_detector.py`) - Hours 6-10

**MVP Scope**: Rule-based + simple ML

**Detection Methods**:
1. **Rule-based** (Fast, reliable):
   - ARP spoofing: Detect duplicate MAC addresses
   - DNS hijacking: Check DNS response IPs
   - Port scan: Track connection attempts per IP
   
2. **ML-based** (Pre-trained Isolation Forest):
   - Load pre-trained model
   - Simple feature vector
   - Anomaly scoring

**Implementation** (Simplified):
```python
class AnomalyDetector:
    def __init__(self):
        self.model = joblib.load('models/isolation_forest.pkl')
        self.arp_cache = {}
    
    def detect(self, packet_features):
        # Rule-based checks
        if self.check_arp_spoofing(packet_features):
            return Alert('ARP_SPOOFING', 'HIGH')
        
        # ML-based
        score = self.model.score_samples([packet_features])
        if score < -0.5:  # Anomaly threshold
            return Alert('ANOMALY', 'MEDIUM')
    
    def check_arp_spoofing(self, features):
        # Simple duplicate IP-MAC check
        pass
```

**Time**: 4 hours  
**Complexity**: Medium  
**Dependencies**: Scikit-learn, pre-trained model

---

### 4. VPN Manager (`core/vpn_manager.py`) - Hours 10-12

**MVP Scope**: OpenVPN subprocess control

**Key Features**:
- Start/stop OpenVPN connections
- Automatic trigger on threat detection
- Basic kill switch (iptables DROP rules)
- Connection status checking

**Implementation** (Simplified):
```python
class VPNManager:
    def __init__(self, config_path='config/vpn_profiles/default.ovpn'):
        self.config = config_path
        self.process = None
    
    def connect(self):
        # Start OpenVPN subprocess
        self.process = subprocess.Popen(
            ['openvpn', '--config', self.config],
            stdout=subprocess.PIPE
        )
        self.enable_kill_switch()
    
    def disconnect(self):
        if self.process:
            self.process.terminate()
        self.disable_kill_switch()
    
    def enable_kill_switch(self):
        # Simple iptables rule
        subprocess.run(['iptables', '-P', 'OUTPUT', 'DROP'])
        subprocess.run(['iptables', '-A', 'OUTPUT', '-o', 'tun0', '-j', 'ACCEPT'])
```

**Time**: 2 hours  
**Complexity**: Low  
**Dependencies**: OpenVPN, iptables

**Inspiration**: Wii-Secure's VPN control, simplified for speed

---

### 5. Honeypot (`core/honeypot.py`) - Hours 12-14

**MVP Scope**: Basic SSH and HTTP honeypots

**Key Features**:
- Listen on common ports (22, 80)
- Log connection attempts
- Track attacker IPs
- Simple response (banner, fake login)

**Implementation** (Simplified):
```python
class Honeypot:
    def __init__(self, port=22, service='SSH'):
        self.port = port
        self.service = service
        self.interactions = []
    
    def start(self):
        sock = socket.socket()
        sock.bind(('0.0.0.0', self.port))
        sock.listen(5)
        while True:
            conn, addr = sock.accept()
            self.log_interaction(addr)
            self.send_fake_banner(conn)
    
    def log_interaction(self, addr):
        self.interactions.append({
            'ip': addr[0],
            'time': datetime.now(),
            'service': self.service
        })
```

**Time**: 2 hours  
**Complexity**: Low  
**Dependencies**: Python socket

---

### 6. Threat Analyzer (`core/threat_analyzer.py`) - Hours 14-16

**MVP Scope**: Simple event correlation

**Key Features**:
- Collect events from all modules
- Correlate by IP and timestamp
- Build basic attack timeline
- Severity scoring

**Implementation** (Simplified):
```python
class ThreatAnalyzer:
    def __init__(self):
        self.events = []
    
    def add_event(self, event):
        self.events.append(event)
        self.correlate_events()
    
    def correlate_events(self):
        # Group events by IP within time window
        incidents = {}
        for event in self.events[-100:]:  # Last 100 events
            ip = event.get('ip')
            if ip not in incidents:
                incidents[ip] = []
            incidents[ip].append(event)
        
        # Identify attack chains
        for ip, events in incidents.items():
            if len(events) > 3:  # Multiple suspicious events
                self.create_incident(ip, events)
```

---

### 7. API Backend (`api/app.py` + `routes.py`) - Hours 16-18

**MVP Scope**: Flask REST API with WebSocket

**Key Endpoints**:
```python
# Flask API
app = Flask(__name__)
socketio = SocketIO(app)

@app.route('/api/status')
def get_status():
    return {
        'network': network_inspector.get_stats(),
        'threats': anomaly_detector.get_recent_threats(),
        'vpn': vpn_manager.is_connected()
    }

@app.route('/api/vpn/connect', methods=['POST'])
def vpn_connect():
    vpn_manager.connect()
    return {'status': 'connecting'}

@app.route('/api/threats/recent')
def get_threats():
    return threat_analyzer.get_incidents()

# WebSocket for real-time updates
@socketio.on('connect')
def handle_connect():
    # Start sending real-time data
    emit_network_updates()
```

**Time**: 2 hours  
**Complexity**: Low  
**Dependencies**: Flask, Flask-SocketIO

---

### 8. Admin Dashboard (`dashboard/`) - Hours 18-24

**MVP Scope**: React SPA with real-time updates

**Key Components**:

```jsx
// App.jsx - Main Dashboard
function App() {
  const [networkStatus, setNetworkStatus] = useState({});
  const [threats, setThreats] = useState([]);
  const [vpnStatus, setVPNStatus] = useState(false);
  
  // WebSocket connection
  useEffect(() => {
    const socket = io('http://localhost:5000');
    socket.on('network_update', data => setNetworkStatus(data));
    socket.on('threat_detected', threat => setThreats([...threats, threat]));
  }, []);
  
  return (
    <div className="dashboard">
      <Header />
      <NetworkStatus data={networkStatus} />
      <ThreatFeed threats={threats} />
      <VPNControl status={vpnStatus} />
      <Stats />
    </div>
  );
}
```

**Components** (5 essential):
1. **NetworkStatus**: Live packet count, bandwidth, active flows
2. **ThreatFeed**: Real-time threat alerts with severity
3. **VPNControl**: Connect/disconnect button, status indicator
4. **Stats**: Simple charts (Chart.js line graph)
5. **AlertPanel**: Toast notifications for threats

**Time**: 6 hours  
**Complexity**: Medium  
**Dependencies**: React, Vite, Chart.js, Socket.IO-client

---

## Integration Flow (24-Hour Build)

```
┌──────────────────┐
│  Network Traffic │
└────────┬─────────┘
         ↓
┌────────────────────┐
│ Network Inspector  │  ← Scapy capture
└────────┬───────────┘
         ↓
┌────────────────────┐
│   DPI Engine       │  ← Protocol analysis
└────────┬───────────┘
         ↓
┌────────────────────┐
│ Anomaly Detector   │  ← Rule + ML detection
└────────┬───────────┘
         ↓ (If threat detected)
┌────────────────────┐
│   VPN Manager      │  ← Auto-connect
│   Honeypot         │  ← Log attacker
│   Threat Analyzer  │  ← Correlate events
└────────┬───────────┘
         ↓
┌────────────────────┐
│   API Backend      │  ← Flask + WebSocket
└────────┬───────────┘
         ↓
┌────────────────────┐
│  Admin Dashboard   │  ← React UI
└────────────────────┘
```

---

## 24-Hour Development Timeline

### Hour-by-Hour Breakdown

| Hours | Task | Deliverable | Priority |
|-------|------|-------------|----------|
| 0-3 | Network Inspector | Packet capture working | 🔴 Critical |
| 3-6 | DPI Engine | Protocol identification | 🔴 Critical |
| 6-10 | Anomaly Detector | Threat detection working | 🔴 Critical |
| 10-12 | VPN Manager | Auto-connect on threat | 🟡 High |
| 12-14 | Honeypot | Basic honeypot logging | 🟡 High |
| 14-16 | Threat Analyzer | Event correlation | 🟡 High |
| 16-18 | API Backend | Flask API + WebSocket | 🔴 Critical |
| 18-20 | Dashboard Core | React app + real-time data | 🔴 Critical |
| 20-22 | Dashboard UI | Charts, styling, UX | 🟢 Medium |
| 22-23 | Integration Testing | End-to-end flow | 🔴 Critical |
| 23-24 | Demo Prep | Documentation, presentation | 🟢 Medium |

### Parallel Tracks (if team >1)

**Track A** (Hours 0-12): Core backend (Inspector → DPI → Detector → VPN)  
**Track B** (Hours 12-18): Intelligence layer (Honeypot → Analyzer → API)  
**Track C** (Hours 18-24): Frontend (Dashboard → Integration → Testing)

---

## MVP Technology Stack (Simplified)

### Backend (Python)
- **Packet Capture**: Scapy (simple, no root needed for reading)
- **ML**: Scikit-learn (pre-trained Isolation Forest)
- **API**: Flask + Flask-SocketIO
- **VPN**: OpenVPN subprocess
- **Storage**: JSON files (no database needed for MVP)

### Frontend (JavaScript)
- **Framework**: React (via create-react-app or Vite)
- **UI**: Tailwind CSS (utility-first, fast)
- **Charts**: Chart.js (simple line/bar charts)
- **Real-time**: Socket.IO client
- **State**: React hooks (no Redux for MVP)

### Dependencies (Minimal)
```txt
# requirements.txt (~10 packages)
scapy==2.5.0
scikit-learn==1.3.0
flask==3.0.0
flask-socketio==5.3.0
flask-cors==4.0.0
pyyaml==6.0.1
```

### Deployment (MVP)
- **Local development**: Python venv + npm dev server
- **Demo**: Run on laptop with local network
- **Optional**: Docker Compose for easier setup

---

## Security Considerations

1. **Privilege Management**: Run packet capture with minimal privileges using capabilities
2. **Data Encryption**: All sensitive data encrypted at rest and in transit
3. **Secure Configuration**: API tokens, VPN credentials stored securely
4. **Audit Logging**: Comprehensive logging of all security events
5. **Input Validation**: Strict validation of all user inputs and network data
6. **Rate Limiting**: Prevent DoS on API endpoints
7. **Secure Defaults**: Conservative security policies by default

---

## MVP Performance Targets (Realistic for 24h)

- **Packet Processing**: 1,000+ packets/second
- **Detection Latency**: <2 seconds from capture to alert
- **API Response Time**: <500ms for queries
- **Dashboard Updates**: 1-2 second refresh
- **System Overhead**: <10% CPU usage

---

## MVP Success Criteria (24-Hour Goals)

### Functional Requirements ✅
- [x] Capture network packets in real-time
- [x] Detect 3+ attack types (ARP spoofing, DNS hijacking, anomalies)
- [x] Automatic VPN connection on threat
- [x] Basic honeypot logging
- [x] Live dashboard with real-time updates

### Performance Targets (Realistic)
- **Packet Processing**: 1,000+ pps
- **Detection Latency**: <2 seconds
- **Dashboard Refresh**: 1-2 seconds
- **System Overhead**: <10% CPU

### Demo Deliverables
1. ✅ Live network monitoring
2. ✅ Simulated attack detection
3. ✅ Automatic VPN trigger
4. ✅ Attack timeline visualization
5. ✅ Working end-to-end system

---

## Inspiration from Wii-Secure

**Phantom-shroud** builds upon **Wii-Secure**, taking inspiration from:
- VPN integration and management
- Network traffic monitoring approach
- Desktop client interface concepts

**Key Innovations** (24-hour additions):
- Real-time threat detection engine
- Automated protection responses
- Active defence with honeypots
- Comprehensive monitoring dashboard
- Event correlation and analysis

**Comparison**:

| Feature | Wii-Secure | Phantom-shroud MVP |
|---------|------------|-------------------|
| **VPN** | ✅ Desktop control | ✅ Auto-trigger + API |
| **Detection** | ❌ None | ✅ Rule + ML based |
| **Honeypot** | ❌ None | ✅ SSH + HTTP |
| **Dashboard** | ⚠️ Desktop only | ✅ Web + Real-time |
| **API** | ⚠️ Basic | ✅ REST + WebSocket |
| **Time to Build** | Unknown | 24 hours |

---

## Risk Management (24-Hour Constraints)

### High-Risk Items
- **Packet capture permissions**: May need sudo/root
  - *Mitigation*: Test early, have fallback pcap reading
- **VPN configuration**: OpenVPN setup complexity
  - *Mitigation*: Pre-configure profiles, test connections
- **ML model performance**: Inference speed
  - *Mitigation*: Use pre-trained, simple models

### Time Savers
- Use pre-trained ML models (no training time)
- Copy-paste Scapy examples
- Bootstrap React dashboard (Vite template)
- Skip authentication for MVP
- Use JSON files instead of database
- Minimal error handling (demo-focused)

---

## Quick Start (Post-Hackathon)

```bash
# 1. Clone and setup backend
git clone https://github.com/Jaiyantan/Phantom-shroud.git
cd Phantom-shroud
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 2. Start core services
python core/network_inspector.py &
python api/app.py &

# 3. Setup and start dashboard
cd dashboard
npm install
npm run dev

# 4. Access dashboard
open http://localhost:5173
```

---

## Conclusion

This 24-hour MVP architecture provides a **functional demonstration** of public Wi-Fi security with:
- ✅ Real-time threat detection
- ✅ Automated VPN protection
- ✅ Basic deception capabilities
- ✅ Live monitoring dashboard
- ✅ End-to-end integration

**Scope**: Simplified but complete system  
**Goal**: Demonstrable protection in 24 hours  
**Foundation**: Builds on Wii-Secure concepts  
**Innovation**: Adds active defence and automation

The modular design allows for **future expansion** into production-grade features post-hackathon.

**Hackathon Constraints**:
- **Timeline**: 24 hours for MVP
- **Team Size**: 1-3 developers (parallel development tracks)
- **Technology Maturity**: High (leveraging proven, simple technologies)
- **Risk Level**: Low (simplified implementations, rapid prototyping)

---

*Document Version*: 1.0  
*Last Updated*: October 30, 2025  
*Author*: Privacy Guard Development Team
