# Network Inspection System - Phase 1 Implementation

## Overview

Phase 1 of the Network Inspection System provides comprehensive packet capture, traffic parsing, and flow tracking capabilities. This is the foundation for real-time network monitoring and threat detection.

## Components

### 1. Interface Manager (`core/network/interface.py`)
Manages network interfaces and provides interface information.

**Features:**
- Auto-discovery of network interfaces
- Interface information (IP addresses, MAC, etc.)
- Default interface detection
- Wireless interface identification
- Monitorable interface filtering

**Usage:**
```python
from core.network.interface import InterfaceManager

manager = InterfaceManager()

# List all interfaces
interfaces = manager.list_interfaces()

# Get default interface
default = manager.get_default_interface()

# Get interface details
info = manager.get_interface_info('eth0')
```

### 2. Packet Capture (`core/network/capture.py`)
Handles real-time packet capture using Scapy.

**Features:**
- Multi-threaded packet capture
- BPF (Berkeley Packet Filter) support
- Callback registration for custom processing
- Packet buffering with queue management
- Capture statistics and monitoring

**Usage:**
```python
from core.network.capture import PacketCapture

capture = PacketCapture(interface='eth0', buffer_size=1000)

# Set filter
capture.set_filter('tcp port 80')

# Register callback
def process_packet(packet):
    print(f"Captured packet: {packet.summary()}")

capture.register_callback(process_packet)

# Start capture
capture.start()

# Get statistics
stats = capture.get_statistics()

# Stop capture
capture.stop()
```

### 3. Traffic Parser (`core/network/parser.py`)
Parses network packets and extracts protocol information.

**Features:**
- Multi-layer protocol parsing (Ethernet, IP, TCP, UDP, ICMP, ARP, DNS, HTTP)
- 5-tuple extraction (src_ip, dst_ip, src_port, dst_port, protocol)
- TCP flags analysis
- DNS query/response parsing
- HTTP request/response parsing
- Payload detection

**Usage:**
```python
from core.network.parser import TrafficParser

parser = TrafficParser()

# Parse a packet
parsed = parser.parse_packet(packet)

print(f"Protocols: {parsed['protocols']}")
print(f"Source IP: {parsed['ip']['src']}")
print(f"Destination IP: {parsed['ip']['dst']}")

# Extract 5-tuple
five_tuple = parser.extract_five_tuple(parsed)
```

### 4. Flow Tracker (`core/network/flow_tracker.py`)
Tracks network flows and maintains flow statistics.

**Features:**
- Flow creation and tracking
- Flow timeout and expiration
- Flow statistics (packets, bytes, duration)
- Top talkers identification
- Protocol distribution analysis
- IP-based flow filtering

**Usage:**
```python
from core.network.flow_tracker import FlowTracker

tracker = FlowTracker(timeout=300)

# Process packets
tracker.process_packet(parsed_packet)

# Get active flows
active_flows = tracker.get_active_flows(limit=50)

# Get top talkers
top_talkers = tracker.get_top_talkers(limit=10, by='bytes')

# Get flows by IP
flows = tracker.get_flows_by_ip('192.168.1.100')

# Get statistics
stats = tracker.get_statistics()
```

### 5. Network Inspector (`core/network_inspector.py`)
Main orchestrator that combines all components.

**Features:**
- Integrated packet capture, parsing, and flow tracking
- Real-time statistics
- Protocol distribution analysis
- Interface management
- Automatic flow cleanup
- Comprehensive monitoring

**Usage:**
```python
from core.network_inspector import NetworkInspector

# Initialize (auto-detects interface)
inspector = NetworkInspector(auto_start=True)

# Or specify interface
inspector = NetworkInspector(interface='eth0', auto_start=False)

# Start inspection
inspector.start()

# Get statistics
stats = inspector.get_stats()

# Get active flows
flows = inspector.get_active_flows(limit=50)

# Get top talkers
top = inspector.get_top_talkers(limit=10, by='bytes')

# Stop inspection
inspector.stop()
```

## API Endpoints

All endpoints are prefixed with `/api/network`

### GET `/status`
Get network inspection status and statistics

**Response:**
```json
{
  "is_running": true,
  "interface": "eth0",
  "elapsed_time": 120.45,
  "capture": {
    "packet_count": 15234,
    "dropped_packets": 0
  },
  "flows": {
    "active_flows": 45,
    "total_flows": 123,
    "total_packets": 15234,
    "total_bytes": 12345678
  },
  "protocols": {
    "TCP": 35,
    "UDP": 8,
    "ICMP": 2
  },
  "packets_per_second": 126.95
}
```

### POST `/start`
Start network inspection

**Response:**
```json
{
  "message": "Network inspection started",
  "status": "running"
}
```

### POST `/stop`
Stop network inspection

**Response:**
```json
{
  "message": "Network inspection stopped",
  "status": "stopped"
}
```

### GET `/flows`
Get active network flows

**Query Parameters:**
- `limit` (int, default: 50) - Maximum number of flows to return

**Response:**
```json
{
  "flows": [
    {
      "src_ip": "192.168.1.100",
      "dst_ip": "8.8.8.8",
      "src_port": 54321,
      "dst_port": 53,
      "protocol": "UDP",
      "packet_count": 5,
      "byte_count": 420,
      "duration": 2.5,
      "start_time": "2025-10-30T10:00:00",
      "last_seen": "2025-10-30T10:00:02.5"
    }
  ],
  "count": 1
}
```

### GET `/flows/top`
Get top talkers (most active flows)

**Query Parameters:**
- `limit` (int, default: 10) - Number of top flows
- `by` (str, default: 'bytes') - Sort by 'bytes' or 'packets'

**Response:**
```json
{
  "top_flows": [...],
  "count": 10,
  "sorted_by": "bytes"
}
```

### GET `/flows/ip/<ip_address>`
Get all flows involving a specific IP address

**Response:**
```json
{
  "ip_address": "192.168.1.100",
  "flows": [...],
  "count": 5
}
```

### GET `/protocols`
Get protocol distribution

**Response:**
```json
{
  "distribution": {
    "TCP": 35,
    "UDP": 10,
    "ICMP": 2
  },
  "percentages": {
    "TCP": 74.47,
    "UDP": 21.28,
    "ICMP": 4.26
  },
  "total_flows": 47
}
```

### GET `/interfaces`
Get list of available network interfaces

**Response:**
```json
{
  "interfaces": ["eth0", "wlan0"],
  "count": 2
}
```

### GET `/interfaces/<iface_name>`
Get detailed information about a specific interface

**Response:**
```json
{
  "name": "eth0",
  "addresses": {
    "ipv4": "192.168.1.100",
    "netmask": "255.255.255.0",
    "mac": "00:11:22:33:44:55"
  }
}
```

### POST `/filter`
Set BPF filter for packet capture

**Request:**
```json
{
  "filter": "tcp port 80"
}
```

**Response:**
```json
{
  "message": "Capture filter set successfully",
  "filter": "tcp port 80"
}
```

## Frontend Component

A React component `LiveTraffic.jsx` is provided for displaying real-time network traffic in the dashboard.

**Features:**
- Real-time flow updates (2-second refresh)
- Start/Stop inspection controls
- Statistics cards
- Flow table with sorting
- Protocol color coding

**Usage:**
```jsx
import LiveTraffic from './components/LiveTraffic';

function App() {
  return (
    <div>
      <LiveTraffic />
    </div>
  );
}
```

## Testing

Run the unit tests:

```bash
cd backend
pytest tests/test_network_inspection.py -v
```

## Dependencies

Required Python packages (already in `requirements.txt`):
- scapy==2.5.0
- pyshark==0.6
- dpkt==1.9.8
- netifaces==0.11.0

Optional ML dependencies (Phase 3+, install from `requirements-ml.txt`):
- scikit-learn==1.3.0
- pandas==2.0.3
- numpy==1.24.3

Python version compatibility:
- Recommended: Python 3.10–3.12
- Python 3.14: Base dependencies work. ML stack may fail to build until upstream wheels are available.

## Security Considerations

**Important:** Packet capture requires elevated privileges (root/sudo) on most systems.

**Options:**
1. Run with sudo: `sudo python api/app.py`
2. Grant capabilities: `sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)`
3. Run in Docker with appropriate capabilities

## Performance

Phase 1 is designed to handle:
- 1000+ packets/second
- 500+ concurrent flows
- Multiple network interfaces
- Real-time processing with minimal latency

## Next Steps

Phase 2 will add:
- Deep Packet Inspection (DPI) engine
- Protocol-specific analyzers
- Pattern matching
- Content inspection
- Advanced filtering

## Troubleshooting

### "Permission denied" error
You need root privileges for packet capture:
```bash
sudo python api/app.py
```

### No packets captured
1. Check if the interface exists: `ip link show`
2. Verify interface is up: `ip link set eth0 up`
3. Check firewall rules
4. Try a different interface

### High memory usage
Reduce buffer size in `PacketCapture` initialization:
```python
capture = PacketCapture(interface='eth0', buffer_size=500)
```

### Flows not appearing
1. Ensure inspection is started
2. Check if traffic is passing through the interface
3. Verify BPF filter (if set)
4. Check flow timeout settings

## Contributing

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for guidelines.

## License

See [LICENSE](../../LICENSE) for details.
