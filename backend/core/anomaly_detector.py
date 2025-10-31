"""
Anomaly Detection Module
Enhanced with Joseph's MITM Detection Algorithms

Features:
- Rule-based detection (ARP spoofing, DNS hijacking, port scanning)
- TTL baseline analysis for proxy detection
- Network latency monitoring
- Duplicate IP/MAC detection
- Statistical anomaly detection (Isolation Forest)
- Signature matching for known attacks
- Real-time alerting
- Target: <2s detection latency

Credits:
- Advanced MITM detection algorithms by Joseph
- Integrated from Joseph's work/mitm.py
"""

import logging
from collections import defaultdict
from datetime import datetime
import pickle
import time
import statistics
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# ============================================================================
# ENHANCED DATA STRUCTURES
# ============================================================================

@dataclass
class NetworkMetrics:
    """Network metrics for anomaly detection"""
    ttl_values: List[int] = field(default_factory=list)
    latency_values: List[float] = field(default_factory=list)
    packet_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    last_updated: float = field(default_factory=time.time)


@dataclass
class ARPRecord:
    """ARP table entry tracking"""
    ip: str
    mac: str
    timestamp: float
    interface: Optional[str] = None


class Alert:
    """Simple alert object"""
    def __init__(self, alert_type, severity, details=None):
        self.type = alert_type
        self.severity = severity
        self.details = details or {}
        self.timestamp = datetime.now()
    
    def to_dict(self):
        return {
            'type': self.type,
            'severity': self.severity,
            'details': self.details,
            'timestamp': self.timestamp.isoformat()
        }


class AnomalyDetector:
    """
    Enhanced hybrid anomaly detection: Rule-based + ML-based + Network Metrics
    
    Features:
    - ARP spoofing detection with duplicate IP/MAC tracking
    - TTL baseline analysis for MITM proxy detection
    - Network latency monitoring and spike detection
    - DNS hijacking detection
    - Port scanning detection
    - Statistical anomaly detection (ML-based)
    """
    
    def __init__(self, model_path='models/isolation_forest.pkl', 
                 ttl_baseline=64, ttl_threshold=10, 
                 latency_spike_threshold=2.0):
        """
        Initialize Enhanced Anomaly Detector
        
        Args:
            model_path: Path to pre-trained ML model
            ttl_baseline: Expected TTL value (64 for Linux, 128 for Windows)
            ttl_threshold: Maximum TTL deviation before alert
            latency_spike_threshold: Latency spike multiplier threshold
        """
        self.model_path = model_path
        self.model = self.load_model()
        
        # ARP tracking
        self.arp_cache = {}  # IP -> MAC mapping
        self.arp_history: Dict[str, List[ARPRecord]] = defaultdict(list)
        self.locked_arps: Dict[str, str] = {}  # IP -> MAC for critical hosts
        
        # Duplicate detection
        self.ip_to_macs: Dict[str, Set[str]] = defaultdict(set)
        self.mac_to_ips: Dict[str, Set[str]] = defaultdict(set)
        
        # Network metrics
        self.ttl_baseline = ttl_baseline
        self.ttl_threshold = ttl_threshold
        self.latency_spike_threshold = latency_spike_threshold
        self.network_metrics: Dict[str, NetworkMetrics] = defaultdict(NetworkMetrics)
        
        # DNS tracking
        self.dns_cache = {}  # Domain -> IP mapping
        self.known_good_dns: Dict[str, Set[str]] = defaultdict(set)
        
        # Connection tracking
        self.connection_tracker = defaultdict(list)  # IP -> connection attempts
        self.port_access_history: Dict[str, List[tuple]] = defaultdict(list)  # IP -> (port, timestamp)
        self.flagged_scanners: Set[str] = set()
        
        # Alerts
        self.recent_alerts = []
        self.alert_counts = defaultdict(int)
        
        logger.info("Enhanced AnomalyDetector initialized with MITM detection")
    
    def load_model(self):
        """
        Load pre-trained ML model
        
        Returns:
            object: Loaded model or None
        """
        try:
            # TODO: Load actual model when available
            # with open(self.model_path, 'rb') as f:
            #     return pickle.load(f)
            logger.warning("ML model not loaded (placeholder)")
            return None
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return None
    
    def detect(self, packet_features):
        """
        Main detection method combining rule-based, network metrics, and ML
        
        Detection Pipeline:
        1. Rule-based checks (ARP, DNS, port scan) - High confidence
        2. Network metrics (TTL, latency) - MITM indicators
        3. ML-based anomaly detection - Statistical anomalies
        
        Args:
            packet_features: Dictionary of packet features
            
        Returns:
            Alert or None
        """
        # Rule-based checks (fast, high confidence)
        alert = self.check_rule_based(packet_features)
        if alert:
            self.recent_alerts.append(alert)
            self.alert_counts[alert.type] += 1
            return alert
        
        # Network metrics checks (TTL and latency anomalies)
        alert = self.check_network_metrics(packet_features)
        if alert:
            self.recent_alerts.append(alert)
            self.alert_counts[alert.type] += 1
            return alert
        
        # ML-based check (slower, probabilistic)
        if self.model:
            alert = self.check_ml_based(packet_features)
            if alert:
                self.recent_alerts.append(alert)
                self.alert_counts[alert.type] += 1
                return alert
        
        return None
    
    def check_network_metrics(self, features):
        """
        Check network metrics for MITM indicators
        
        Args:
            features: Packet features dict
            
        Returns:
            Alert or None
        """
        # Check TTL anomalies
        if self.check_ttl_anomaly(features):
            return Alert(
                'TTL_ANOMALY',
                'MEDIUM',
                {
                    'description': 'TTL deviation detected - possible proxy or MITM',
                    'src_ip': features.get('src_ip'),
                    'ttl': features.get('ttl')
                }
            )
        
        # Check latency spikes
        if self.check_latency_spike(features):
            return Alert(
                'LATENCY_SPIKE',
                'LOW',
                {
                    'description': 'Latency spike detected',
                    'src_ip': features.get('src_ip'),
                    'latency': features.get('latency')
                }
            )
        
        return None
    
    def check_rule_based(self, features):
        """
        Rule-based anomaly detection
        
        Args:
            features: Packet features dict
            
        Returns:
            Alert or None
        """
        # Check for ARP spoofing
        if self.check_arp_spoofing(features):
            return Alert(
                'ARP_SPOOFING',
                'HIGH',
                {'description': 'Duplicate IP-MAC mapping detected'}
            )
        
        # Check for DNS hijacking
        if self.check_dns_hijacking(features):
            return Alert(
                'DNS_HIJACKING',
                'HIGH',
                {'description': 'Suspicious DNS response detected'}
            )
        
        # Check for port scanning
        if self.check_port_scan(features):
            return Alert(
                'PORT_SCAN',
                'MEDIUM',
                {'description': 'Multiple port connection attempts detected'}
            )
        
        return None
    
    def check_arp_spoofing(self, features):
        """
        Enhanced ARP spoofing detection with duplicate IP/MAC tracking
        
        Detects:
        - Duplicate IP addresses with different MACs
        - MAC address changes for locked entries (gateway)
        - Suspicious rapid ARP changes
        
        Args:
            features: Packet features dict with 'src_ip', 'src_mac'
            
        Returns:
            bool: True if ARP spoofing detected
        """
        src_ip = features.get('src_ip')
        src_mac = features.get('src_mac')
        
        if not src_ip or not src_mac:
            return False
        
        # Update tracking structures
        current_time = time.time()
        self.ip_to_macs[src_ip].add(src_mac)
        self.mac_to_ips[src_mac].add(src_ip)
        
        # Record in ARP history
        arp_record = ARPRecord(
            ip=src_ip,
            mac=src_mac,
            timestamp=current_time,
            interface=features.get('interface')
        )
        self.arp_history[src_ip].append(arp_record)
        
        # Clean old history (keep last 100 records per IP)
        if len(self.arp_history[src_ip]) > 100:
            self.arp_history[src_ip] = self.arp_history[src_ip][-100:]
        
        # Check 1: Duplicate IP with multiple MACs (CRITICAL)
        if len(self.ip_to_macs[src_ip]) > 1:
            logger.warning(f"Duplicate IP detected: {src_ip} has MACs {self.ip_to_macs[src_ip]}")
            return True
        
        # Check 2: Locked entry violation (gateway spoofing)
        if src_ip in self.locked_arps:
            expected_mac = self.locked_arps[src_ip]
            if src_mac != expected_mac:
                logger.critical(f"ARP spoofing: {src_ip} changed from {expected_mac} to {src_mac}")
                return True
        
        # Check 3: Rapid MAC changes (3+ changes in short time)
        recent_records = [r for r in self.arp_history[src_ip] 
                         if current_time - r.timestamp < 60]
        unique_macs = {r.mac for r in recent_records}
        if len(unique_macs) >= 3:
            logger.warning(f"Suspicious ARP changes for {src_ip}: {unique_macs}")
            return True
        
        # Update ARP cache
        old_mac = self.arp_cache.get(src_ip)
        if old_mac and old_mac != src_mac:
            logger.info(f"ARP change detected: {src_ip} from {old_mac} to {src_mac}")
        self.arp_cache[src_ip] = src_mac
        
        return False
    
    def lock_arp_entry(self, ip: str, mac: str):
        """
        Lock an ARP entry (typically for gateway) to prevent spoofing
        
        Args:
            ip: IP address to lock
            mac: Expected MAC address
        """
        self.locked_arps[ip] = mac
        logger.info(f"Locked ARP entry: {ip} -> {mac}")
    
    def check_dns_hijacking(self, features):
        """
        Enhanced DNS hijacking detection
        
        Detects:
        - DNS responses that differ from known good IPs
        - Suspicious changes in DNS resolution
        - Private IP responses for public domains
        
        Args:
            features: Packet features dict with 'dns_query', 'dns_response'
            
        Returns:
            bool: True if DNS hijacking detected
        """
        domain = features.get('dns_query')
        response_ip = features.get('dns_response')
        
        if not domain or not response_ip:
            return False
        
        # Check 1: Compare with known good DNS entries
        if domain in self.known_good_dns:
            known_ips = self.known_good_dns[domain]
            if response_ip not in known_ips and len(known_ips) > 0:
                logger.warning(f"DNS mismatch: {domain} resolved to {response_ip}, expected {known_ips}")
                return True
        
        # Check 2: Detect private IP for public domains
        if self._is_public_domain(domain) and self._is_private_ip(response_ip):
            logger.warning(f"Suspicious DNS: public domain {domain} resolved to private IP {response_ip}")
            return True
        
        # Check 3: Track DNS changes
        old_ip = self.dns_cache.get(domain)
        if old_ip and old_ip != response_ip:
            logger.info(f"DNS change detected: {domain} from {old_ip} to {response_ip}")
            # If we've seen this domain before and IP changed, might be suspicious
            if domain in self.known_good_dns:
                return True
        
        # Update cache
        self.dns_cache[domain] = response_ip
        self.known_good_dns[domain].add(response_ip)
        
        return False
    
    def _is_public_domain(self, domain: str) -> bool:
        """Check if domain is likely public (not .local, .lan, etc.)"""
        private_tlds = ['.local', '.lan', '.internal', '.intranet']
        return not any(domain.endswith(tld) for tld in private_tlds)
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        try:
            parts = [int(p) for p in ip.split('.')]
            if parts[0] == 10:
                return True
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            if parts[0] == 192 and parts[1] == 168:
                return True
            if parts[0] == 127:  # Localhost
                return True
        except:
            pass
        return False
    
    def check_port_scan(self, features):
        """
        Enhanced port scanning detection
        
        Detects:
        - Multiple port access attempts in short time window
        - Sequential port scanning patterns
        - Previously flagged scanner IPs
        
        Args:
            features: Packet features dict with 'src_ip', 'dst_port'
            
        Returns:
            bool: True if port scan detected
        """
        src_ip = features.get('src_ip')
        dst_port = features.get('dst_port')
        
        if not src_ip:
            return False
        
        # Check if already flagged
        if src_ip in self.flagged_scanners:
            return True
        
        current_time = time.time()
        
        # Track port access with timestamp
        if dst_port:
            self.port_access_history[src_ip].append((dst_port, current_time))
        
        # Clean old history (keep last 60 seconds)
        self.port_access_history[src_ip] = [
            (port, ts) for port, ts in self.port_access_history[src_ip]
            if current_time - ts < 60
        ]
        
        # Also track general connection attempts
        self.connection_tracker[src_ip].append(datetime.now())
        recent = [t for t in self.connection_tracker[src_ip] 
                  if (datetime.now() - t).seconds < 60]
        self.connection_tracker[src_ip] = recent
        
        # Detection criteria
        recent_ports = [port for port, ts in self.port_access_history[src_ip]]
        unique_ports = set(recent_ports)
        
        # Threshold 1: 5+ unique ports in 60 seconds
        if len(unique_ports) >= 5:
            logger.warning(f"Port scan detected: {src_ip} accessed {len(unique_ports)} unique ports")
            self.flagged_scanners.add(src_ip)
            return True
        
        # Threshold 2: 10+ connection attempts regardless of port
        if len(recent) > 10:
            logger.warning(f"High connection rate: {src_ip} made {len(recent)} attempts")
            self.flagged_scanners.add(src_ip)
            return True
        
        # Threshold 3: Sequential port pattern (e.g., 80, 81, 82...)
        if len(unique_ports) >= 3:
            sorted_ports = sorted(unique_ports)
            is_sequential = all(
                sorted_ports[i+1] - sorted_ports[i] <= 2 
                for i in range(len(sorted_ports)-1)
            )
            if is_sequential:
                logger.warning(f"Sequential port scan: {src_ip} scanned ports {sorted_ports}")
                self.flagged_scanners.add(src_ip)
                return True
        
        return False
    
    def check_ttl_anomaly(self, features):
        """
        Detect TTL anomalies indicating proxy or MITM
        
        TTL (Time To Live) changes can indicate:
        - Proxy server insertion
        - VPN/tunnel interception
        - Network path changes
        
        Args:
            features: Packet features dict with 'src_ip', 'ttl'
            
        Returns:
            bool: True if TTL anomaly detected
        """
        src_ip = features.get('src_ip')
        ttl = features.get('ttl')
        
        if not src_ip or ttl is None:
            return False
        
        # Get or create metrics for this IP
        metrics = self.network_metrics[src_ip]
        metrics.ttl_values.append(ttl)
        metrics.last_updated = time.time()
        
        # Keep last 100 values
        if len(metrics.ttl_values) > 100:
            metrics.ttl_values = metrics.ttl_values[-100:]
        
        # Need at least 5 samples for baseline
        if len(metrics.ttl_values) < 5:
            return False
        
        # Calculate statistics
        avg_ttl = statistics.mean(metrics.ttl_values[-10:])
        deviation = abs(ttl - avg_ttl)
        
        # Check for significant deviation
        if deviation > self.ttl_threshold:
            logger.warning(
                f"TTL anomaly: {src_ip} current={ttl}, avg={avg_ttl:.1f}, "
                f"deviation={deviation:.1f} (threshold={self.ttl_threshold})"
            )
            return True
        
        # Check for baseline deviation
        if abs(ttl - self.ttl_baseline) > self.ttl_threshold:
            logger.info(
                f"TTL baseline deviation: {src_ip} ttl={ttl}, "
                f"baseline={self.ttl_baseline}"
            )
        
        return False
    
    def check_latency_spike(self, features):
        """
        Detect latency spikes indicating network issues or MITM
        
        Sudden latency increases can indicate:
        - MITM proxy processing
        - Network congestion
        - Routing changes
        
        Args:
            features: Packet features dict with 'src_ip', 'latency'
            
        Returns:
            bool: True if latency spike detected
        """
        src_ip = features.get('src_ip')
        latency = features.get('latency')
        
        if not src_ip or latency is None:
            return False
        
        # Get or create metrics
        metrics = self.network_metrics[src_ip]
        metrics.latency_values.append(latency)
        metrics.last_updated = time.time()
        
        # Keep last 100 values
        if len(metrics.latency_values) > 100:
            metrics.latency_values = metrics.latency_values[-100:]
        
        # Need at least 10 samples for baseline
        if len(metrics.latency_values) < 10:
            return False
        
        # Calculate average latency
        avg_latency = statistics.mean(metrics.latency_values[-10:])
        
        # Check for spike (current latency >> average)
        if latency > avg_latency * self.latency_spike_threshold:
            spike_ratio = latency / avg_latency if avg_latency > 0 else 0
            logger.warning(
                f"Latency spike: {src_ip} current={latency:.2f}ms, "
                f"avg={avg_latency:.2f}ms, spike_ratio={spike_ratio:.2f}x"
            )
            return True
        
        return False
    
    def check_ml_based(self, features):
        """
        ML-based anomaly detection using Isolation Forest
        
        Args:
            features: Packet features dict
            
        Returns:
            Alert or None
        """
        if not self.model:
            return None
        
        try:
            # TODO: Extract feature vector for ML model
            # feature_vector = self.extract_ml_features(features)
            # score = self.model.score_samples([feature_vector])
            
            # Anomaly threshold
            # if score < -0.5:
            #     return Alert(
            #         'ANOMALY',
            #         'MEDIUM',
            #         {'score': float(score), 'description': 'Statistical anomaly detected'}
            #     )
            pass
        except Exception as e:
            logger.error(f"ML detection error: {e}")
        
        return None
    
    def get_recent_threats(self, limit=10):
        """
        Get recent threat alerts
        
        Args:
            limit: Number of alerts to return
            
        Returns:
            list: Recent alerts
        """
        return [alert.to_dict() for alert in self.recent_alerts[-limit:]]
    
    def get_statistics(self):
        """
        Get comprehensive detection statistics
        
        Returns:
            dict: Enhanced statistics
        """
        alert_types = defaultdict(int)
        for alert in self.recent_alerts:
            alert_types[alert.type] += 1
        
        return {
            'total_alerts': len(self.recent_alerts),
            'alert_types': dict(alert_types),
            'alert_counts': dict(self.alert_counts),
            'model_loaded': self.model is not None,
            'arp_tracking': {
                'cached_entries': len(self.arp_cache),
                'locked_entries': len(self.locked_arps),
                'duplicate_ips': len([ip for ip, macs in self.ip_to_macs.items() if len(macs) > 1]),
                'duplicate_macs': len([mac for mac, ips in self.mac_to_ips.items() if len(ips) > 1])
            },
            'network_metrics': {
                'tracked_hosts': len(self.network_metrics),
                'ttl_baseline': self.ttl_baseline,
                'ttl_threshold': self.ttl_threshold
            },
            'port_scan': {
                'flagged_scanners': len(self.flagged_scanners),
                'monitored_ips': len(self.port_access_history)
            },
            'dns_tracking': {
                'cached_domains': len(self.dns_cache),
                'known_good_entries': len(self.known_good_dns)
            }
        }
    
    def get_network_metrics_stats(self, ip: str = None):
        """
        Get network metrics statistics for specific IP or all
        
        Args:
            ip: Optional IP address to get stats for
            
        Returns:
            dict: Metrics statistics
        """
        if ip:
            if ip not in self.network_metrics:
                return {}
            
            metrics = self.network_metrics[ip]
            result = {'ip': ip}
            
            if metrics.ttl_values:
                result['ttl'] = {
                    'current': metrics.ttl_values[-1],
                    'average': statistics.mean(metrics.ttl_values),
                    'min': min(metrics.ttl_values),
                    'max': max(metrics.ttl_values),
                    'stdev': statistics.stdev(metrics.ttl_values) if len(metrics.ttl_values) > 1 else 0
                }
            
            if metrics.latency_values:
                result['latency'] = {
                    'current': metrics.latency_values[-1],
                    'average': statistics.mean(metrics.latency_values),
                    'min': min(metrics.latency_values),
                    'max': max(metrics.latency_values),
                    'stdev': statistics.stdev(metrics.latency_values) if len(metrics.latency_values) > 1 else 0
                }
            
            return result
        else:
            # Return stats for all tracked IPs
            return {
                ip: self.get_network_metrics_stats(ip)
                for ip in self.network_metrics.keys()
            }
    
    def get_suspicious_ips(self):
        """
        Get list of all suspicious IP addresses
        
        Returns:
            dict: Categorized suspicious IPs
        """
        return {
            'port_scanners': list(self.flagged_scanners),
            'duplicate_ip_sources': [
                ip for ip, macs in self.ip_to_macs.items() 
                if len(macs) > 1
            ],
            'arp_spoofing_suspects': [
                ip for ip in self.arp_cache.keys()
                if len(self.arp_history[ip]) > 10  # Active in ARP
            ]
        }
    
    def clear_flagged_ip(self, ip: str):
        """
        Clear an IP from flagged scanner list (after investigation)
        
        Args:
            ip: IP address to clear
        """
        self.flagged_scanners.discard(ip)
        logger.info(f"Cleared flagged IP: {ip}")
    
    def reset_statistics(self):
        """Reset all tracking statistics (useful for testing)"""
        self.recent_alerts = []
        self.alert_counts = defaultdict(int)
        self.flagged_scanners = set()
        self.ip_to_macs = defaultdict(set)
        self.mac_to_ips = defaultdict(set)
        logger.info("Statistics reset")


if __name__ == "__main__":
    # Enhanced test code
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print("=" * 80)
    print("Enhanced AnomalyDetector - MITM Detection Test")
    print("=" * 80)
    print()
    
    # Initialize detector
    detector = AnomalyDetector(ttl_baseline=64, ttl_threshold=10)
    print("[✓] Enhanced AnomalyDetector initialized")
    print()
    
    # Test 1: ARP spoofing detection
    print("[TEST 1] ARP Spoofing Detection")
    print("-" * 40)
    
    # Lock gateway
    detector.lock_arp_entry("192.168.1.1", "aa:bb:cc:dd:ee:ff")
    
    # Normal traffic
    result = detector.detect({
        'src_ip': '192.168.1.1',
        'src_mac': 'aa:bb:cc:dd:ee:ff'
    })
    print(f"Normal gateway traffic: {result}")
    
    # Spoofed gateway
    result = detector.detect({
        'src_ip': '192.168.1.1',
        'src_mac': '11:22:33:44:55:66'  # Different MAC!
    })
    print(f"Spoofed gateway: {result.type if result else 'None'}")
    print()
    
    # Test 2: Port scanning detection
    print("[TEST 2] Port Scan Detection")
    print("-" * 40)
    attacker_ip = "10.0.0.100"
    for port in [80, 443, 8080, 22, 3306, 5432]:
        result = detector.detect({
            'src_ip': attacker_ip,
            'dst_port': port
        })
        if result:
            print(f"Port scan detected at port {port}: {result.type}")
            break
    else:
        print("Port scan pattern completed")
    print()
    
    # Test 3: TTL anomaly detection
    print("[TEST 3] TTL Anomaly Detection")
    print("-" * 40)
    test_ip = "8.8.8.8"
    
    # Establish baseline
    for _ in range(5):
        detector.detect({
            'src_ip': test_ip,
            'ttl': 64
        })
    print("Baseline established (TTL=64)")
    
    # Anomalous TTL (proxy inserted)
    result = detector.detect({
        'src_ip': test_ip,
        'ttl': 52  # 12 hops less - proxy!
    })
    print(f"Proxy detected: {result.type if result else 'None'}")
    print()
    
    # Test 4: DNS hijacking detection
    print("[TEST 4] DNS Hijacking Detection")
    print("-" * 40)
    
    # Establish known good
    detector.known_good_dns['google.com'].add('142.250.185.46')
    
    # Suspicious DNS response
    result = detector.detect({
        'dns_query': 'google.com',
        'dns_response': '192.168.1.100'  # Private IP!
    })
    print(f"DNS hijacking: {result.type if result else 'None'}")
    print()
    
    # Final statistics
    print("[STATISTICS]")
    print("-" * 40)
    stats = detector.get_statistics()
    print(f"Total alerts: {stats['total_alerts']}")
    print(f"Alert types: {stats['alert_types']}")
    print(f"ARP tracking: {stats['arp_tracking']}")
    print(f"Port scan: {stats['port_scan']}")
    print()
    
    # Suspicious IPs
    suspicious = detector.get_suspicious_ips()
    print("[SUSPICIOUS IPs]")
    print("-" * 40)
    print(f"Port scanners: {suspicious['port_scanners']}")
    print(f"Duplicate IPs: {suspicious['duplicate_ip_sources']}")
    print()
    
    print("=" * 80)
    print("[✓] Enhanced AnomalyDetector test complete")
    print("=" * 80)
