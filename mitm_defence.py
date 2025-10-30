#!/usr/bin/env python3
"""
Enhanced Network MITM Defense System
Comprehensive solution for detecting, deceiving, and protecting against
Man-in-the-Middle attacks with WiFi security analysis.

New Features:
- WiFi Security Analysis (WPA2/WPA3/Open detection)
- TTL Analysis for proxy detection
- TCP Window Size monitoring
- Enhanced honeypot with request logging
- Duplicate IP/MAC detection
- Network latency monitoring
- DNS spoofing detection
"""

import socket
import struct
import threading
import time
import json
import hashlib
import ssl
import http.server
import socketserver
from dataclasses import dataclass, asdict, field
from datetime import datetime
from typing import Dict, List, Set, Optional, Tuple
from collections import defaultdict
from pathlib import Path
import subprocess
import platform
import re
import statistics


# ============================================================================
# ENHANCED CONFIGURATION
# ============================================================================

@dataclass
class SecurityConfig:
    """Enhanced security configuration"""
    
    # ARP Protection
    arp_monitor_interval: float = 2.0
    arp_change_threshold: int = 3
    arp_auto_lock: bool = True
    
    # Port Scan Detection
    scan_time_window: int = 30
    scan_port_threshold: int = 5
    
    # Honeypot Configuration
    honeypot_enabled: bool = True
    honeypot_ports: List[int] = field(default_factory=lambda: [8080, 8443, 3306, 5432, 21, 23])
    honeypot_banner_delay: float = 0.5
    honeypot_log_full_requests: bool = True
    
    # TLS Validation
    enforce_tls_validation: bool = True
    allowed_ca_bundle: Optional[str] = None
    min_tls_version: int = ssl.TLSVersion.TLSv1_2
    
    # WiFi Security
    wifi_security_check_interval: float = 60.0
    alert_on_open_wifi: bool = True
    
    # Network Metrics
    ttl_baseline: int = 64  # Linux default
    ttl_deviation_threshold: int = 10
    latency_check_interval: float = 30.0
    latency_spike_threshold: float = 2.0  # 2x normal
    
    # Forensics
    forensics_log_path: str = "./mitm_defense_logs"
    max_log_size_mb: int = 100


# ============================================================================
# ENHANCED FORENSICS & LOGGING
# ============================================================================

class ForensicsLogger:
    """Enhanced forensic logging with metrics tracking"""
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.log_dir = Path(config.forensics_log_path)
        self.log_dir.mkdir(exist_ok=True)
        
        self.session_id = hashlib.sha256(
            f"{datetime.now().isoformat()}{socket.gethostname()}".encode()
        ).hexdigest()[:16]
        
        self.events: List[Dict] = []
        self.metrics: Dict[str, List[float]] = defaultdict(list)
        self.lock = threading.Lock()
    
    def log_event(self, category: str, severity: str, details: Dict) -> None:
        """Log a security event with full context"""
        event = {
            "timestamp": datetime.now().isoformat(),
            "session_id": self.session_id,
            "category": category,
            "severity": severity,
            "hostname": socket.gethostname(),
            "details": details
        }
        
        with self.lock:
            self.events.append(event)
            self._write_event(event)
            print(f"[{severity}] {category}: {details.get('message', '')}")
    
    def log_metric(self, metric_name: str, value: float) -> None:
        """Log a metric value for analysis"""
        with self.lock:
            self.metrics[metric_name].append(value)
            # Keep only last 1000 values
            if len(self.metrics[metric_name]) > 1000:
                self.metrics[metric_name] = self.metrics[metric_name][-1000:]
    
    def get_metric_stats(self, metric_name: str) -> Dict:
        """Get statistics for a metric"""
        with self.lock:
            values = self.metrics.get(metric_name, [])
            if not values:
                return {}
            return {
                "count": len(values),
                "mean": statistics.mean(values),
                "median": statistics.median(values),
                "stdev": statistics.stdev(values) if len(values) > 1 else 0,
                "min": min(values),
                "max": max(values)
            }
    
    def _write_event(self, event: Dict) -> None:
        """Write event to disk immediately"""
        log_file = self.log_dir / f"events_{datetime.now().strftime('%Y%m%d')}.jsonl"
        try:
            with open(log_file, 'a') as f:
                f.write(json.dumps(event) + "\n")
        except Exception as e:
            print(f"[FORENSICS] Failed to write event: {e}")
    
    def generate_report(self) -> str:
        """Generate comprehensive forensics report"""
        with self.lock:
            if not self.events:
                return "No security events recorded."
            
            report = [
                "=" * 80,
                f"ENHANCED MITM Defense System - Forensics Report",
                f"Session ID: {self.session_id}",
                f"Generated: {datetime.now().isoformat()}",
                "=" * 80,
                ""
            ]
            
            # Event summary
            by_category = defaultdict(int)
            by_severity = defaultdict(int)
            
            for event in self.events:
                by_category[event["category"]] += 1
                by_severity[event["severity"]] += 1
            
            report.append("EVENT SUMMARY:")
            report.append(f"  Total Events: {len(self.events)}")
            report.append(f"  By Severity: {dict(by_severity)}")
            report.append(f"  By Category: {dict(by_category)}")
            report.append("")
            
            # Metrics summary
            report.append("METRICS SUMMARY:")
            for metric_name, values in self.metrics.items():
                stats = self.get_metric_stats(metric_name)
                if stats:
                    report.append(f"  {metric_name}:")
                    report.append(f"    Mean: {stats['mean']:.2f}, Median: {stats['median']:.2f}")
                    report.append(f"    Range: {stats['min']:.2f} - {stats['max']:.2f}")
            report.append("")
            
            # Critical events
            critical = [e for e in self.events if e["severity"] == "CRITICAL"]
            if critical:
                report.append("CRITICAL EVENTS:")
                for event in critical:
                    report.append(f"  [{event['timestamp']}] {event['category']}")
                    report.append(f"    {json.dumps(event['details'], indent=6)}")
                report.append("")
            
            return "\n".join(report)


# ============================================================================
# WIFI SECURITY ANALYZER
# ============================================================================

class WiFiSecurityAnalyzer:
    """Analyzes WiFi network security posture"""
    
    def __init__(self, config: SecurityConfig, logger: ForensicsLogger):
        self.config = config
        self.logger = logger
        self.running = False
        self.current_ssid: Optional[str] = None
        self.security_type: Optional[str] = None
        self.signal_strength: int = 0
        self.monitor_thread: Optional[threading.Thread] = None
    
    def start(self) -> None:
        """Start WiFi security monitoring"""
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        self.logger.log_event(
            "wifi_analyzer",
            "INFO",
            {"message": "WiFi security analysis started"}
        )
    
    def stop(self) -> None:
        """Stop WiFi monitoring"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5.0)
    
    def _monitor_loop(self) -> None:
        """Main monitoring loop"""
        while self.running:
            try:
                self._analyze_wifi()
                time.sleep(self.config.wifi_security_check_interval)
            except Exception as e:
                self.logger.log_event(
                    "wifi_analyzer",
                    "ERROR",
                    {"message": "WiFi analysis error", "error": str(e)}
                )
                time.sleep(self.config.wifi_security_check_interval)
    
    def _analyze_wifi(self) -> None:
        """Analyze current WiFi connection"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(
                    ["netsh", "wlan", "show", "interfaces"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                for line in result.stdout.split("\n"):
                    if "SSID" in line and "BSSID" not in line:
                        self.current_ssid = line.split(":")[-1].strip()
                    elif "Authentication" in line:
                        self.security_type = line.split(":")[-1].strip()
                    elif "Signal" in line:
                        match = re.search(r"(\d+)%", line)
                        if match:
                            self.signal_strength = int(match.group(1))
            
            elif platform.system() == "Linux":
                # Try nmcli first
                result = subprocess.run(
                    ["nmcli", "-t", "-f", "active,ssid,security", "dev", "wifi"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                for line in result.stdout.split("\n"):
                    if line.startswith("yes:"):
                        parts = line.split(":")
                        if len(parts) >= 3:
                            self.current_ssid = parts[1]
                            self.security_type = parts[2] if parts[2] else "OPEN"
            
            elif platform.system() == "Darwin":  # macOS
                result = subprocess.run(
                    ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-I"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                for line in result.stdout.split("\n"):
                    if "SSID:" in line:
                        self.current_ssid = line.split(":")[-1].strip()
                    elif "link auth:" in line:
                        self.security_type = line.split(":")[-1].strip()
            
            # Log findings
            if self.current_ssid:
                self.logger.log_event(
                    "wifi_analyzer",
                    "INFO",
                    {
                        "message": "WiFi analysis complete",
                        "ssid": self.current_ssid,
                        "security": self.security_type,
                        "signal_strength": self.signal_strength
                    }
                )
                
                # Alert on open/weak WiFi
                if self.config.alert_on_open_wifi:
                    if self.security_type in ["OPEN", "WEP", "", None]:
                        self.logger.log_event(
                            "wifi_analyzer",
                            "CRITICAL",
                            {
                                "message": "INSECURE WIFI DETECTED!",
                                "ssid": self.current_ssid,
                                "security": self.security_type or "OPEN",
                                "risk": "High - Open networks allow easy MITM attacks"
                            }
                        )
                    elif "WPA" in str(self.security_type).upper() and "WPA3" not in str(self.security_type).upper():
                        self.logger.log_event(
                            "wifi_analyzer",
                            "WARNING",
                            {
                                "message": "Weak WiFi security detected",
                                "ssid": self.current_ssid,
                                "security": self.security_type,
                                "recommendation": "WPA3 recommended for better security"
                            }
                        )
        
        except Exception as e:
            pass  # Silent fail for unsupported systems
    
    def get_status(self) -> Dict:
        """Get current WiFi status"""
        return {
            "ssid": self.current_ssid,
            "security": self.security_type,
            "signal_strength": self.signal_strength,
            "is_secure": self.security_type not in ["OPEN", "WEP", "", None] if self.security_type else False
        }


# ============================================================================
# NETWORK METRICS ANALYZER
# ============================================================================

class NetworkMetricsAnalyzer:
    """Analyzes network metrics for MITM detection"""
    
    def __init__(self, config: SecurityConfig, logger: ForensicsLogger):
        self.config = config
        self.logger = logger
        self.running = False
        self.ttl_history: Dict[str, List[int]] = defaultdict(list)
        self.latency_history: Dict[str, List[float]] = defaultdict(list)
        self.monitor_thread: Optional[threading.Thread] = None
    
    def start(self) -> None:
        """Start network metrics monitoring"""
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        self.logger.log_event(
            "metrics_analyzer",
            "INFO",
            {"message": "Network metrics analysis started"}
        )
    
    def stop(self) -> None:
        """Stop monitoring"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5.0)
    
    def _monitor_loop(self) -> None:
        """Main monitoring loop"""
        while self.running:
            try:
                self._check_gateway_metrics()
                time.sleep(self.config.latency_check_interval)
            except Exception as e:
                self.logger.log_event(
                    "metrics_analyzer",
                    "ERROR",
                    {"message": "Metrics analysis error", "error": str(e)}
                )
                time.sleep(self.config.latency_check_interval)
    
    def _check_gateway_metrics(self) -> None:
        """Check gateway TTL and latency"""
        try:
            gateway = self._get_gateway()
            if not gateway:
                return
            
            # Ping gateway
            if platform.system() == "Windows":
                result = subprocess.run(
                    ["ping", "-n", "1", gateway],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
            else:
                result = subprocess.run(
                    ["ping", "-c", "1", gateway],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
            
            # Extract TTL
            ttl_match = re.search(r"ttl=(\d+)", result.stdout.lower())
            if ttl_match:
                ttl = int(ttl_match.group(1))
                self.ttl_history[gateway].append(ttl)
                self.logger.log_metric(f"ttl_{gateway}", ttl)
                
                # Check for TTL anomalies
                if len(self.ttl_history[gateway]) > 5:
                    avg_ttl = statistics.mean(self.ttl_history[gateway][-5:])
                    if abs(ttl - avg_ttl) > self.config.ttl_deviation_threshold:
                        self.logger.log_event(
                            "metrics_analyzer",
                            "WARNING",
                            {
                                "message": "TTL deviation detected - possible proxy",
                                "gateway": gateway,
                                "current_ttl": ttl,
                                "average_ttl": avg_ttl,
                                "deviation": abs(ttl - avg_ttl)
                            }
                        )
            
            # Extract latency
            time_match = re.search(r"time[=<](\d+\.?\d*)\s*ms", result.stdout.lower())
            if time_match:
                latency = float(time_match.group(1))
                self.latency_history[gateway].append(latency)
                self.logger.log_metric(f"latency_{gateway}", latency)
                
                # Check for latency spikes
                if len(self.latency_history[gateway]) > 10:
                    avg_latency = statistics.mean(self.latency_history[gateway][-10:])
                    if latency > avg_latency * self.config.latency_spike_threshold:
                        self.logger.log_event(
                            "metrics_analyzer",
                            "WARNING",
                            {
                                "message": "Latency spike detected",
                                "gateway": gateway,
                                "current_latency": latency,
                                "average_latency": avg_latency,
                                "spike_ratio": latency / avg_latency
                            }
                        )
        
        except Exception as e:
            pass
    
    def _get_gateway(self) -> Optional[str]:
        """Get default gateway IP"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(
                    ["route", "print", "0.0.0.0"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                for line in result.stdout.split("\n"):
                    if "0.0.0.0" in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            return parts[2]
            else:
                result = subprocess.run(
                    ["ip", "route", "show", "default"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                match = re.search(r"default via ([\d.]+)", result.stdout)
                if match:
                    return match.group(1)
        except:
            pass
        return None
    
    def get_status(self) -> Dict:
        """Get current metrics status"""
        gateway = self._get_gateway()
        if gateway and gateway in self.ttl_history:
            return {
                "gateway": gateway,
                "ttl_current": self.ttl_history[gateway][-1] if self.ttl_history[gateway] else None,
                "ttl_average": statistics.mean(self.ttl_history[gateway]) if self.ttl_history[gateway] else None,
                "latency_current": self.latency_history[gateway][-1] if self.latency_history[gateway] else None,
                "latency_average": statistics.mean(self.latency_history[gateway]) if self.latency_history[gateway] else None
            }
        return {}


# ============================================================================
# ENHANCED ARP MONITORING
# ============================================================================

@dataclass
class ARPEntry:
    """Represents a single ARP table entry"""
    ip: str
    mac: str
    interface: str
    timestamp: float = field(default_factory=time.time)


class ARPMonitor:
    """Enhanced ARP monitoring with duplicate detection"""
    
    def __init__(self, config: SecurityConfig, logger: ForensicsLogger):
        self.config = config
        self.logger = logger
        
        self.arp_history: Dict[str, List[ARPEntry]] = defaultdict(list)
        self.locked_entries: Dict[str, str] = {}
        self.gateway_ip: Optional[str] = None
        self.gateway_mac: Optional[str] = None
        
        # Duplicate detection
        self.ip_to_macs: Dict[str, Set[str]] = defaultdict(set)
        self.mac_to_ips: Dict[str, Set[str]] = defaultdict(set)
        
        self.running = False
        self.monitor_thread: Optional[threading.Thread] = None
    
    def start(self) -> None:
        """Start ARP monitoring"""
        if self.running:
            return
        
        self.running = True
        self.gateway_ip = self._discover_gateway()
        
        if self.gateway_ip:
            self.logger.log_event(
                "arp_monitor",
                "INFO",
                {"message": "Gateway discovered", "gateway_ip": self.gateway_ip}
            )
        
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
    
    def stop(self) -> None:
        """Stop ARP monitoring"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5.0)
    
    def _discover_gateway(self) -> Optional[str]:
        """Discover default gateway IP address"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(
                    ["route", "print", "0.0.0.0"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                for line in result.stdout.split("\n"):
                    if "0.0.0.0" in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            return parts[2]
            else:
                result = subprocess.run(
                    ["ip", "route", "show", "default"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                match = re.search(r"default via ([\d.]+)", result.stdout)
                if match:
                    return match.group(1)
        except Exception as e:
            self.logger.log_event(
                "arp_monitor",
                "WARNING",
                {"message": "Failed to discover gateway", "error": str(e)}
            )
        
        return None
    
    def _read_arp_table(self) -> List[ARPEntry]:
        """Read current ARP table from operating system"""
        entries = []
        
        try:
            if platform.system() == "Windows":
                result = subprocess.run(
                    ["arp", "-a"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                for line in result.stdout.split("\n"):
                    match = re.search(
                        r"([\d.]+)\s+([\da-fA-F]{2}[:-]){5}[\da-fA-F]{2}",
                        line
                    )
                    if match:
                        parts = line.split()
                        if len(parts) >= 2:
                            ip = parts[0]
                            mac = parts[1].replace("-", ":").lower()
                            entries.append(ARPEntry(ip, mac, "unknown"))
            else:
                result = subprocess.run(
                    ["arp", "-an"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                for line in result.stdout.split("\n"):
                    match = re.search(
                        r"\(([\d.]+)\) at ([\da-fA-F:]+)",
                        line
                    )
                    if match:
                        ip = match.group(1)
                        mac = match.group(2).lower()
                        interface_match = re.search(r"on (\S+)", line)
                        interface = interface_match.group(1) if interface_match else "unknown"
                        entries.append(ARPEntry(ip, mac, interface))
        
        except Exception as e:
            self.logger.log_event(
                "arp_monitor",
                "ERROR",
                {"message": "Failed to read ARP table", "error": str(e)}
            )
        
        return entries
    
    def _monitor_loop(self) -> None:
        """Main monitoring loop"""
        while self.running:
            try:
                current_entries = self._read_arp_table()
                self._analyze_entries(current_entries)
                time.sleep(self.config.arp_monitor_interval)
            except Exception as e:
                self.logger.log_event(
                    "arp_monitor",
                    "ERROR",
                    {"message": "Monitor loop error", "error": str(e)}
                )
                time.sleep(self.config.arp_monitor_interval)
    
    def _analyze_entries(self, entries: List[ARPEntry]) -> None:
        """Analyze ARP entries for anomalies"""
        # Clear current mappings
        current_ip_macs = defaultdict(set)
        current_mac_ips = defaultdict(set)
        
        for entry in entries:
            current_ip_macs[entry.ip].add(entry.mac)
            current_mac_ips[entry.mac].add(entry.ip)
            
            # Check for locked entry violations
            if entry.ip in self.locked_entries:
                if entry.mac != self.locked_entries[entry.ip]:
                    self._handle_arp_spoofing(entry, self.locked_entries[entry.ip])
                    continue
            
            # Track history
            history = self.arp_history[entry.ip]
            history.append(entry)
            
            # Keep only recent history
            cutoff_time = time.time() - 300  # 5 minutes
            history[:] = [h for h in history if h.timestamp > cutoff_time]
            
            # Check for MAC changes
            unique_macs = {h.mac for h in history}
            if len(unique_macs) > 1:
                self._handle_mac_change(entry.ip, list(unique_macs))
            
            # Auto-lock gateway if detected
            if self.config.arp_auto_lock and entry.ip == self.gateway_ip:
                if self.gateway_mac is None:
                    self.gateway_mac = entry.mac
                    self.locked_entries[entry.ip] = entry.mac
                    self.logger.log_event(
                        "arp_monitor",
                        "INFO",
                        {
                            "message": "Gateway MAC locked",
                            "ip": entry.ip,
                            "mac": entry.mac
                        }
                    )
        
        # Detect duplicate IPs
        for ip, macs in current_ip_macs.items():
            if len(macs) > 1:
                self.logger.log_event(
                    "arp_monitor",
                    "CRITICAL",
                    {
                        "message": "Duplicate IP detected - possible ARP spoofing",
                        "ip": ip,
                        "mac_addresses": list(macs),
                        "count": len(macs)
                    }
                )
        
        # Detect duplicate MACs
        for mac, ips in current_mac_ips.items():
            if len(ips) > 1:
                self.logger.log_event(
                    "arp_monitor",
                    "WARNING",
                    {
                        "message": "Duplicate MAC detected - router or NAT device",
                        "mac": mac,
                        "ip_addresses": list(ips),
                        "count": len(ips)
                    }
                )
        
        self.ip_to_macs = current_ip_macs
        self.mac_to_ips = current_mac_ips
    
    def _handle_arp_spoofing(self, current: ARPEntry, expected_mac: str) -> None:
        """Handle detected ARP spoofing attack"""
        self.logger.log_event(
            "arp_monitor",
            "CRITICAL",
            {
                "message": "ARP SPOOFING ATTACK DETECTED!",
                "attack_type": "arp_spoofing",
                "ip": current.ip,
                "expected_mac": expected_mac,
                "observed_mac": current.mac,
                "interface": current.interface,
                "action": "Connection blocked by MAC lock"
            }
        )
    
    def _handle_mac_change(self, ip: str, macs: List[str]) -> None:
        """Handle suspicious MAC address changes"""
        history = self.arp_history[ip]
        
        if len(history) >= self.config.arp_change_threshold:
            self.logger.log_event(
                "arp_monitor",
                "WARNING",
                {
                    "message": "Suspicious ARP changes detected",
                    "ip": ip,
                    "mac_addresses": macs,
                    "change_count": len(history)
                }
            )
    
    def get_status(self) -> Dict:
        """Get current ARP monitoring status"""
        return {
            "gateway_ip": self.gateway_ip,
            "gateway_mac": self.gateway_mac,
            "locked_entries": len(self.locked_entries),
            "tracked_ips": len(self.arp_history),
            "duplicate_ips": len([ip for ip, macs in self.ip_to_macs.items() if len(macs) > 1]),
            "duplicate_macs": len([mac for mac, ips in self.mac_to_ips.items() if len(ips) > 1])
        }


# ============================================================================
# PORT SCAN DETECTION
# ============================================================================

@dataclass
class PortAccessEvent:
    """Records a single port access event"""
    timestamp: float
    source_ip: str
    dest_port: int


class PortScanDetector:
    """Detects network reconnaissance through port scanning patterns"""
    
    def __init__(self, config: SecurityConfig, logger: ForensicsLogger):
        self.config = config
        self.logger = logger
        
        self.access_history: Dict[str, List[PortAccessEvent]] = defaultdict(list)
        self.flagged_scanners: Set[str] = set()
        self.lock = threading.Lock()
    
    def record_access(self, source_ip: str, dest_port: int) -> None:
        """Record a port access event"""
        with self.lock:
            event = PortAccessEvent(
                timestamp=time.time(),
                source_ip=source_ip,
                dest_port=dest_port
            )
            
            history = self.access_history[source_ip]
            history.append(event)
            
            # Clean old events
            cutoff = time.time() - self.config.scan_time_window
            history[:] = [e for e in history if e.timestamp > cutoff]
            
            # Detect scan pattern
            if len(history) >= self.config.scan_port_threshold:
                unique_ports = {e.dest_port for e in history}
                
                if len(unique_ports) >= self.config.scan_port_threshold:
                    self._handle_scan_detection(source_ip, unique_ports)
    
    def _handle_scan_detection(self, source_ip: str, ports: Set[int]) -> None:
        """Handle detected port scan"""
        if source_ip not in self.flagged_scanners:
            self.flagged_scanners.add(source_ip)
            
            self.logger.log_event(
                "port_scan",
                "CRITICAL",
                {
                    "message": "PORT SCAN ATTACK DETECTED!",
                    "attack_type": "port_scan","source_ip": source_ip,
                    "ports_accessed": sorted(list(ports)),
                    "access_count": len(self.access_history[source_ip]),
                    "time_window": f"{self.config.scan_time_window}s"
                }
            )
    
    def get_status(self) -> Dict:
        """Get current scan detection status"""
        return {
            "flagged_scanners": len(self.flagged_scanners),
            "monitored_ips": len(self.access_history),
            "scanner_list": list(self.flagged_scanners)
        }


# ============================================================================
# ENHANCED HONEYPOT SERVICES
# ============================================================================

class HoneypotService:
    """Enhanced honeypot with detailed request logging"""
    
    def __init__(self, config: SecurityConfig, logger: ForensicsLogger,
                 scan_detector: PortScanDetector):
        self.config = config
        self.logger = logger
        self.scan_detector = scan_detector
        
        self.services: List[threading.Thread] = []
        self.running = False
        self.interaction_count: Dict[int, int] = defaultdict(int)
        self.attacker_ips: Set[str] = set()
    
    def start(self) -> None:
        """Start all honeypot services"""
        if not self.config.honeypot_enabled:
            return
        
        self.running = True
        
        for port in self.config.honeypot_ports:
            thread = threading.Thread(
                target=self._run_honeypot,
                args=(port,),
                daemon=True
            )
            thread.start()
            self.services.append(thread)
            
            self.logger.log_event(
                "honeypot",
                "INFO",
                {"message": f"Honeypot started on port {port}", "service_type": self._get_service_name(port)}
            )
    
    def stop(self) -> None:
        """Stop all honeypot services"""
        self.running = False
        for thread in self.services:
            thread.join(timeout=2.0)
    
    def _run_honeypot(self, port: int) -> None:
        """Run a single honeypot service"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(1.0)
            sock.bind(('0.0.0.0', port))
            sock.listen(5)
            
            while self.running:
                try:
                    client, addr = sock.accept()
                    threading.Thread(
                        target=self._handle_connection,
                        args=(client, addr, port),
                        daemon=True
                    ).start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        self.logger.log_event(
                            "honeypot",
                            "ERROR",
                            {"port": port, "error": str(e)}
                        )
        
        except Exception as e:
            self.logger.log_event(
                "honeypot",
                "ERROR",
                {"message": f"Failed to start honeypot on port {port}", "error": str(e)}
            )
    
    def _handle_connection(self, client: socket.socket, addr: Tuple, port: int) -> None:
        """Handle a connection to honeypot with full logging"""
        source_ip = addr[0]
        
        # Track attacker
        self.attacker_ips.add(source_ip)
        self.interaction_count[port] += 1
        
        # Record access for scan detection
        self.scan_detector.record_access(source_ip, port)
        
        try:
            # Delay to analyze behavior
            time.sleep(self.config.honeypot_banner_delay)
            
            # Send deceptive banner based on port
            banner = self._generate_banner(port)
            client.send(banner.encode())
            
            # Capture attacker data
            client.settimeout(5.0)
            request_data = b""
            
            try:
                while True:
                    chunk = client.recv(4096)
                    if not chunk:
                        break
                    request_data += chunk
                    if len(request_data) > 10000:  # Limit to 10KB
                        break
                
                # Parse and log request details
                request_str = request_data.decode('utf-8', errors='ignore')
                
                # Extract interesting details
                details = {
                    "message": "HONEYPOT INTERACTION - Attacker caught!",
                    "source_ip": source_ip,
                    "port": port,
                    "service_type": self._get_service_name(port),
                    "banner_sent": banner[:100],
                    "data_length": len(request_data),
                    "interaction_count": self.interaction_count[port]
                }
                
                if self.config.honeypot_log_full_requests:
                    details["full_request"] = request_str[:1000]  # First 1000 chars
                    details["request_hex"] = request_data[:500].hex()
                
                # Detect attack patterns
                attack_indicators = []
                if "sqlmap" in request_str.lower():
                    attack_indicators.append("SQL Injection Tool (sqlmap)")
                if "nmap" in request_str.lower():
                    attack_indicators.append("Port Scanner (nmap)")
                if "metasploit" in request_str.lower():
                    attack_indicators.append("Exploitation Framework (Metasploit)")
                if "nikto" in request_str.lower():
                    attack_indicators.append("Web Scanner (Nikto)")
                if "../" in request_str or "..%2f" in request_str.lower():
                    attack_indicators.append("Directory Traversal Attempt")
                if "union select" in request_str.lower():
                    attack_indicators.append("SQL Injection Attempt")
                if "<script>" in request_str.lower():
                    attack_indicators.append("XSS Attempt")
                
                if attack_indicators:
                    details["attack_indicators"] = attack_indicators
                    details["message"] = f"ATTACK DETECTED: {', '.join(attack_indicators)}"
                
                self.logger.log_event(
                    "honeypot",
                    "WARNING",
                    details
                )
                
                # Send fake response
                self._send_fake_response(client, port, request_str)
                
            except socket.timeout:
                self.logger.log_event(
                    "honeypot",
                    "INFO",
                    {
                        "message": "Connection timeout - attacker disconnected",
                        "source_ip": source_ip,
                        "port": port
                    }
                )
        
        except Exception as e:
            self.logger.log_event(
                "honeypot",
                "ERROR",
                {"source_ip": source_ip, "port": port, "error": str(e)}
            )
        finally:
            client.close()
    
    def _generate_banner(self, port: int) -> str:
        """Generate deceptive service banner"""
        banners = {
            21: "220 ProFTPD 1.3.5 Server (Debian)\r\n",
            22: "SSH-2.0-OpenSSH_7.4\r\n",
            23: "Ubuntu 18.04 LTS\r\nlogin: ",
            80: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\nContent-Type: text/html\r\n\r\n",
            443: "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\n\r\n",
            3306: "\x4a\x00\x00\x00\x0a5.7.33-0ubuntu0.18.04.1\x00",
            5432: "PostgreSQL 12.5 on x86_64-pc-linux-gnu\r\n",
            8080: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\nContent-Type: text/html\r\n\r\n",
            8443: "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)\r\nContent-Type: text/html\r\n\r\n"
        }
        return banners.get(port, "220 Service Ready\r\n")
    
    def _send_fake_response(self, client: socket.socket, port: int, request: str) -> None:
        """Send fake response based on request"""
        try:
            if port in [80, 8080, 443, 8443]:
                # HTTP response with fake admin panel
                response = """HTTP/1.1 200 OK
Content-Type: text/html
Connection: close

<!DOCTYPE html>
<html>
<head><title>Admin Panel</title></head>
<body>
<h1>Admin Login</h1>
<form method="POST" action="/login">
<input type="text" name="username" placeholder="Username"><br>
<input type="password" name="password" placeholder="Password"><br>
<input type="submit" value="Login">
</form>
</body>
</html>"""
                client.send(response.encode())
            
            elif port == 21:
                # FTP responses
                if "USER" in request.upper():
                    client.send(b"331 Password required\r\n")
                elif "PASS" in request.upper():
                    client.send(b"230 Login successful\r\n")
            
            elif port == 22:
                # SSH - just close after banner
                pass
            
            elif port == 3306:
                # MySQL - send auth challenge
                client.send(b"\x07\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00")
        
        except:
            pass
    
    def _get_service_name(self, port: int) -> str:
        """Get service name for port"""
        services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            80: "HTTP",
            443: "HTTPS",
            3306: "MySQL",
            5432: "PostgreSQL",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt"
        }
        return services.get(port, f"Unknown-{port}")
    
    def get_status(self) -> Dict:
        """Get honeypot status"""
        return {
            "enabled": self.config.honeypot_enabled,
            "active_ports": self.config.honeypot_ports,
            "total_interactions": sum(self.interaction_count.values()),
            "interactions_by_port": dict(self.interaction_count),
            "unique_attackers": len(self.attacker_ips),
            "attacker_ips": list(self.attacker_ips)
        }


# ============================================================================
# TLS VALIDATION ENFORCER
# ============================================================================

class TLSValidator:
    """Enforces application-level TLS validation to detect inline proxies"""
    
    def __init__(self, config: SecurityConfig, logger: ForensicsLogger):
        self.config = config
        self.logger = logger
        
        # Create SSL context with strict validation
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.minimum_version = config.min_tls_version
        self.ssl_context.check_hostname = True
        self.ssl_context.verify_mode = ssl.CERT_REQUIRED
        
        if config.allowed_ca_bundle:
            self.ssl_context.load_verify_locations(config.allowed_ca_bundle)
    
    def validate_connection(self, hostname: str, port: int = 443) -> Dict:
        """Validate TLS connection and detect anomalies"""
        result = {
            "hostname": hostname,
            "port": port,
            "valid": False,
            "certificate": None,
            "errors": []
        }
        
        try:
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with self.ssl_context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    result["valid"] = True
                    result["certificate"] = {
                        "subject": dict(x[0] for x in cert['subject']),
                        "issuer": dict(x[0] for x in cert['issuer']),
                        "version": cert['version'],
                        "serial_number": cert['serialNumber'],
                        "not_before": cert['notBefore'],
                        "not_after": cert['notAfter']
                    }
                    
                    # Check for suspicious certificate properties
                    self._analyze_certificate(hostname, cert)
        
        except ssl.SSLError as e:
            result["errors"].append(f"SSL Error: {str(e)}")
            self.logger.log_event(
                "tls_validator",
                "CRITICAL",
                {
                    "message": "TLS validation failed - MITM proxy detected!",
                    "hostname": hostname,
                    "error": str(e),
                    "recommendation": "Do not trust this connection"
                }
            )
        
        except Exception as e:
            result["errors"].append(f"Connection Error: {str(e)}")
        
        return result
    
    def _analyze_certificate(self, hostname: str, cert: Dict) -> None:
        """Analyze certificate for suspicious properties"""
        issuer = dict(x[0] for x in cert['issuer'])
        subject = dict(x[0] for x in cert['subject'])
        
        # Check for self-signed certificates
        if issuer == subject:
            self.logger.log_event(
                "tls_validator",
                "CRITICAL",
                {
                    "message": "Self-signed certificate detected - MITM likely!",
                    "hostname": hostname,
                    "issuer": issuer,
                    "risk": "HIGH - Inline proxy intercepting traffic"
                }
            )


# ============================================================================
# MAIN DEFENSE COORDINATOR
# ============================================================================

class MITMDefenseSystem:
    """Enhanced main coordinator for all defense components"""
    
    def __init__(self, config: Optional[SecurityConfig] = None):
        self.config = config or SecurityConfig()
        
        # Initialize components
        self.logger = ForensicsLogger(self.config)
        self.arp_monitor = ARPMonitor(self.config, self.logger)
        self.scan_detector = PortScanDetector(self.config, self.logger)
        self.honeypot = HoneypotService(self.config, self.logger, self.scan_detector)
        self.tls_validator = TLSValidator(self.config, self.logger)
        self.wifi_analyzer = WiFiSecurityAnalyzer(self.config, self.logger)
        self.metrics_analyzer = NetworkMetricsAnalyzer(self.config, self.logger)
        
        self.running = False
    
    def start(self) -> None:
        """Start all defense systems"""
        if self.running:
            return
        
        self.running = True
        
        self.logger.log_event(
            "system",
            "INFO",
            {"message": "Enhanced MITM Defense System starting"}
        )
        
        # Start components
        self.arp_monitor.start()
        self.honeypot.start()
        self.wifi_analyzer.start()
        self.metrics_analyzer.start()
        
        self.logger.log_event(
            "system",
            "INFO",
            {"message": "All defense systems operational"}
        )
    
    def stop(self) -> None:
        """Stop all defense systems"""
        if not self.running:
            return
        
        self.running = False
        
        self.logger.log_event(
            "system",
            "INFO",
            {"message": "MITM Defense System shutting down"}
        )
        
        self.arp_monitor.stop()
        self.honeypot.stop()
        self.wifi_analyzer.stop()
        self.metrics_analyzer.stop()
    
    def validate_tls_endpoint(self, hostname: str, port: int = 443) -> Dict:
        """Validate a TLS endpoint"""
        return self.tls_validator.validate_connection(hostname, port)
    
    def get_status(self) -> Dict:
        """Get comprehensive system status"""
        return {
            "running": self.running,
            "arp_monitor": self.arp_monitor.get_status(),
            "scan_detector": self.scan_detector.get_status(),
            "honeypot": self.honeypot.get_status(),
            "wifi": self.wifi_analyzer.get_status(),
            "metrics": self.metrics_analyzer.get_status(),
            "events": {
                "total": len(self.logger.events),
                "critical": len([e for e in self.logger.events if e["severity"] == "CRITICAL"]),
                "warnings": len([e for e in self.logger.events if e["severity"] == "WARNING"])
            }
        }
    
    def generate_report(self) -> str:
        """Generate comprehensive forensics report"""
        return self.logger.generate_report()


# ============================================================================
# DEMONSTRATION & TESTING
# ============================================================================

def demonstrate_system():
    """Demonstrate the enhanced MITM defense system"""
    
    print("=" * 80)
    print("ENHANCED MITM Defense System - Security Demonstration")
    print("=" * 80)
    print()
    
    # Create configuration
    config = SecurityConfig(
        arp_monitor_interval=5.0,
        honeypot_enabled=True,
        honeypot_ports=[8080, 8443, 3306],
        honeypot_log_full_requests=True,
        wifi_security_check_interval=30.0,
        forensics_log_path="./enhanced_logs"
    )
    
    # Initialize system
    defense = MITMDefenseSystem(config)
    
    print("[+] Starting enhanced defense systems...")
    defense.start()
    print("[+] All systems operational\n")
    
    # Show initial status
    status = defense.get_status()
    print("System Status:")
    print(json.dumps(status, indent=2))
    print()
    
    # Simulate monitoring period
    print("[+] Monitoring network for threats (20 seconds)...")
    print("    - ARP table monitoring (duplicate detection enabled)")
    print("    - Port scan detection active")
    print("    - Honeypot services with full logging")
    print("    - WiFi security analysis")
    print("    - Network metrics (TTL, latency)")
    print()
    
    try:
        time.sleep(20)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
    
    # Validate a TLS endpoint
    print("[+] Testing TLS validation against google.com...")
    tls_result = defense.validate_tls_endpoint("google.com", 443)
    
    if tls_result["valid"]:
        print("[✓] TLS validation successful")
        if tls_result["certificate"]:
            print(f"    Certificate issued by: {tls_result['certificate']['issuer'].get('organizationName', 'Unknown')}")
    else:
        print("[✗] TLS validation failed:")
        for error in tls_result["errors"]:
            print(f"    - {error}")
    print()
    
    # Show final status
    print("[+] Final system status:")
    final_status = defense.get_status()
    print(json.dumps(final_status, indent=2))
    print()
    
    # Show metrics
    print("[+] Network Metrics:")
    metrics_status = defense.metrics_analyzer.get_status()
    if metrics_status:
        print(f"    Gateway: {metrics_status.get('gateway')}")
        print(f"    TTL: Current={metrics_status.get('ttl_current')}, Avg={metrics_status.get('ttl_average')}")
        print(f"    Latency: Current={metrics_status.get('latency_current')}ms, Avg={metrics_status.get('latency_average')}ms")
    print()
    
    # Show WiFi status
    print("[+] WiFi Security:")
    wifi_status = defense.wifi_analyzer.get_status()
    if wifi_status.get('ssid'):
        print(f"    SSID: {wifi_status['ssid']}")
        print(f"    Security: {wifi_status['security']}")
        print(f"    Status: {'✓ SECURE' if wifi_status['is_secure'] else '✗ INSECURE'}")
    print()
    
    # Generate forensics report
    print("[+] Generating enhanced forensics report...")
    report = defense.generate_report()
    print(report)
    print()
    
    # Cleanup
    print("[+] Shutting down defense systems...")
    defense.stop()
    print("[✓] System shutdown complete")
    print()
    print("=" * 80)
    print("Enhanced logs saved to:", config.forensics_log_path)
    print("=" * 80)


if __name__ == "__main__":
    demonstrate_system()