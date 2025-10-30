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
import requests
from scapy.all import sniff, TCP, Raw, DHCP, BOOTP
from plyer import notification
from wifi_anomaly import WiFiAnomalyDetector
from mac_randomization import mac_randomization_check_and_enforce
from arp_static import set_static_arp, clear_static_arp
from tcp_metrics import TCPMetricsMonitor
from interface_isolator import isolate_interface
from honeypot_fingerprint import log_connection
from gratuitous_arp_detect import start_gratuitous_arp_monitor, stop_gratuitous_arp_monitor


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
    
    # Evil Twin Detection
    evil_twin_scan_interval: float = 120.0
    trust_on_first_use: bool = True # Automatically trust networks on first connection
    
    # VPN / Traffic Encapsulation
    auto_vpn_on_insecure: bool = True
    vpn_connection_name: str = "MySecureVPN" # Name of pre-configured VPN
    
    # DNS Security
    dns_spoof_check_interval: float = 300.0
    doh_resolver_url: str = "https://dns.google/resolve"
    dns_check_domains: List[str] = field(default_factory=lambda: ["www.google.com", "www.cloudflare.com", "www.microsoft.com"])

    # Session Protection
    enable_session_hijack_detection: bool = True
    insecure_cookie_keywords: List[str] = field(default_factory=lambda: ["session", "auth", "token", "jwt", "user"])
    https_enforced_hosts: List[str] = field(default_factory=lambda: [
        "google.com", "facebook.com", "twitter.com", "instagram.com", "linkedin.com",
        "youtube.com", "paypal.com", "apple.com", "microsoft.com", "amazon.com"
    ])

    # User Notifications
    enable_desktop_notifications: bool = True

    # DHCP Monitoring
    enable_dhcp_monitoring: bool = True
    
    # Network Metrics
    ttl_baseline: int = 64  # Linux default
    ttl_deviation_threshold: int = 10
    latency_check_interval: float = 30.0
    latency_spike_threshold: float = 2.0  # 2x normal
    
    # Forensics
    forensics_log_path: str = "./mitm_defense_logs"
    max_log_size_mb: int = 100

    enable_static_arp: bool = True
    enable_tcp_metrics: bool = True
    enable_interface_isolation: bool = True
    enable_gratuitous_arp: bool = True


# ============================================================================
# ENHANCED FORENSICS & LOGGING
# ============================================================================

class SystemNotifier:
    """Handles sending desktop notifications for critical alerts"""

    def send_notification(self, title: str, message: str) -> None:
        """Send a cross-platform desktop notification"""
        try:
            notification.notify(
                title=f"Privacy Guard Alert: {title}",
                message=message,
                app_name="Privacy Guard",
                timeout=10 # seconds
            )
        except Exception as e:
            # This can fail if no notification backend is available
            print(f"[NOTIFIER] Failed to send notification: {e}")

class ForensicsLogger:
    """Enhanced forensic logging with metrics tracking and notifications"""
    
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
        self.notifier = SystemNotifier() if config.enable_desktop_notifications else None
    
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

            # Send notification for critical events
            if severity == "CRITICAL" and self.notifier:
                self.notifier.send_notification(
                    title=f"{category.replace('_', ' ').title()} Alert",
                    message=details.get('message', 'A critical security event was detected.')
                )
    
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
                # Get network profile information
                result = subprocess.run(
                    ["netsh", "wlan", "show", "interfaces"],
                    capture_output=True, text=True, timeout=5
                )
                
                ssid_match = re.search(r"SSID\s+:\s(.+)", result.stdout)
                auth_match = re.search(r"Authentication\s+:\s(.+)", result.stdout)
                signal_match = re.search(r"Signal\s+:\s(\d+)%", result.stdout)
                
                if ssid_match:
                    self.current_ssid = ssid_match.group(1).strip()
                if auth_match:
                    self.security_type = auth_match.group(1).strip()
                if signal_match:
                    self.signal_strength = int(signal_match.group(1))

                # Check for WPS on Windows (requires more complex parsing)
                # For simplicity, we'll focus on what's easily available.
            
            elif platform.system() == "Linux":
                # Using nmcli for detailed connection info
                result = subprocess.run(
                    ["nmcli", "-t", "-f", "active,ssid,security,wpa-flags,rsn-flags", "dev", "wifi"],
                    capture_output=True, text=True, timeout=5
                )
                
                for line in result.stdout.split("\n"):
                    if line.startswith("yes:"):
                        parts = line.split(":")
                        if len(parts) >= 5:
                            self.current_ssid = parts[1]
                            security_raw = parts[2]
                            wpa_flags = parts[3]
                            rsn_flags = parts[4]
                            
                            self.security_type = self._classify_linux_security(
                                security_raw, wpa_flags, rsn_flags
                            )
                        break
            
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
                    security_rating, risk_description = self._rate_security()
                    
                    if security_rating == "CRITICAL":
                        self.logger.log_event(
                            "wifi_analyzer",
                            "CRITICAL",
                            {
                                "message": "INSECURE WIFI DETECTED!",
                                "ssid": self.current_ssid,
                                "security_type": self.security_type,
                                "risk": risk_description
                            }
                        )
                    elif security_rating == "WARNING":
                        self.logger.log_event(
                            "wifi_analyzer",
                            "WARNING",
                            {
                                "message": "Weak WiFi security detected",
                                "ssid": self.current_ssid,
                                "security_type": self.security_type,
                                "recommendation": risk_description
                            }
                        )
        
        except Exception as e:
            self.logger.log_event(
                "wifi_analyzer", "ERROR", 
                {"message": "Failed to analyze WiFi", "error": str(e)}
            )
    
    def _classify_linux_security(self, security: str, wpa_flags: str, rsn_flags: str) -> str:
        """Classify Linux WiFi security based on nmcli flags"""
        if not security:
            return "Open"
        
        if "wep" in security.lower():
            return "WEP"
        
        # Check for WPA3
        if "sae" in rsn_flags:
            return "WPA3-Personal"
        if "wpa3" in security.lower():
             return "WPA3-Enterprise"
        
        # Check for WPA2
        if "psk" in rsn_flags or "802.1x" in rsn_flags:
            return "WPA2"
        
        # Check for WPA1
        if "wpa" in security.lower():
            return "WPA"

        return "Unknown"

    def _rate_security(self) -> Tuple[str, str]:
        """Rate the security of the current connection"""
        sec_type = str(self.security_type).upper()

        if not self.security_type or "OPEN" in sec_type:
            return "CRITICAL", "Open networks are completely unencrypted."
        
        if "WEP" in sec_type:
            return "CRITICAL", "WEP encryption is obsolete and easily broken."
            
        if "WPA" in sec_type and "WPA2" not in sec_type and "WPA3" not in sec_type:
            return "WARNING", "WPA is vulnerable; WPA2 or WPA3 is recommended."

        # Placeholder for weak password detection
        # self._check_password_strength()

        return "INFO", "Network appears to be using strong encryption."

    def _check_password_strength(self) -> None:
        """Placeholder for weak password detection logic"""
        # This would require user input or access to saved network profiles
        # Example logic:
        # password = get_wifi_password(self.current_ssid)
        # if len(password) < 8:
        #     self.logger.log_event("wifi_analyzer", "WARNING", ...)
        pass
    
    def get_status(self) -> Dict:
        """Get current WiFi status"""
        is_secure = self.security_type not in ["Open", "WEP", "", None] if self.security_type else False
        security_rating, risk = self._rate_security()
        
        return {
            "ssid": self.current_ssid,
            "security": self.security_type,
            "signal_strength": self.signal_strength,
            "is_secure": is_secure,
            "security_rating": security_rating,
            "risk_description": risk
        }


# ============================================================================
# EVIL TWIN DETECTOR
# ============================================================================

@dataclass
class NetworkProfile:
    """Stores profile of a trusted WiFi network"""
    ssid: str
    bssid: str
    security_type: str
    signal_strength: int
    first_seen: datetime = field(default_factory=datetime.now)

class EvilTwinDetector:
    """Detects Evil Twin attacks by profiling and monitoring WiFi networks"""

    def __init__(self, config: SecurityConfig, logger: ForensicsLogger):
        self.config = config
        self.logger = logger
        self.running = False
        self.trusted_networks: Dict[str, NetworkProfile] = {}
        self.monitor_thread: Optional[threading.Thread] = None
        self.ssid_bssid_history = []  # Will store dicts with 'ssid', 'bssid_hash', 'signal', 'timestamp', 'event'
        self.anomaly_detector = WiFiAnomalyDetector(logger)

    def start(self) -> None:
        """Start Evil Twin detection"""
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        self.logger.log_event(
            "evil_twin_detector",
            "INFO",
            {"message": "Evil Twin detection started"}
        )

    def stop(self) -> None:
        """Stop detector"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5.0)

    def _monitor_loop(self) -> None:
        """Main monitoring loop for scanning networks"""
        while self.running:
            try:
                self._scan_and_analyze()
                time.sleep(self.config.evil_twin_scan_interval)
            except Exception as e:
                self.logger.log_event(
                    "evil_twin_detector",
                    "ERROR",
                    {"message": "Evil Twin scan error", "error": str(e)}
                )
                time.sleep(self.config.evil_twin_scan_interval)

    def _scan_and_analyze(self) -> None:
        """Scans for WiFi networks and analyzes them for threats"""
        # This is a placeholder for platform-specific WiFi scanning logic
        # For a production system, this would use native libraries or tools
        # Example using `nmcli` on Linux:
        if platform.system() == "Linux":
            try:
                result = subprocess.run(
                    ["nmcli", "-t", "-f", "ssid,bssid,security,signal", "dev", "wifi", "list"],
                    capture_output=True, text=True, timeout=15
                )
                
                seen_ssids = defaultdict(list)
                now = time.time()
                for line in result.stdout.strip().split("\n"):
                    parts = line.split(":")
                    if len(parts) >= 4:
                        ssid, bssid, security, signal = parts[0], parts[1], parts[2], int(parts[3])
                        bssid_hash = hashlib.sha256(bssid.encode()).hexdigest()
                        profile = NetworkProfile(ssid, bssid, security, signal)
                        seen_ssids[ssid].append(profile)
                        # Log (hashed) BSSID history for forensics & future anomaly checks
                        self.ssid_bssid_history.append({
                            'ssid': ssid,
                            'bssid_hash': bssid_hash,
                            'signal': signal,
                            'timestamp': now,
                            'event': 'scan'
                        })
                        self.logger.log_event(
                            "evil_twin_scan",
                            "INFO",
                            {
                                "ssid": ssid,
                                "bssid_hash": bssid_hash,
                                "signal": signal,
                                "timestamp": now
                            }
                        )
                        # -- NEW: anomaly module --
                        self.anomaly_detector.observe(ssid, bssid, signal)

                self._analyze_profiles(seen_ssids)

            except FileNotFoundError:
                self.logger.log_event("evil_twin_detector", "WARNING", {"message": "nmcli not found, cannot scan for evil twins."})
            except Exception as e:
                 self.logger.log_event("evil_twin_detector", "ERROR", {"message": "Failed to execute nmcli scan", "error": str(e)})

    def _analyze_profiles(self, seen_ssids: Dict[str, List[NetworkProfile]]) -> None:
        """Analyzes scanned network profiles for anomalies"""
        for ssid, profiles in seen_ssids.items():
            if len(profiles) > 1:
                # Multiple APs with the same SSID - potential Evil Twin
                is_open = any("Open" in p.security_type for p in profiles)
                is_encrypted = any("WPA" in p.security_type for p in profiles)

                if is_open and is_encrypted:
                    self.logger.log_event(
                        "evil_twin_detector",
                        "CRITICAL",
                        {
                            "message": "EVIL TWIN DETECTED: Unencrypted & encrypted network with same SSID",
                            "ssid": ssid,
                            "details": f"Detected {len(profiles)} access points for this SSID.",
                            "risk": "An attacker is likely broadcasting an open network to intercept traffic."
                        }
                    )

    def trust_network(self, profile: NetworkProfile) -> None:
        """Explicitly trust a network profile"""
        if self.config.trust_on_first_use and profile.ssid not in self.trusted_networks:
            self.trusted_networks[profile.ssid] = profile
            self.logger.log_event(
                "evil_twin_detector",
                "INFO",
                {
                    "message": "Trusting new network (Trust on First Use)",
                    "ssid": profile.ssid,
                    "bssid": profile.bssid,
                    "security": profile.security_type
                }
            )

# ============================================================================
# TRAFFIC ENCAPSULATOR (VPN MANAGER)
# ============================================================================

class TrafficEncapsulator:
    """Manages VPN connections to secure traffic on untrusted networks"""

    def __init__(self, config: SecurityConfig, logger: ForensicsLogger):
        self.config = config
        self.logger = logger
        self.is_vpn_active = False

    def check_and_enforce_vpn(self, is_network_secure: bool) -> None:
        """Check current network security and enforce VPN if necessary"""
        if not self.config.auto_vpn_on_insecure:
            return

        self.is_vpn_active = self._check_vpn_status()

        if not is_network_secure and not self.is_vpn_active:
            self.logger.log_event(
                "vpn_manager",
                "WARNING",
                {"message": "Insecure network detected. Attempting to activate VPN."}
            )
            if self._activate_vpn():
                self.is_vpn_active = True
                self.logger.log_event(
                    "vpn_manager",
                    "INFO",
                    {"message": f"VPN '{self.config.vpn_connection_name}' activated successfully."}
                )
            else:
                self.logger.log_event(
                    "vpn_manager",
                    "CRITICAL",
                    {
                        "message": "FAILED TO ACTIVATE VPN ON INSECURE NETWORK!",
                        "recommendation": "Disconnect from this network immediately to protect your data."
                    }
                )
    
    def _check_vpn_status(self) -> bool:
        """Check if the configured VPN connection is active"""
        try:
            if platform.system() == "Linux":
                result = subprocess.run(
                    ["nmcli", "-t", "-f", "NAME,TYPE,STATE", "con"],
                    capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.splitlines():
                    name, type, state = line.split(":")
                    if name == self.config.vpn_connection_name and type == "vpn" and state == "activated":
                        return True

            elif platform.system() == "Windows":
                # Checking VPN status on Windows is more complex.
                # This is a simplified check.
                result = subprocess.run(
                    ["rasdial"], capture_output=True, text=True, timeout=5
                )
                if self.config.vpn_connection_name in result.stdout:
                    return True

        except Exception as e:
            self.logger.log_event("vpn_manager", "ERROR", {"message": "Failed to check VPN status", "error": str(e)})
        
        return False

    def _activate_vpn(self) -> bool:
        """Activate the pre-configured VPN connection"""
        try:
            if platform.system() == "Linux":
                result = subprocess.run(
                    ["nmcli", "con", "up", self.config.vpn_connection_name],
                    capture_output=True, text=True, timeout=30
                )
                return "successfully activated" in result.stdout.lower()
            
            elif platform.system() == "Windows":
                # Assumes VPN is configured to not require username/password interactively
                result = subprocess.run(
                    ["rasdial", self.config.vpn_connection_name],
                    capture_output=True, text=True, timeout=30
                )
                return "command completed successfully" in result.stdout.lower()

        except Exception as e:
            self.logger.log_event("vpn_manager", "ERROR", {"message": "Failed to activate VPN", "error": str(e)})
        
        return False

# ============================================================================
# DNS SECURITY ENHANCER
# ============================================================================

class DNSSecurityEnhancer:
    """Detects DNS spoofing by comparing system DNS with a DoH resolver"""

    def __init__(self, config: SecurityConfig, logger: ForensicsLogger):
        self.config = config
        self.logger = logger
        self.running = False
        self.monitor_thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start DNS spoofing detection"""
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        self.logger.log_event("dns_security", "INFO", {"message": "DNS spoofing detection started"})

    def stop(self) -> None:
        """Stop DNS monitoring"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5.0)

    def _monitor_loop(self) -> None:
        """Periodically check for DNS spoofing"""
        while self.running:
            try:
                for domain in self.config.dns_check_domains:
                    self.check_domain(domain)
                    time.sleep(2) # Stagger checks
                time.sleep(self.config.dns_spoof_check_interval)
            except Exception as e:
                self.logger.log_event("dns_security", "ERROR", {"message": "DNS monitor loop error", "error": str(e)})

    def check_domain(self, domain: str) -> None:
        """Compare system DNS and DoH for a single domain"""
        try:
            system_ips = self._get_system_dns(domain)
            doh_ips = self._get_doh_dns(domain)

            if not system_ips or not doh_ips:
                self.logger.log_event("dns_security", "WARNING", {"message": "Could not resolve domain via one of the methods", "domain": domain})
                return

            if not system_ips.intersection(doh_ips):
                self.logger.log_event(
                    "dns_security",
                    "CRITICAL",
                    {
                        "message": "DNS SPOOFING DETECTED!",
                        "domain": domain,
                        "system_dns_results": sorted(list(system_ips)),
                        "doh_dns_results": sorted(list(doh_ips)),
                        "risk": "Your DNS queries are likely being redirected to a malicious server."
                    }
                )
        except Exception as e:
            self.logger.log_event("dns_security", "ERROR", {"message": f"Failed to check domain {domain}", "error": str(e)})

    def _get_system_dns(self, domain: str) -> Set[str]:
        """Get IP addresses for a domain using system's default DNS"""
        try:
            ips = socket.getaddrinfo(domain, None, family=socket.AF_INET)
            return {ip[4][0] for ip in ips}
        except socket.gaierror:
            return set()

    def _get_doh_dns(self, domain: str) -> Set[str]:
        """Get IP addresses for a domain using a DoH resolver"""
        try:
            params = {"name": domain, "type": "A"}
            response = requests.get(self.config.doh_resolver_url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            if "Answer" in data:
                return {answer["data"] for answer in data["Answer"] if answer["type"] == 1} # Type 1 is 'A' record
        except requests.RequestException as e:
            self.logger.log_event("dns_security", "WARNING", {"message": "DoH request failed", "error": str(e)})
        
        return set()

# ============================================================================
# SESSION HIJACKING DETECTOR
# ============================================================================

class SessionProtector:
    """Detects insecure cookies and session tokens to prevent hijacking"""

    def __init__(self, config: SecurityConfig, logger: ForensicsLogger):
        self.config = config
        self.logger = logger
        self.running = False
        self.sniffer_thread: Optional[threading.Thread] = None
        self.detected_hosts: Set[str] = set()

    def start(self) -> None:
        """Start session hijacking detection"""
        if not self.config.enable_session_hijack_detection:
            return
            
        self.running = True
        self.sniffer_thread = threading.Thread(target=self._start_sniffer, daemon=True)
        self.sniffer_thread.start()
        self.logger.log_event("session_protector", "INFO", {"message": "Session hijacking detection started"})

    def stop(self) -> None:
        """Stop session monitoring"""
        self.running = False
        # The sniffer will stop on its own when the running flag is false

    def _start_sniffer(self) -> None:
        """Initializes the Scapy sniffer"""
        try:
            sniff(filter="tcp port 80", prn=self._packet_callback, stop_filter=self._should_stop_sniffing)
        except Exception as e:
            self.logger.log_event("session_protector", "ERROR", {"message": "Failed to start packet sniffer. Ensure you have libpcap/WinPcap installed and run with root/admin privileges.", "error": str(e)})

    def _should_stop_sniffing(self, packet) -> bool:
        return not self.running

    def _packet_callback(self, packet) -> None:
        """Callback for each captured packet"""
        if not packet.haslayer(TCP) or not packet.haslayer(Raw):
            return

        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            headers = payload.split("\r\n")
            
            host = ""
            cookie_line = ""

            for header in headers:
                if header.lower().startswith("host:"):
                    host = header.split(":", 1)[1].strip()
                elif header.lower().startswith("cookie:"):
                    cookie_line = header.split(":", 1)[1].strip()

            if host and host not in self.detected_hosts:
                self._check_for_ssl_stripping(host)
                if cookie_line:
                    self._analyze_cookies(host, cookie_line)

        except Exception:
            pass # Ignore parsing errors

    def _check_for_ssl_stripping(self, host: str) -> None:
        """Check if an HTTP connection is made to a host that should be HTTPS"""
        for enforced_host in self.config.https_enforced_hosts:
            if enforced_host in host:
                self.logger.log_event(
                    "ssl_stripping_detector",
                    "CRITICAL",
                    {
                        "message": "SSL STRIPPING ATTACK DETECTED!",
                        "host": host,
                        "risk": f"Connection to '{host}' is unencrypted (HTTP), but it should be encrypted (HTTPS).",
                        "recommendation": "Do not enter any sensitive information on this site. Your connection is being monitored."
                    }
                )
                self.detected_hosts.add(host)
                return

    def _analyze_cookies(self, host: str, cookie_line: str) -> None:
        """Analyzes cookies for insecure properties"""
        cookies = [c.strip() for c in cookie_line.split(';')]
        
        for cookie in cookies:
            try:
                cookie_name = cookie.split("=")[0]
                for keyword in self.config.insecure_cookie_keywords:
                    if keyword in cookie_name.lower():
                        self.logger.log_event(
                            "session_protector",
                            "CRITICAL",
                            {
                                "message": "INSECURE SESSION COOKIE DETECTED!",
                                "host": host,
                                "cookie_name": cookie_name,
                                "risk": f"Sensitive cookie '{cookie_name}' sent over unencrypted HTTP. This can be easily stolen.",
                                "recommendation": "Avoid using this website on insecure networks."
                            }
                        )
                        self.detected_hosts.add(host) # Report only once per host per session
                        return
            except IndexError:
                continue


# ============================================================================
# DHCP SPOOFING DETECTOR
# ============================================================================

class DHCPWatcher:
    """Monitors for rogue DHCP servers on the network"""

    def __init__(self, config: SecurityConfig, logger: ForensicsLogger):
        self.config = config
        self.logger = logger
        self.running = False
        self.sniffer_thread: Optional[threading.Thread] = None
        self.legit_dhcp_server: Optional[str] = None

    def start(self) -> None:
        if not self.config.enable_dhcp_monitoring:
            return
        
        self.running = True
        self.sniffer_thread = threading.Thread(target=self._start_sniffer, daemon=True)
        self.sniffer_thread.start()
        self.logger.log_event("dhcp_watcher", "INFO", {"message": "DHCP monitoring started."})

    def stop(self) -> None:
        self.running = False

    def _start_sniffer(self) -> None:
        try:
            sniff(filter="udp and (port 67 or 68)", prn=self._packet_callback, store=0, stop_filter=self._should_stop_sniffing)
        except Exception as e:
            self.logger.log_event("dhcp_watcher", "ERROR", {"message": "Failed to start DHCP sniffer. Ensure you have libpcap/WinPcap installed and run with root/admin privileges.", "error": str(e)})

    def _should_stop_sniffing(self, packet) -> bool:
        return not self.running

    def _packet_callback(self, packet) -> None:
        if packet.haslayer(DHCP):
            dhcp_packet = packet[DHCP]
            if dhcp_packet.options[0][1] == 2: # DHCP Offer
                server_ip = packet[BOOTP].siaddr
                if self.legit_dhcp_server is None:
                    self.legit_dhcp_server = server_ip
                    self.logger.log_event("dhcp_watcher", "INFO", {"message": f"Legitimate DHCP server identified: {server_ip}"})
                elif server_ip != self.legit_dhcp_server:
                    self.logger.log_event(
                        "dhcp_watcher",
                        "CRITICAL",
                        {
                            "message": "ROGUE DHCP SERVER DETECTED!",
                            "legitimate_server": self.legit_dhcp_server,
                            "rogue_server": server_ip,
                            "risk": "A rogue DHCP server can redirect your traffic through an attacker's machine."
                        }
                    )

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
        if self.config.enable_static_arp and self.gateway_ip:
            clear_static_arp(self.gateway_ip, self.logger)
    
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
        if self.config.enable_interface_isolation:
            # pass detected Wi-Fi iface name
            isolate_interface(self._get_wireless_iface(), self.logger)
    
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

    def _get_wireless_iface(self) -> Optional[str]:
        """Attempt to discover the Wi-Fi interface name."""
        try:
            if platform.system() == "Linux":
                result = subprocess.run(
                    ["nmcli", "-t", "-f", "NAME,TYPE,STATE", "dev", "wifi"],
                    capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.splitlines():
                    name, type, state = line.split(":")
                    if type == "wifi" and state == "connected":
                        return name
            elif platform.system() == "Windows":
                result = subprocess.run(
                    ["netsh", "wlan", "show", "interfaces"],
                    capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.splitlines():
                    if "SSID" in line:
                        parts = line.split()
                        if len(parts) > 1:
                            return parts[1]
        except Exception as e:
            self.logger.log_event(
                "arp_monitor",
                "WARNING",
                {"message": "Failed to discover wireless interface", "error": str(e)}
            )
        return None


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
        self.evil_twin_detector = EvilTwinDetector(self.config, self.logger)
        self.vpn_manager = TrafficEncapsulator(self.config, self.logger)
        self.dns_enhancer = DNSSecurityEnhancer(self.config, self.logger)
        self.session_protector = SessionProtector(self.config, self.logger)
        self.dhcp_watcher = DHCPWatcher(self.config, self.logger)
        
        self.running = False
        self.main_loop_thread: Optional[threading.Thread] = None
    
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
        self.evil_twin_detector.start()
        self.dns_enhancer.start()
        self.session_protector.start()
        self.dhcp_watcher.start()
        
        # start gratuitous_arp monitor
        if self.config.enable_gratuitous_arp:
            start_gratuitous_arp_monitor(self.logger)
        # tcp_metrics
        if self.config.enable_tcp_metrics:
            self.tcp_metrics = TCPMetricsMonitor(self.logger)
            self.tcp_metrics.start()
        
        self.logger.log_event(
            "system",
            "INFO",
            {"message": "All defense systems operational"}
        )

        # Start the main coordination loop
        self.main_loop_thread = threading.Thread(target=self._coordination_loop, daemon=True)
        self.main_loop_thread.start()
    
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
        self.evil_twin_detector.stop()
        self.dns_enhancer.stop()
        self.session_protector.stop()
        self.dhcp_watcher.stop()

        # stop gratuitous arp
        if self.config.enable_gratuitous_arp:
            stop_gratuitous_arp_monitor()
        if hasattr(self, 'tcp_metrics'):
            self.tcp_metrics.stop()

        if self.main_loop_thread:
            self.main_loop_thread.join(timeout=2.0)
    
    def _coordination_loop(self) -> None:
        """Main loop for coordinating actions between components"""
        while self.running:
            try:
                # 1. Check network security and enforce VPN if needed
                wifi_status = self.wifi_analyzer.get_status()
                is_secure = wifi_status.get("is_secure", True)
                self.vpn_manager.check_and_enforce_vpn(is_secure)

                # Add other coordination logic here in the future
                
                time.sleep(15) # Check every 15 seconds
            except Exception as e:
                self.logger.log_event("system_coordinator", "ERROR", {"message": "Coordination loop error", "error": str(e)})
    
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
            "evil_twin": { "trusted_networks": len(self.evil_twin_detector.trusted_networks) },
            "vpn_status": { "active": self.vpn_manager.is_vpn_active },
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
    print("Privacy Guard - Advanced Network Defense System")
    print("=" * 80)
    print()
    
    # Create configuration
    config = SecurityConfig(
        arp_monitor_interval=5.0,
        honeypot_enabled=True,
        honeypot_ports=[8080, 8443, 3306],
        honeypot_log_full_requests=True,
        wifi_security_check_interval=30.0,
        forensics_log_path="./enhanced_logs",
        enable_session_hijack_detection=True,
        enable_dhcp_monitoring=True,
        enable_desktop_notifications=True,
        enable_static_arp=True,
        enable_tcp_metrics=True,
        enable_interface_isolation=True,
        enable_gratuitous_arp=True
    )
    
    # Initialize system
    defense = MITMDefenseSystem(config)
    
    print("[+] Starting Privacy Guard defense systems...")
    defense.start()
    print("[+] All systems operational\n")
    
    # Show initial status
    status = defense.get_status()
    print("System Status:")
    print(json.dumps(status, indent=2))
    print()
    
    # Simulate monitoring period
    print("[+] Monitoring network for threats (30 seconds)...")
    print("    - ARP & DHCP Monitoring")
    print("    - Port Scan Detection")
    print("    - Honeypot Services")
    print("    - WiFi Security & Evil Twin Analysis")
    print("    - DNS Spoofing Detection")
    print("    - Session & SSL Strip Monitoring")
    print("    - Auto-VPN on Insecure Networks")
    print("    - Real-time Desktop Notifications")
    print()
    
    try:
        time.sleep(30)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
    
    # Validate a TLS endpoint
    print("[+] Testing TLS validation against example.com...")
    tls_result = defense.validate_tls_endpoint("example.com", 443)
    
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
        if not wifi_status['is_secure']:
            print(f"    Risk: {wifi_status.get('risk_description', 'N/A')}")
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