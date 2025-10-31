"""
WiFi Security Analyzer
Detects security risks and vulnerabilities in WiFi networks.

Original Author: Joseph (network_security_analyzer.py)
Enhanced and integrated: October 31, 2025

Features:
- Cross-platform WiFi analysis (Windows/Linux/macOS)
- Encryption strength assessment
- Suspicious SSID detection
- Gateway and DNS validation
- Rogue AP detection indicators
- Risk scoring system
"""

import subprocess
import platform
import re
import socket
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from collections import defaultdict

logger = logging.getLogger(__name__)


class WiFiSecurityAnalyzer:
    """
    Comprehensive WiFi security analyzer for detecting network threats.
    Compatible with Windows, Linux, and macOS.
    """
    
    def __init__(self):
        """Initialize WiFi Security Analyzer"""
        self.os_type = platform.system()
        self.risk_score = 0
        self.risks = []
        self.warnings = []
        self.info_items = []
        self.network_info = {}
        
        # Known suspicious SSIDs (common in evil twin/rogue AP attacks)
        self.suspicious_ssids = [
            'Free WiFi', 'Free_WiFi', 'FreeWiFi',
            'Public WiFi', 'Guest', 'Free Internet',
            'Starbucks', 'McDonalds', 'Airport WiFi',
            'Hotel WiFi', 'attwifi', 'xfinitywifi',
            'Free Public WiFi', 'WiFi', 'Internet'
        ]
        
        # Legitimate vendor MAC prefixes (OUI - first 3 octets)
        self.known_legitimate_oui = {
            '00:1A:2B': 'Cisco Systems',
            '00:50:56': 'VMware',
            'F4:F5:D8': 'Google',
            '00:23:6C': 'Apple',
            '00:1B:63': 'Apple',
            '00:25:00': 'Apple',
            'AC:DE:48': 'Apple',
            '00:0C:29': 'VMware',
            '00:50:F2': 'Microsoft',
            '00:15:5D': 'Microsoft',
            'D0:50:99': 'TP-Link',
            '50:C7:BF': 'TP-Link',
            'E8:DE:27': 'TP-Link',
            'A0:F3:C1': 'Ubiquiti',
            'DC:9F:DB': 'Ubiquiti',
            '00:1D:73': 'Cisco',
            '00:22:90': 'Cisco',
        }
        
        logger.info(f"WiFi Security Analyzer initialized on {self.os_type}")
    
    def run_command(self, command: str, timeout: int = 10) -> str:
        """
        Execute system command and return output
        
        Args:
            command: Command to execute
            timeout: Timeout in seconds
        
        Returns:
            Command output as string
        """
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            logger.error(f"Command timeout: {command}")
            return ""
        except Exception as e:
            logger.error(f"Command error: {e}")
            return f"Error: {str(e)}"
    
    def get_current_ssid(self) -> Optional[str]:
        """Get currently connected SSID"""
        try:
            if self.os_type == "Windows":
                output = self.run_command("netsh wlan show interfaces")
                match = re.search(r"SSID\s+:\s+(.+)", output)
                return match.group(1).strip() if match else None
            
            elif self.os_type == "Linux":
                output = self.run_command("iwgetid -r")
                return output.strip() if output.strip() else None
            
            elif self.os_type == "Darwin":  # macOS
                output = self.run_command(
                    "/System/Library/PrivateFrameworks/Apple80211.framework/"
                    "Versions/Current/Resources/airport -I"
                )
                match = re.search(r"\sSSID:\s+(.+)", output)
                return match.group(1).strip() if match else None
        
        except Exception as e:
            logger.error(f"Error getting SSID: {e}")
            return None
    
    def get_network_details(self) -> Dict:
        """Retrieve detailed network configuration"""
        details = {
            'ssid': None,
            'bssid': None,
            'signal': None,
            'channel': None,
            'encryption': None,
            'authentication': None,
            'gateway': None,
            'dns_servers': [],
            'ip_address': None,
            'mac_address': None,
            'subnet_mask': None
        }
        
        try:
            if self.os_type == "Windows":
                self._get_windows_details(details)
            elif self.os_type == "Linux":
                self._get_linux_details(details)
            elif self.os_type == "Darwin":
                self._get_macos_details(details)
        
        except Exception as e:
            logger.error(f"Error gathering network details: {e}")
        
        self.network_info = details
        return details
    
    def _get_windows_details(self, details: Dict):
        """Get network details on Windows"""
        # Wireless interface info
        output = self.run_command("netsh wlan show interfaces")
        details['ssid'] = self._extract_value(output, r"SSID\s+:\s+(.+)")
        details['bssid'] = self._extract_value(output, r"BSSID\s+:\s+(.+)")
        details['signal'] = self._extract_value(output, r"Signal\s+:\s+(.+)")
        details['channel'] = self._extract_value(output, r"Channel\s+:\s+(.+)")
        details['encryption'] = self._extract_value(output, r"Cipher\s+:\s+(.+)")
        details['authentication'] = self._extract_value(output, r"Authentication\s+:\s+(.+)")
        
        # Network configuration
        ipconfig = self.run_command("ipconfig /all")
        details['gateway'] = self._extract_value(ipconfig, r"Default Gateway.*:\s+([0-9.]+)")
        details['ip_address'] = self._extract_value(ipconfig, r"IPv4 Address.*:\s+([0-9.]+)")
        details['subnet_mask'] = self._extract_value(ipconfig, r"Subnet Mask.*:\s+([0-9.]+)")
        details['mac_address'] = self._extract_value(ipconfig, r"Physical Address.*:\s+([0-9A-Fa-f-]+)")
        
        dns_matches = re.findall(r"DNS Servers.*:\s+([0-9.]+)", ipconfig)
        details['dns_servers'] = dns_matches
    
    def _get_linux_details(self, details: Dict):
        """Get network details on Linux"""
        # Wireless info
        iwconfig = self.run_command("iwconfig 2>/dev/null")
        details['ssid'] = self._extract_value(iwconfig, r'ESSID:"(.+?)"')
        details['bssid'] = self._extract_value(iwconfig, r"Access Point:\s+([0-9A-Fa-f:]+)")
        
        # Get encryption info
        ssid = details['ssid']
        if ssid:
            iwlist = self.run_command(f'sudo iwlist scan 2>/dev/null | grep -A 20 \'ESSID:"{ssid}"\'')
            if "WPA3" in iwlist:
                details['encryption'] = "WPA3"
            elif "WPA2" in iwlist:
                details['encryption'] = "WPA2"
            elif "WPA" in iwlist:
                details['encryption'] = "WPA"
            elif "WEP" in iwlist:
                details['encryption'] = "WEP"
            else:
                details['encryption'] = "Open"
        
        # Network config
        ip_route = self.run_command("ip route | grep default")
        details['gateway'] = self._extract_value(ip_route, r"default via ([0-9.]+)")
        
        ip_addr = self.run_command("ip addr show")
        details['ip_address'] = self._extract_value(ip_addr, r"inet ([0-9.]+)/")
        details['mac_address'] = self._extract_value(ip_addr, r"link/ether ([0-9A-Fa-f:]+)")
        
        resolv = self.run_command("cat /etc/resolv.conf 2>/dev/null")
        dns_matches = re.findall(r"nameserver\s+([0-9.]+)", resolv)
        details['dns_servers'] = dns_matches
    
    def _get_macos_details(self, details: Dict):
        """Get network details on macOS"""
        airport = self.run_command(
            "/System/Library/PrivateFrameworks/Apple80211.framework/"
            "Versions/Current/Resources/airport -I"
        )
        details['ssid'] = self._extract_value(airport, r"\sSSID:\s+(.+)")
        details['bssid'] = self._extract_value(airport, r"BSSID:\s+(.+)")
        details['channel'] = self._extract_value(airport, r"channel:\s+(.+)")
        
        # Network config
        netstat = self.run_command("netstat -nr | grep default")
        details['gateway'] = self._extract_value(netstat, r"default\s+([0-9.]+)")
        
        ifconfig = self.run_command("ifconfig")
        details['ip_address'] = self._extract_value(ifconfig, r"inet ([0-9.]+)")
        details['mac_address'] = self._extract_value(ifconfig, r"ether ([0-9A-Fa-f:]+)")
        
        scutil = self.run_command("scutil --dns")
        dns_matches = re.findall(r"nameserver\[0\] : ([0-9.]+)", scutil)
        details['dns_servers'] = dns_matches
    
    def _extract_value(self, text: str, pattern: str) -> Optional[str]:
        """Helper to extract value using regex"""
        match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        return match.group(1).strip() if match else None
    
    def analyze(self) -> Dict:
        """
        Perform complete WiFi security analysis
        
        Returns:
            Dictionary with analysis results
        """
        logger.info("Starting WiFi security analysis...")
        
        # Reset state
        self.risk_score = 0
        self.risks = []
        self.warnings = []
        self.info_items = []
        
        # Gather network details
        self.get_network_details()
        
        if not self.network_info.get('ssid'):
            logger.warning("Not connected to WiFi")
            return {
                'connected': False,
                'message': 'Not connected to a WiFi network'
            }
        
        # Run all security checks
        self.check_encryption_security()
        self.check_suspicious_ssid()
        self.check_bssid_legitimacy()
        self.check_gateway_dns()
        self.check_signal_strength()
        
        # Determine overall risk level
        risk_level = self._calculate_risk_level()
        
        result = {
            'connected': True,
            'network_info': self.network_info,
            'risk_score': self.risk_score,
            'risk_level': risk_level,
            'risks': self.risks,
            'warnings': self.warnings,
            'info': self.info_items,
            'timestamp': datetime.now().isoformat()
        }
        
        logger.info(f"Analysis complete. Risk level: {risk_level} (score: {self.risk_score})")
        return result
    
    def check_encryption_security(self):
        """Analyze encryption type and security"""
        encryption = (self.network_info.get('encryption') or '').upper()
        auth = (self.network_info.get('authentication') or '').upper()
        
        if not encryption or encryption == "OPEN" or encryption == "NONE":
            self.risks.append({
                'severity': 'CRITICAL',
                'message': 'Network has NO encryption - all traffic is visible',
                'recommendation': 'Avoid this network or use VPN'
            })
            self.risk_score += 50
        
        elif "WEP" in encryption:
            self.risks.append({
                'severity': 'HIGH',
                'message': 'WEP encryption is obsolete and easily crackable',
                'recommendation': 'Use a network with WPA2/WPA3'
            })
            self.risk_score += 40
        
        elif "WPA" in encryption and "WPA2" not in encryption and "WPA3" not in encryption:
            self.warnings.append({
                'severity': 'MEDIUM',
                'message': 'WPA encryption is outdated',
                'recommendation': 'WPA2 or WPA3 recommended'
            })
            self.risk_score += 25
        
        elif "WPA2" in encryption:
            self.info_items.append("✓ WPA2 encryption detected (good security)")
        
        elif "WPA3" in encryption:
            self.info_items.append("✓ WPA3 encryption detected (excellent security)")
        
        else:
            self.warnings.append({
                'severity': 'LOW',
                'message': f'Unknown encryption type: {encryption}'
            })
    
    def check_suspicious_ssid(self):
        """Check for suspicious or common attack SSID patterns"""
        ssid = self.network_info.get('ssid', '')
        
        if not ssid:
            return
        
        # Check against known suspicious SSIDs
        for suspicious in self.suspicious_ssids:
            if suspicious.lower() in ssid.lower():
                self.risks.append({
                    'severity': 'HIGH',
                    'message': f'Suspicious SSID detected: "{ssid}" (common in rogue AP attacks)',
                    'recommendation': 'Verify this is a legitimate network before connecting'
                })
                self.risk_score += 35
                return
        
        # Check for generic/unusual names
        if len(ssid) < 3 or ssid.lower() in ['wifi', 'network', 'internet']:
            self.warnings.append({
                'severity': 'MEDIUM',
                'message': f'Generic SSID name: "{ssid}"',
                'recommendation': 'Verify network legitimacy'
            })
            self.risk_score += 10
    
    def check_bssid_legitimacy(self):
        """Check BSSID (MAC address) against known vendors"""
        bssid = self.network_info.get('bssid', '')
        
        if not bssid:
            return
        
        # Extract OUI (first 3 octets)
        oui = ':'.join(bssid.split(':')[:3]).upper()
        
        vendor = self.known_legitimate_oui.get(oui)
        if vendor:
            self.info_items.append(f"✓ AP vendor identified: {vendor}")
        else:
            self.warnings.append({
                'severity': 'LOW',
                'message': f'Unknown AP vendor (MAC: {bssid})',
                'recommendation': 'Research this MAC address prefix'
            })
    
    def check_gateway_dns(self):
        """Validate gateway and DNS server configurations"""
        gateway = self.network_info.get('gateway')
        dns_servers = self.network_info.get('dns_servers', [])
        
        if gateway:
            self.info_items.append(f"Gateway: {gateway}")
            
            # Check if gateway is in private IP range
            if not self._is_private_ip(gateway):
                self.warnings.append({
                    'severity': 'MEDIUM',
                    'message': f'Gateway {gateway} is not a private IP',
                    'recommendation': 'This is unusual for local networks'
                })
                self.risk_score += 15
        
        if dns_servers:
            for dns in dns_servers:
                self.info_items.append(f"DNS Server: {dns}")
                
                # Check for common legitimate DNS servers
                if dns not in ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1'] and not self._is_private_ip(dns):
                    self.warnings.append({
                        'severity': 'LOW',
                        'message': f'Unusual DNS server: {dns}',
                        'recommendation': 'Verify DNS server legitimacy'
                    })
    
    def check_signal_strength(self):
        """Analyze signal strength for proximity indicators"""
        signal = self.network_info.get('signal', '')
        
        if not signal:
            return
        
        # Extract percentage if present
        match = re.search(r'(\d+)%', signal)
        if match:
            strength = int(match.group(1))
            
            if strength < 30:
                self.warnings.append({
                    'severity': 'LOW',
                    'message': f'Weak signal: {strength}%',
                    'recommendation': 'Move closer to AP or check for interference'
                })
            elif strength >= 70:
                self.info_items.append(f"✓ Strong signal: {strength}%")
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        try:
            parts = [int(p) for p in ip.split('.')]
            if len(parts) != 4:
                return False
            
            # Private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            return (
                parts[0] == 10 or
                (parts[0] == 172 and 16 <= parts[1] <= 31) or
                (parts[0] == 192 and parts[1] == 168)
            )
        except:
            return False
    
    def _calculate_risk_level(self) -> str:
        """Calculate overall risk level from score"""
        if self.risk_score >= 50:
            return "CRITICAL"
        elif self.risk_score >= 30:
            return "HIGH"
        elif self.risk_score >= 15:
            return "MEDIUM"
        elif self.risk_score >= 5:
            return "LOW"
        else:
            return "MINIMAL"
    
    def get_summary(self) -> str:
        """Get human-readable summary"""
        if not self.network_info.get('ssid'):
            return "Not connected to WiFi"
        
        ssid = self.network_info['ssid']
        encryption = self.network_info.get('encryption', 'Unknown')
        risk_level = self._calculate_risk_level()
        
        summary = f"Network: {ssid}\n"
        summary += f"Encryption: {encryption}\n"
        summary += f"Risk Level: {risk_level} (Score: {self.risk_score})\n"
        summary += f"\nRisks: {len(self.risks)}, Warnings: {len(self.warnings)}\n"
        
        return summary
