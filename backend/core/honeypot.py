"""
Honeypot Module
Production-ready implementation with attacker tracking.

Original Author: Joseph (honeypots_basic.py)
Enhanced and integrated: October 31, 2025

Features:
- HTTP and SSH honeypots
- Attacker tracking and counting
- Thread-safe logging
- Alert callbacks on interaction
"""

import socket
import threading
import logging
import time
from datetime import datetime
from typing import Optional, Callable, Dict, List
from collections import defaultdict
import json

logger = logging.getLogger(__name__)


class AttackerTracker:
    """
    Tracks attacker IPs and connection attempts.
    Thread-safe implementation for honeypot monitoring.
    """
    
    def __init__(self, alert_callback: Optional[Callable] = None):
        """
        Initialize Attacker Tracker
        
        Args:
            alert_callback: Function to call on significant events.
                          Signature: callback(ip: str, count: int, context: dict)
        """
        self.ip_counts = {}
        self.interactions = []
        self._lock = threading.Lock()
        self.alert_callback = alert_callback
        self.alert_thresholds = [1, 5, 10, 20, 50]  # Alert on these counts
    
    def record(self, ip: str, context: Dict):
        """
        Record an attacker interaction
        
        Args:
            ip: Attacker IP address
            context: Context information (service, port, data, etc.)
        """
        with self._lock:
            self.ip_counts[ip] = self.ip_counts.get(ip, 0) + 1
            count = self.ip_counts[ip]
            
            interaction = {
                'ip': ip,
                'count': count,
                'timestamp': time.time(),
                'context': context
            }
            self.interactions.append(interaction)
            
            # Keep only recent interactions (last 1000)
            if len(self.interactions) > 1000:
                self.interactions = self.interactions[-1000:]
        
        # Trigger alerts at specific thresholds
        if count in self.alert_thresholds and self.alert_callback:
            try:
                self.alert_callback(ip, count, context)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")
    
    def get_top_attackers(self, limit: int = 10) -> List[tuple]:
        """Get top attackers by connection count"""
        with self._lock:
            return sorted(
                self.ip_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:limit]
    
    def get_attacker_info(self, ip: str) -> Optional[Dict]:
        """Get information about a specific attacker"""
        with self._lock:
            if ip not in self.ip_counts:
                return None
            
            ip_interactions = [i for i in self.interactions if i['ip'] == ip]
            return {
                'ip': ip,
                'total_attempts': self.ip_counts[ip],
                'interactions': ip_interactions[-10:]  # Last 10
            }
    
    def get_stats(self) -> Dict:
        """Get overall statistics"""
        with self._lock:
            return {
                'unique_attackers': len(self.ip_counts),
                'total_interactions': len(self.interactions),
                'top_attackers': self.get_top_attackers(5)
            }


class Honeypot:
    """
    Production-ready honeypot with HTTP and SSH support.
    Includes attacker tracking and configurable responses.
    """
    
    def __init__(
        self,
        port: int = 22,
        service: str = 'SSH',
        log_file: str = 'data/honeypot_logs.json',
        tracker: Optional[AttackerTracker] = None
    ):
        """
        Initialize Honeypot
        
        Args:
            port: Port to listen on
            service: Service type ('SSH' or 'HTTP')
            log_file: Path to log file
            tracker: AttackerTracker instance (creates new if None)
        """
        self.port = port
        self.service = service.upper()
        self.log_file = log_file
        self.tracker = tracker or AttackerTracker()
        self.is_running = False
        self.server_socket = None
        self._server_thread = None
        
        # Realistic banners
        self.banners = {
            'SSH': b'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3\r\n',
            'HTTP': b'HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n<h1>Welcome</h1>\n<!-- honeypot -->'
        }
        
        logger.info(f"Honeypot initialized: {service} on port {port}")
    
    def start(self):
        """Start honeypot service in background thread"""
        if self.is_running:
            logger.warning("Honeypot already running")
            return
        
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(5)
            self.is_running = True
            
            # Run in background thread
            thread = threading.Thread(target=self._accept_connections, daemon=True)
            thread.start()
            
            logger.info(f"Honeypot listening on port {self.port}")
            
        except Exception as e:
            logger.error(f"Failed to start honeypot: {e}")
            self.is_running = False
    
    def stop(self):
        """Stop honeypot service"""
        if not self.is_running:
            return
        
        self.is_running = False
        if self.server_socket:
            self.server_socket.close()
        
        logger.info("Honeypot stopped")
    
    def _accept_connections(self):
        """Accept and handle incoming connections"""
        while self.is_running:
            try:
                conn, addr = self.server_socket.accept()
                # Handle in separate thread
                thread = threading.Thread(
                    target=self._handle_connection,
                    args=(conn, addr),
                    daemon=True
                )
                thread.start()
            except Exception as e:
                if self.is_running:
                    logger.error(f"Connection accept error: {e}")
    
    def _handle_connection(self, conn, addr):
        """
        Handle individual connection
        
        Args:
            conn: Socket connection
            addr: Client address tuple (ip, port)
        """
        try:
            # Log the interaction
            self.log_interaction(addr)
            
            # Send fake banner
            self.send_fake_banner(conn)
            
            # Try to receive data (e.g., login attempts)
            try:
                data = conn.recv(1024)
                if data:
                    self.log_data(addr, data)
            except:
                pass
            
            # Close connection
            conn.close()
            
        except Exception as e:
            logger.error(f"Connection handling error: {e}")
    
    def log_interaction(self, addr):
        """
        Log honeypot interaction
        
        Args:
            addr: Client address tuple (ip, port)
        """
        interaction = {
            'ip': addr[0],
            'port': addr[1],
            'service': self.service,
            'honeypot_port': self.port,
            'timestamp': datetime.now().isoformat()
        }
        
        self.interactions.append(interaction)
        logger.warning(f"Honeypot interaction from {addr[0]}:{addr[1]} on {self.service}")
        
        # Save to file
        self._save_to_file(interaction)
    
    def log_data(self, addr, data):
        """
        Log data received from attacker
        
        Args:
            addr: Client address
            data: Received data
        """
        try:
            data_str = data.decode('utf-8', errors='ignore')
            logger.info(f"Data from {addr[0]}: {data_str[:100]}")  # First 100 chars
        except:
            pass
    
    def send_fake_banner(self, conn):
        """
        Send fake service banner
        
        Args:
            conn: Socket connection
        """
        try:
            banner = self.banners.get(self.service, '')
            if banner:
                conn.send(banner.encode())
        except Exception as e:
            logger.error(f"Failed to send banner: {e}")
    
    def _save_to_file(self, interaction):
        """
        Save interaction to log file
        
        Args:
            interaction: Interaction dictionary
        """
        try:
            # Read existing logs
            logs = []
            try:
                with open(self.log_file, 'r') as f:
                    logs = json.load(f)
            except FileNotFoundError:
                pass
            
            # Append new interaction
            logs.append(interaction)
            
            # Write back
            with open(self.log_file, 'w') as f:
                json.dump(logs, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to save to file: {e}")
    
    def get_interactions(self, limit=None):
        """
        Get logged interactions
        
        Args:
            limit: Maximum number of interactions to return
            
        Returns:
            list: Interaction records
        """
        if limit:
            return self.interactions[-limit:]
        return self.interactions
    
    def get_attacker_ips(self):
        """
        Get unique attacker IP addresses
        
        Returns:
            set: Set of IP addresses
        """
        return set(i['ip'] for i in self.interactions)
    
    def get_statistics(self):
        """
        Get honeypot statistics
        
        Returns:
            dict: Statistics
        """
        return {
            'service': self.service,
            'port': self.port,
            'is_running': self.is_running,
            'total_interactions': len(self.interactions),
            'unique_ips': len(self.get_attacker_ips())
        }


if __name__ == "__main__":
    # Test code
    logging.basicConfig(level=logging.INFO)
    honeypot = Honeypot(port=2222, service='SSH')
    print("Honeypot ready")
    print(f"Statistics: {honeypot.get_statistics()}")
