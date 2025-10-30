"""
Honeypot Module
Hours 12-14 Implementation

MVP Scope:
- Basic honeypot (SSH, HTTP)
- Connection logging
- Simple attacker IP tracking
- Alert generation on interaction
"""

import socket
import threading
import logging
from datetime import datetime
import json

logger = logging.getLogger(__name__)


class Honeypot:
    """
    Basic honeypot for SSH and HTTP services.
    Simplified for 24-hour MVP.
    """
    
    def __init__(self, port=22, service='SSH', log_file='data/honeypot_logs.json'):
        """
        Initialize Honeypot
        
        Args:
            port: Port to listen on
            service: Service type (SSH, HTTP)
            log_file: Path to log file
        """
        self.port = port
        self.service = service
        self.log_file = log_file
        self.interactions = []
        self.is_running = False
        self.server_socket = None
        self.banners = {
            'SSH': 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5',
            'HTTP': 'HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n\r\n'
        }
        logger.info(f"Honeypot initialized for {service} on port {port}")
    
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
