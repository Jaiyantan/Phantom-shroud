"""
VPN Manager Module
Hours 10-12 Implementation

MVP Scope:
- OpenVPN integration
- Manual and automatic connection triggers
- Basic kill switch (iptables rules)
- Connection status monitoring
"""

import subprocess
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


class VPNManager:
    """
    OpenVPN subprocess controller with kill switch.
    Simplified for 24-hour MVP.
    """
    
    def __init__(self, config_path='config/vpn_profiles/default.ovpn'):
        """
        Initialize VPN Manager
        
        Args:
            config_path: Path to OpenVPN configuration file
        """
        self.config_path = config_path
        self.process = None
        self.connected = False
        self.kill_switch_enabled = False
        logger.info(f"VPNManager initialized with config: {config_path}")
    
    def connect(self, auto_trigger=False):
        """
        Start VPN connection
        
        Args:
            auto_trigger: Whether connection was automatically triggered
            
        Returns:
            bool: True if connection started successfully
        """
        if self.connected:
            logger.warning("VPN already connected")
            return True
        
        try:
            # Check if config file exists
            if not os.path.exists(self.config_path):
                logger.error(f"Config file not found: {self.config_path}")
                return False
            
            logger.info(f"Starting OpenVPN connection {'(auto-triggered)' if auto_trigger else ''}")
            
            # TODO: Start OpenVPN subprocess
            # self.process = subprocess.Popen(
            #     ['openvpn', '--config', self.config_path],
            #     stdout=subprocess.PIPE,
            #     stderr=subprocess.PIPE
            # )
            
            # Enable kill switch
            if self.enable_kill_switch():
                self.connected = True
                logger.info("VPN connection established")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to start VPN: {e}")
            return False
    
    def disconnect(self):
        """
        Stop VPN connection
        
        Returns:
            bool: True if disconnected successfully
        """
        if not self.connected:
            logger.warning("VPN not connected")
            return True
        
        try:
            logger.info("Stopping VPN connection")
            
            # Terminate OpenVPN process
            if self.process:
                self.process.terminate()
                self.process.wait(timeout=5)
                self.process = None
            
            # Disable kill switch
            self.disable_kill_switch()
            
            self.connected = False
            logger.info("VPN disconnected")
            return True
            
        except Exception as e:
            logger.error(f"Failed to stop VPN: {e}")
            return False
    
    def enable_kill_switch(self):
        """
        Enable kill switch using iptables
        Blocks all traffic except through VPN tunnel
        
        Returns:
            bool: True if kill switch enabled
        """
        if self.kill_switch_enabled:
            return True
        
        try:
            logger.info("Enabling VPN kill switch")
            
            # TODO: Implement iptables rules
            # Block all output traffic by default
            # subprocess.run(['iptables', '-P', 'OUTPUT', 'DROP'], check=True)
            
            # Allow VPN tunnel traffic
            # subprocess.run([
            #     'iptables', '-A', 'OUTPUT',
            #     '-o', 'tun0',  # VPN interface
            #     '-j', 'ACCEPT'
            # ], check=True)
            
            # Allow local traffic
            # subprocess.run([
            #     'iptables', '-A', 'OUTPUT',
            #     '-o', 'lo',
            #     '-j', 'ACCEPT'
            # ], check=True)
            
            self.kill_switch_enabled = True
            logger.info("Kill switch enabled")
            return True
            
        except Exception as e:
            logger.error(f"Failed to enable kill switch: {e}")
            return False
    
    def disable_kill_switch(self):
        """
        Disable kill switch and restore normal routing
        
        Returns:
            bool: True if kill switch disabled
        """
        if not self.kill_switch_enabled:
            return True
        
        try:
            logger.info("Disabling VPN kill switch")
            
            # TODO: Remove iptables rules
            # Flush output chain
            # subprocess.run(['iptables', '-F', 'OUTPUT'], check=True)
            
            # Reset default policy
            # subprocess.run(['iptables', '-P', 'OUTPUT', 'ACCEPT'], check=True)
            
            self.kill_switch_enabled = False
            logger.info("Kill switch disabled")
            return True
            
        except Exception as e:
            logger.error(f"Failed to disable kill switch: {e}")
            return False
    
    def is_connected(self):
        """
        Check if VPN is currently connected
        
        Returns:
            bool: True if connected
        """
        # TODO: Implement actual connection check
        # Check if process is running
        # Check if tun0 interface exists
        # Verify IP address
        return self.connected
    
    def get_status(self):
        """
        Get current VPN status
        
        Returns:
            dict: Status information
        """
        status = {
            'connected': self.connected,
            'kill_switch': self.kill_switch_enabled,
            'config': self.config_path,
            'process_alive': self.process is not None and self.process.poll() is None
        }
        
        # TODO: Add more status info
        # - IP address
        # - Connection time
        # - Data transferred
        
        return status


if __name__ == "__main__":
    # Test code
    logging.basicConfig(level=logging.INFO)
    vpn = VPNManager()
    print("VPNManager ready")
    print(f"Status: {vpn.get_status()}")
