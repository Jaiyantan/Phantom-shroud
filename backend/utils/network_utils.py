"""
Network Utility Functions
Helper functions for network operations
"""

import socket
import netifaces
import logging

logger = logging.getLogger(__name__)


def get_default_interface():
    """
    Get the default network interface
    
    Returns:
        str: Interface name (e.g., 'eth0', 'wlan0')
    """
    try:
        # Get default gateway
        gateways = netifaces.gateways()
        default_interface = gateways['default'][netifaces.AF_INET][1]
        return default_interface
    except Exception as e:
        logger.error(f"Failed to get default interface: {e}")
        # Fallback
        return 'eth0'


def get_local_ip():
    """
    Get local IP address
    
    Returns:
        str: Local IP address
    """
    try:
        # Connect to external address to get local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        logger.error(f"Failed to get local IP: {e}")
        return '127.0.0.1'


def get_mac_address(ip):
    """
    Get MAC address for IP (ARP lookup)
    
    Args:
        ip: IP address
        
    Returns:
        str: MAC address or None
    """
    # TODO: Implement ARP lookup
    # Can use scapy: sr1(ARP(pdst=ip), timeout=2)
    return None


def is_private_ip(ip):
    """
    Check if IP is in private range
    
    Args:
        ip: IP address string
        
    Returns:
        bool: True if private IP
    """
    try:
        octets = [int(x) for x in ip.split('.')]
        
        # 10.0.0.0/8
        if octets[0] == 10:
            return True
        
        # 172.16.0.0/12
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            return True
        
        # 192.168.0.0/16
        if octets[0] == 192 and octets[1] == 168:
            return True
        
        return False
        
    except:
        return False


def format_mac(mac):
    """
    Format MAC address to standard format
    
    Args:
        mac: MAC address string
        
    Returns:
        str: Formatted MAC (XX:XX:XX:XX:XX:XX)
    """
    # Remove common separators
    mac = mac.replace(':', '').replace('-', '').replace('.', '')
    
    # Add colons
    return ':'.join(mac[i:i+2] for i in range(0, 12, 2)).upper()


def get_network_interfaces():
    """
    Get list of all network interfaces
    
    Returns:
        list: Interface names
    """
    try:
        return netifaces.interfaces()
    except Exception as e:
        logger.error(f"Failed to get interfaces: {e}")
        return []


if __name__ == "__main__":
    # Test
    logging.basicConfig(level=logging.INFO)
    print(f"Default interface: {get_default_interface()}")
    print(f"Local IP: {get_local_ip()}")
    print(f"All interfaces: {get_network_interfaces()}")
    print(f"Is 192.168.1.1 private? {is_private_ip('192.168.1.1')}")
    print(f"Is 8.8.8.8 private? {is_private_ip('8.8.8.8')}")
