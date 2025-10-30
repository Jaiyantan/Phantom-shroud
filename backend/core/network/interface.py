"""
Interface Manager Module
Manages network interfaces for traffic monitoring
"""

import netifaces
import logging
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)


class InterfaceManager:
    """
    Manages network interfaces and provides interface information
    """
    
    def __init__(self):
        """Initialize Interface Manager"""
        self.interfaces = self._discover_interfaces()
        logger.info(f"Discovered {len(self.interfaces)} network interfaces")
    
    def _discover_interfaces(self) -> List[Dict]:
        """
        Discover all available network interfaces
        
        Returns:
            List of interface information dictionaries
        """
        interfaces = []
        
        try:
            for iface in netifaces.interfaces():
                iface_info = self.get_interface_info(iface)
                if iface_info:
                    interfaces.append(iface_info)
        except Exception as e:
            logger.error(f"Error discovering interfaces: {e}")
        
        return interfaces
    
    def get_interface_info(self, iface_name: str) -> Optional[Dict]:
        """
        Get detailed information about a network interface
        
        Args:
            iface_name: Name of the interface
            
        Returns:
            Dictionary with interface information or None
        """
        try:
            addrs = netifaces.ifaddresses(iface_name)
            info = {
                'name': iface_name,
                'addresses': {}
            }
            
            # Get IPv4 address
            if netifaces.AF_INET in addrs:
                ipv4 = addrs[netifaces.AF_INET][0]
                info['addresses']['ipv4'] = ipv4.get('addr')
                info['addresses']['netmask'] = ipv4.get('netmask')
                info['addresses']['broadcast'] = ipv4.get('broadcast')
            
            # Get IPv6 address
            if netifaces.AF_INET6 in addrs:
                ipv6 = addrs[netifaces.AF_INET6][0]
                info['addresses']['ipv6'] = ipv6.get('addr')
            
            # Get MAC address
            if netifaces.AF_LINK in addrs:
                link = addrs[netifaces.AF_LINK][0]
                info['addresses']['mac'] = link.get('addr')
            
            return info
            
        except Exception as e:
            logger.warning(f"Could not get info for interface {iface_name}: {e}")
            return None
    
    def list_interfaces(self) -> List[str]:
        """
        List all available interface names
        
        Returns:
            List of interface names
        """
        return [iface['name'] for iface in self.interfaces]
    
    def get_default_interface(self) -> Optional[str]:
        """
        Get the default network interface
        
        Returns:
            Default interface name or None
        """
        try:
            gateways = netifaces.gateways()
            default_gateway = gateways.get('default')
            
            if default_gateway and netifaces.AF_INET in default_gateway:
                return default_gateway[netifaces.AF_INET][1]
            
            # Fallback: return first non-loopback interface
            for iface in self.list_interfaces():
                if iface != 'lo' and not iface.startswith('lo'):
                    return iface
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting default interface: {e}")
            return None
    
    def get_interface_stats(self, iface_name: str) -> Dict:
        """
        Get statistics for a network interface
        
        Args:
            iface_name: Name of the interface
            
        Returns:
            Dictionary with interface statistics
        """
        stats = {
            'name': iface_name,
            'active': False,
            'packets_sent': 0,
            'packets_recv': 0,
            'bytes_sent': 0,
            'bytes_recv': 0,
            'errors': 0
        }
        
        try:
            # Basic check if interface exists
            if iface_name in netifaces.interfaces():
                stats['active'] = True
                # Note: netifaces doesn't provide packet stats
                # This would require platform-specific code or psutil
                
        except Exception as e:
            logger.error(f"Error getting stats for {iface_name}: {e}")
        
        return stats
    
    def is_wireless(self, iface_name: str) -> bool:
        """
        Check if an interface is wireless
        
        Args:
            iface_name: Name of the interface
            
        Returns:
            True if wireless, False otherwise
        """
        # Simple heuristic: check if name contains 'wlan', 'wifi', or 'wl'
        wireless_keywords = ['wlan', 'wifi', 'wl', 'wlp']
        return any(keyword in iface_name.lower() for keyword in wireless_keywords)
    
    def get_monitorable_interfaces(self) -> List[str]:
        """
        Get list of interfaces suitable for monitoring
        (excludes loopback and virtual interfaces)
        
        Returns:
            List of monitorable interface names
        """
        exclude_patterns = ['lo', 'docker', 'veth', 'br-', 'virbr']
        
        monitorable = []
        for iface in self.list_interfaces():
            # Exclude based on patterns
            if not any(pattern in iface for pattern in exclude_patterns):
                monitorable.append(iface)
        
        return monitorable
