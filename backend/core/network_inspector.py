"""
Network Inspector Module
Hours 0-3 Implementation

MVP Scope:
- Basic packet capture using Scapy
- Simple flow tracking (src/dst IP, ports)
- Single interface monitoring
- Target: 1,000+ packets/second
"""

from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import time
import logging

logger = logging.getLogger(__name__)


class NetworkInspector:
    """
    Basic network packet capture and flow tracking.
    Simplified for 24-hour MVP.
    """
    
    def __init__(self, interface=None):
        """
        Initialize Network Inspector
        
        Args:
            interface: Network interface to monitor (auto-detect if None)
        """
        self.interface = interface or self.detect_interface()
        self.flows = defaultdict(int)
        self.packet_count = 0
        self.start_time = None
        self.is_running = False
        logger.info(f"NetworkInspector initialized on interface: {self.interface}")
    
    def detect_interface(self):
        """
        Auto-detect default network interface
        
        Returns:
            str: Interface name
        """
        # TODO: Implement interface detection
        # Placeholder: return first available interface
        return "eth0"
    
    def start_capture(self, packet_callback=None):
        """
        Start capturing packets
        
        Args:
            packet_callback: Optional callback function for each packet
        """
        logger.info("Starting packet capture...")
        self.is_running = True
        self.start_time = time.time()
        
        try:
            # TODO: Implement actual packet capture
            # sniff(iface=self.interface, prn=self.process_packet, store=False)
            pass
        except Exception as e:
            logger.error(f"Capture error: {e}")
            self.is_running = False
    
    def process_packet(self, packet):
        """
        Process captured packet
        
        Args:
            packet: Scapy packet object
        """
        # TODO: Implement packet processing
        self.packet_count += 1
        
        # Extract flow information
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            flow_id = (src_ip, dst_ip)
            self.flows[flow_id] += 1
        
        return packet
    
    def stop_capture(self):
        """Stop packet capture"""
        self.is_running = False
        logger.info("Packet capture stopped")
    
    def get_stats(self):
        """
        Get current network statistics
        
        Returns:
            dict: Network statistics
        """
        elapsed = time.time() - self.start_time if self.start_time else 0
        pps = self.packet_count / elapsed if elapsed > 0 else 0
        
        return {
            'packet_count': self.packet_count,
            'flow_count': len(self.flows),
            'packets_per_second': round(pps, 2),
            'elapsed_time': round(elapsed, 2),
            'interface': self.interface,
            'is_running': self.is_running
        }
    
    def get_top_flows(self, limit=10):
        """
        Get top flows by packet count
        
        Args:
            limit: Number of flows to return
            
        Returns:
            list: Top flows
        """
        sorted_flows = sorted(
            self.flows.items(),
            key=lambda x: x[1],
            reverse=True
        )
        return sorted_flows[:limit]


if __name__ == "__main__":
    # Test code
    logging.basicConfig(level=logging.INFO)
    inspector = NetworkInspector()
    print(f"NetworkInspector ready on {inspector.interface}")
    print(f"Stats: {inspector.get_stats()}")
