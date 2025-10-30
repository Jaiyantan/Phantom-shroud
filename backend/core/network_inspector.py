"""
Network Inspector Module
Phase 1 - Enhanced Implementation

Provides comprehensive network inspection capabilities:
- Multi-interface packet capture
- Advanced traffic parsing
- Flow tracking and analysis
- Real-time statistics
"""

import logging
import threading
import time
from typing import Optional, Dict, List
from collections import defaultdict
from datetime import datetime

from .network.capture import PacketCapture, PacketCaptureManager
from .network.parser import TrafficParser
from .network.interface import InterfaceManager
from .network.flow_tracker import FlowTracker

logger = logging.getLogger(__name__)


class NetworkInspector:
    """
    Enhanced Network Inspector with comprehensive monitoring capabilities
    """
    
    def __init__(self, interface: Optional[str] = None, auto_start: bool = False):
        """
        Initialize Network Inspector
        
        Args:
            interface: Network interface to monitor (auto-detect if None)
            auto_start: Whether to start capture automatically
        """
        # Initialize components
        self.interface_manager = InterfaceManager()
        self.interface = interface or self.detect_interface()
        
        # Initialize capture, parser, and flow tracker
        self.capture = PacketCapture(interface=self.interface)
        self.parser = TrafficParser()
        self.flow_tracker = FlowTracker(timeout=300)
        
        # Statistics
        self.start_time = None
        self.is_running = False
        self.last_stats_time = datetime.now()
        
        # Protocol statistics
        self.protocol_stats = defaultdict(int)
        
        # Cleanup thread
        self._cleanup_thread = None
        self._stop_cleanup = threading.Event()
        
        logger.info(f"NetworkInspector initialized on interface: {self.interface}")
        
        # Register packet processing callback
        self.capture.register_callback(self._process_packet)
        
        if auto_start:
            self.start()
    
    def detect_interface(self) -> str:
        """
        Auto-detect default network interface
        
        Returns:
            str: Interface name
        """
        default_iface = self.interface_manager.get_default_interface()
        
        if not default_iface:
            # Fallback to first monitorable interface
            monitorable = self.interface_manager.get_monitorable_interfaces()
            default_iface = monitorable[0] if monitorable else 'eth0'
        
        logger.info(f"Auto-detected interface: {default_iface}")
        return default_iface
    
    def _process_packet(self, packet):
        """
        Internal packet processing callback
        
        Args:
            packet: Scapy packet object
        """
        try:
            # Parse packet
            parsed = self.parser.parse_packet(packet)
            
            if parsed:
                # Update protocol statistics
                for protocol in parsed.get('protocols', []):
                    self.protocol_stats[protocol] += 1
                
                # Update flow tracker
                self.flow_tracker.process_packet(parsed)
                
        except Exception as e:
            logger.debug(f"Error processing packet: {e}")
    
    def start(self):
        """Start network inspection"""
        if self.is_running:
            logger.warning("Network inspection is already running")
            return
        
        logger.info("Starting network inspection...")
        self.start_time = datetime.now()
        self.is_running = True
        
        # Start packet capture
        self.capture.start()
        
        # Start cleanup thread for expired flows
        self._start_cleanup_thread()
        
        logger.info("Network inspection started successfully")
    
    def stop(self):
        """Stop network inspection"""
        if not self.is_running:
            logger.warning("Network inspection is not running")
            return
        
        logger.info("Stopping network inspection...")
        self.is_running = False
        
        # Stop packet capture
        self.capture.stop()
        
        # Stop cleanup thread
        self._stop_cleanup.set()
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=5)
        
        logger.info("Network inspection stopped")
    
    def _start_cleanup_thread(self):
        """Start background thread for flow cleanup"""
        self._stop_cleanup.clear()
        
        def cleanup_loop():
            while not self._stop_cleanup.is_set():
                time.sleep(60)  # Cleanup every minute
                if self.is_running:
                    self.flow_tracker.cleanup_expired_flows()
        
        self._cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
        self._cleanup_thread.start()
    
    def get_stats(self) -> Dict:
        """
        Get comprehensive network statistics
        
        Returns:
            Dictionary with network statistics
        """
        capture_stats = self.capture.get_statistics()
        flow_stats = self.flow_tracker.get_statistics()
        
        elapsed = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
        pps = flow_stats['total_packets'] / elapsed if elapsed > 0 else 0
        
        return {
            'is_running': self.is_running,
            'interface': self.interface,
            'elapsed_time': round(elapsed, 2),
            'capture': capture_stats,
            'flows': flow_stats,
            'protocols': dict(self.protocol_stats),
            'packets_per_second': round(pps, 2)
        }
    
    def get_active_flows(self, limit: Optional[int] = 50) -> List[Dict]:
        """
        Get list of active network flows
        
        Args:
            limit: Maximum number of flows to return
            
        Returns:
            List of flow dictionaries
        """
        return self.flow_tracker.get_active_flows(limit=limit)
    
    def get_top_talkers(self, limit: int = 10, by: str = 'bytes') -> List[Dict]:
        """
        Get top talkers (most active flows)
        
        Args:
            limit: Number of top flows to return
            by: Sort by 'bytes' or 'packets'
            
        Returns:
            List of top flow dictionaries
        """
        return self.flow_tracker.get_top_talkers(limit=limit, by=by)
    
    def get_flows_by_ip(self, ip_address: str) -> List[Dict]:
        """
        Get all flows involving a specific IP address
        
        Args:
            ip_address: IP address to search for
            
        Returns:
            List of flow dictionaries
        """
        return self.flow_tracker.get_flows_by_ip(ip_address)
    
    def get_protocol_distribution(self) -> Dict[str, int]:
        """
        Get distribution of protocols
        
        Returns:
            Dictionary with protocol counts
        """
        return self.flow_tracker.get_protocol_distribution()
    
    def get_interfaces(self) -> List[str]:
        """
        Get list of available network interfaces
        
        Returns:
            List of interface names
        """
        return self.interface_manager.list_interfaces()
    
    def get_interface_info(self, iface_name: str) -> Optional[Dict]:
        """
        Get detailed information about an interface
        
        Args:
            iface_name: Name of the interface
            
        Returns:
            Interface information dictionary or None
        """
        return self.interface_manager.get_interface_info(iface_name)
    
    def set_capture_filter(self, bpf_filter: str):
        """
        Set BPF filter for packet capture
        
        Args:
            bpf_filter: BPF filter string (e.g., "tcp port 80")
        """
        self.capture.set_filter(bpf_filter)
        logger.info(f"Capture filter set: {bpf_filter}")


if __name__ == "__main__":
    # Test code
    logging.basicConfig(level=logging.INFO)
    inspector = NetworkInspector()
    print(f"NetworkInspector ready on {inspector.interface}")
    print(f"Stats: {inspector.get_stats()}")
