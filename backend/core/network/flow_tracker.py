"""
Flow Tracker Module
Tracks network flows and maintains flow statistics
"""

import logging
from typing import Dict, List, Optional
from collections import defaultdict
from datetime import datetime, timedelta
import threading

logger = logging.getLogger(__name__)


class Flow:
    """Represents a network flow"""
    
    def __init__(self, five_tuple: tuple):
        """
        Initialize a flow
        
        Args:
            five_tuple: (src_ip, dst_ip, src_port, dst_port, protocol)
        """
        self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol = five_tuple
        self.start_time = datetime.now()
        self.last_seen = self.start_time
        self.packet_count = 0
        self.byte_count = 0
        self.flags = set()
    
    def update(self, packet_size: int, flags: Optional[List[str]] = None):
        """
        Update flow with new packet
        
        Args:
            packet_size: Size of the packet in bytes
            flags: TCP flags if applicable
        """
        self.last_seen = datetime.now()
        self.packet_count += 1
        self.byte_count += packet_size
        
        if flags:
            self.flags.update(flags)
    
    def duration(self) -> float:
        """
        Get flow duration in seconds
        
        Returns:
            Duration in seconds
        """
        return (self.last_seen - self.start_time).total_seconds()
    
    def to_dict(self) -> Dict:
        """
        Convert flow to dictionary
        
        Returns:
            Dictionary representation of the flow
        """
        return {
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'start_time': self.start_time.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'duration': self.duration(),
            'packet_count': self.packet_count,
            'byte_count': self.byte_count,
            'flags': list(self.flags)
        }


class FlowTracker:
    """
    Tracks network flows and maintains flow statistics
    """
    
    def __init__(self, timeout: int = 300):
        """
        Initialize Flow Tracker
        
        Args:
            timeout: Flow timeout in seconds (default: 300)
        """
        self.flows = {}
        self.timeout = timeout
        self.flow_count = 0
        self.expired_flows = []
        self._lock = threading.Lock()
        
        # Statistics
        self.total_packets = 0
        self.total_bytes = 0
        
        logger.info(f"FlowTracker initialized with timeout: {timeout}s")
    
    def process_packet(self, parsed_packet: Dict):
        """
        Process a parsed packet and update flows
        
        Args:
            parsed_packet: Parsed packet dictionary from TrafficParser
        """
        try:
            # Extract 5-tuple
            five_tuple = self._extract_five_tuple(parsed_packet)
            if not five_tuple:
                return
            
            packet_size = parsed_packet.get('length', 0)
            flags = None
            
            if 'tcp' in parsed_packet:
                flags = parsed_packet['tcp'].get('flags', [])
            
            with self._lock:
                # Get or create flow
                if five_tuple not in self.flows:
                    self.flows[five_tuple] = Flow(five_tuple)
                    self.flow_count += 1
                
                # Update flow
                self.flows[five_tuple].update(packet_size, flags)
                
                # Update statistics
                self.total_packets += 1
                self.total_bytes += packet_size
            
        except Exception as e:
            logger.debug(f"Error processing packet in flow tracker: {e}")
    
    def _extract_five_tuple(self, parsed_packet: Dict) -> Optional[tuple]:
        """
        Extract 5-tuple from parsed packet
        
        Args:
            parsed_packet: Parsed packet dictionary
            
        Returns:
            Tuple of (src_ip, dst_ip, src_port, dst_port, protocol) or None
        """
        try:
            if 'ip' not in parsed_packet:
                return None
            
            src_ip = parsed_packet['ip']['src']
            dst_ip = parsed_packet['ip']['dst']
            
            if 'tcp' in parsed_packet:
                src_port = parsed_packet['tcp']['sport']
                dst_port = parsed_packet['tcp']['dport']
                protocol = 'TCP'
            elif 'udp' in parsed_packet:
                src_port = parsed_packet['udp']['sport']
                dst_port = parsed_packet['udp']['dport']
                protocol = 'UDP'
            else:
                src_port = 0
                dst_port = 0
                protocol = parsed_packet['protocols'][0] if parsed_packet['protocols'] else 'UNKNOWN'
            
            return (src_ip, dst_ip, src_port, dst_port, protocol)
            
        except Exception as e:
            logger.debug(f"Error extracting 5-tuple: {e}")
            return None
    
    def cleanup_expired_flows(self):
        """
        Remove expired flows based on timeout
        """
        try:
            now = datetime.now()
            expired = []
            
            with self._lock:
                for five_tuple, flow in list(self.flows.items()):
                    if (now - flow.last_seen).total_seconds() > self.timeout:
                        expired.append(five_tuple)
                        self.expired_flows.append(flow.to_dict())
                
                # Remove expired flows
                for five_tuple in expired:
                    del self.flows[five_tuple]
            
            if expired:
                logger.debug(f"Cleaned up {len(expired)} expired flows")
                
        except Exception as e:
            logger.error(f"Error cleaning up flows: {e}")
    
    def get_active_flows(self, limit: Optional[int] = None) -> List[Dict]:
        """
        Get list of active flows
        
        Args:
            limit: Maximum number of flows to return
            
        Returns:
            List of flow dictionaries
        """
        with self._lock:
            flows = [flow.to_dict() for flow in self.flows.values()]
            
            # Sort by last seen (most recent first)
            flows.sort(key=lambda x: x['last_seen'], reverse=True)
            
            if limit:
                flows = flows[:limit]
            
            return flows
    
    def get_flow_by_tuple(self, five_tuple: tuple) -> Optional[Dict]:
        """
        Get a specific flow by its 5-tuple
        
        Args:
            five_tuple: (src_ip, dst_ip, src_port, dst_port, protocol)
            
        Returns:
            Flow dictionary or None
        """
        with self._lock:
            flow = self.flows.get(five_tuple)
            return flow.to_dict() if flow else None
    
    def get_flows_by_ip(self, ip_address: str) -> List[Dict]:
        """
        Get all flows involving a specific IP address
        
        Args:
            ip_address: IP address to search for
            
        Returns:
            List of flow dictionaries
        """
        with self._lock:
            matching_flows = []
            
            for flow in self.flows.values():
                if flow.src_ip == ip_address or flow.dst_ip == ip_address:
                    matching_flows.append(flow.to_dict())
            
            return matching_flows
    
    def get_top_talkers(self, limit: int = 10, by: str = 'bytes') -> List[Dict]:
        """
        Get top talkers (most active flows)
        
        Args:
            limit: Number of top flows to return
            by: Sort by 'bytes' or 'packets'
            
        Returns:
            List of top flow dictionaries
        """
        with self._lock:
            flows = [flow.to_dict() for flow in self.flows.values()]
            
            # Sort by specified metric
            sort_key = 'byte_count' if by == 'bytes' else 'packet_count'
            flows.sort(key=lambda x: x[sort_key], reverse=True)
            
            return flows[:limit]
    
    def get_statistics(self) -> Dict:
        """
        Get flow tracker statistics
        
        Returns:
            Dictionary with statistics
        """
        with self._lock:
            return {
                'active_flows': len(self.flows),
                'total_flows': self.flow_count,
                'total_packets': self.total_packets,
                'total_bytes': self.total_bytes,
                'expired_flows': len(self.expired_flows)
            }
    
    def get_protocol_distribution(self) -> Dict[str, int]:
        """
        Get distribution of protocols in active flows
        
        Returns:
            Dictionary with protocol counts
        """
        with self._lock:
            distribution = defaultdict(int)
            
            for flow in self.flows.values():
                distribution[flow.protocol] += 1
            
            return dict(distribution)
    
    def reset_statistics(self):
        """Reset all statistics"""
        with self._lock:
            self.flows.clear()
            self.flow_count = 0
            self.total_packets = 0
            self.total_bytes = 0
            self.expired_flows.clear()
            
        logger.info("Flow tracker statistics reset")
