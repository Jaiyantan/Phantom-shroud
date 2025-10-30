"""
Deep Packet Inspection Engine
Hours 3-6 Implementation

MVP Scope:
- Protocol identification (HTTP, HTTPS, DNS)
- Basic SSL/TLS validation
- Essential feature extraction (~20 features)
- Payload size and frequency analysis
"""

from scapy.all import TCP, UDP, DNS, IP
import logging

logger = logging.getLogger(__name__)


class DPIEngine:
    """
    Basic Deep Packet Inspection for protocol analysis.
    Simplified for 24-hour MVP.
    """
    
    def __init__(self):
        """Initialize DPI Engine"""
        self.protocol_stats = {}
        logger.info("DPIEngine initialized")
    
    def analyze_packet(self, packet):
        """
        Analyze packet and extract features
        
        Args:
            packet: Scapy packet object
            
        Returns:
            dict: Extracted features
        """
        features = {
            'protocol': self.identify_protocol(packet),
            'size': len(packet),
            'timestamp': packet.time if hasattr(packet, 'time') else None,
            'ports': self.extract_ports(packet),
            'flags': self.extract_flags(packet),
            'payload_size': len(packet.payload) if hasattr(packet, 'payload') else 0
        }
        
        # Update statistics
        protocol = features['protocol']
        self.protocol_stats[protocol] = self.protocol_stats.get(protocol, 0) + 1
        
        return features
    
    def identify_protocol(self, packet):
        """
        Identify network protocol
        
        Args:
            packet: Scapy packet object
            
        Returns:
            str: Protocol name
        """
        # TODO: Implement comprehensive protocol identification
        
        if packet.haslayer(TCP):
            dport = packet[TCP].dport
            sport = packet[TCP].sport
            
            # Common port identification
            if dport == 80 or sport == 80:
                return 'HTTP'
            elif dport == 443 or sport == 443:
                return 'HTTPS'
            elif dport == 22 or sport == 22:
                return 'SSH'
            elif dport in [20, 21] or sport in [20, 21]:
                return 'FTP'
            else:
                return 'TCP'
        
        elif packet.haslayer(UDP):
            dport = packet[UDP].dport
            sport = packet[UDP].sport
            
            if dport == 53 or sport == 53:
                return 'DNS'
            elif dport == 67 or sport == 68:
                return 'DHCP'
            else:
                return 'UDP'
        
        elif packet.haslayer(DNS):
            return 'DNS'
        
        return 'UNKNOWN'
    
    def extract_ports(self, packet):
        """
        Extract source and destination ports
        
        Args:
            packet: Scapy packet object
            
        Returns:
            tuple: (source_port, destination_port) or (None, None)
        """
        if packet.haslayer(TCP):
            return (packet[TCP].sport, packet[TCP].dport)
        elif packet.haslayer(UDP):
            return (packet[UDP].sport, packet[UDP].dport)
        return (None, None)
    
    def extract_flags(self, packet):
        """
        Extract TCP flags if present
        
        Args:
            packet: Scapy packet object
            
        Returns:
            str: TCP flags or None
        """
        if packet.haslayer(TCP):
            return packet[TCP].flags
        return None
    
    def extract_features(self, packet):
        """
        Extract comprehensive feature set for ML
        
        Args:
            packet: Scapy packet object
            
        Returns:
            list: Feature vector
        """
        # TODO: Implement 15-20 feature extraction
        features = []
        
        # Basic features
        features.append(len(packet))  # Packet size
        features.append(1 if packet.haslayer(TCP) else 0)  # Has TCP
        features.append(1 if packet.haslayer(UDP) else 0)  # Has UDP
        
        # Port features
        sport, dport = self.extract_ports(packet)
        features.append(sport if sport else 0)
        features.append(dport if dport else 0)
        
        # TODO: Add more features (payload entropy, inter-arrival time, etc.)
        
        return features
    
    def get_protocol_distribution(self):
        """
        Get distribution of observed protocols
        
        Returns:
            dict: Protocol distribution
        """
        total = sum(self.protocol_stats.values())
        if total == 0:
            return {}
        
        return {
            proto: {
                'count': count,
                'percentage': round((count / total) * 100, 2)
            }
            for proto, count in self.protocol_stats.items()
        }


if __name__ == "__main__":
    # Test code
    logging.basicConfig(level=logging.INFO)
    dpi = DPIEngine()
    print("DPIEngine ready")
    print(f"Protocol distribution: {dpi.get_protocol_distribution()}")
