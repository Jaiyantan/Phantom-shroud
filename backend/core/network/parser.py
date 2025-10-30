"""
Traffic Parser Module
Parses network packets and extracts relevant information
"""

import logging
from typing import Dict, Optional, List
from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse
from datetime import datetime

logger = logging.getLogger(__name__)


class TrafficParser:
    """
    Parses network packets and extracts protocol information
    """
    
    def __init__(self):
        """Initialize Traffic Parser"""
        self.parsed_count = 0
        logger.info("TrafficParser initialized")
    
    def parse_packet(self, packet) -> Optional[Dict]:
        """
        Parse a single packet and extract relevant information
        
        Args:
            packet: Scapy packet object
            
        Returns:
            Dictionary with parsed packet information or None
        """
        try:
            self.parsed_count += 1
            
            parsed = {
                'timestamp': datetime.now().isoformat(),
                'length': len(packet),
                'protocols': []
            }
            
            # Layer 2 - Ethernet/ARP
            if packet.haslayer(ARP):
                parsed['protocols'].append('ARP')
                parsed['arp'] = self._parse_arp(packet)
            
            # Layer 3 - IP
            if packet.haslayer(IP):
                parsed['protocols'].append('IP')
                parsed['ip'] = self._parse_ip(packet)
                
                # Layer 4 - Transport
                if packet.haslayer(TCP):
                    parsed['protocols'].append('TCP')
                    parsed['tcp'] = self._parse_tcp(packet)
                    
                    # Application layer protocols
                    if packet.haslayer(HTTPRequest):
                        parsed['protocols'].append('HTTP')
                        parsed['http'] = self._parse_http_request(packet)
                    elif packet.haslayer(HTTPResponse):
                        parsed['protocols'].append('HTTP')
                        parsed['http'] = self._parse_http_response(packet)
                
                elif packet.haslayer(UDP):
                    parsed['protocols'].append('UDP')
                    parsed['udp'] = self._parse_udp(packet)
                    
                    # DNS
                    if packet.haslayer(DNS):
                        parsed['protocols'].append('DNS')
                        parsed['dns'] = self._parse_dns(packet)
                
                elif packet.haslayer(ICMP):
                    parsed['protocols'].append('ICMP')
                    parsed['icmp'] = self._parse_icmp(packet)
            
            # Extract payload if present
            if packet.haslayer(Raw):
                parsed['has_payload'] = True
                parsed['payload_size'] = len(packet[Raw].load)
            
            return parsed
            
        except Exception as e:
            logger.debug(f"Error parsing packet: {e}")
            return None
    
    def _parse_ip(self, packet) -> Dict:
        """Parse IP layer"""
        ip_layer = packet[IP]
        return {
            'src': ip_layer.src,
            'dst': ip_layer.dst,
            'version': ip_layer.version,
            'ttl': ip_layer.ttl,
            'proto': ip_layer.proto,
            'length': ip_layer.len
        }
    
    def _parse_tcp(self, packet) -> Dict:
        """Parse TCP layer"""
        tcp_layer = packet[TCP]
        flags = []
        
        # Extract TCP flags
        if tcp_layer.flags.S:
            flags.append('SYN')
        if tcp_layer.flags.A:
            flags.append('ACK')
        if tcp_layer.flags.F:
            flags.append('FIN')
        if tcp_layer.flags.R:
            flags.append('RST')
        if tcp_layer.flags.P:
            flags.append('PSH')
        if tcp_layer.flags.U:
            flags.append('URG')
        
        return {
            'sport': tcp_layer.sport,
            'dport': tcp_layer.dport,
            'seq': tcp_layer.seq,
            'ack': tcp_layer.ack,
            'flags': flags,
            'window': tcp_layer.window,
            'dataofs': tcp_layer.dataofs
        }
    
    def _parse_udp(self, packet) -> Dict:
        """Parse UDP layer"""
        udp_layer = packet[UDP]
        return {
            'sport': udp_layer.sport,
            'dport': udp_layer.dport,
            'length': udp_layer.len,
            'checksum': udp_layer.chksum
        }
    
    def _parse_icmp(self, packet) -> Dict:
        """Parse ICMP layer"""
        icmp_layer = packet[ICMP]
        return {
            'type': icmp_layer.type,
            'code': icmp_layer.code,
            'checksum': icmp_layer.chksum
        }
    
    def _parse_arp(self, packet) -> Dict:
        """Parse ARP layer"""
        arp_layer = packet[ARP]
        return {
            'op': arp_layer.op,  # 1=request, 2=reply
            'hwsrc': arp_layer.hwsrc,
            'psrc': arp_layer.psrc,
            'hwdst': arp_layer.hwdst,
            'pdst': arp_layer.pdst
        }
    
    def _parse_dns(self, packet) -> Dict:
        """Parse DNS layer"""
        dns_layer = packet[DNS]
        dns_info = {
            'id': dns_layer.id,
            'qr': dns_layer.qr,  # 0=query, 1=response
            'opcode': dns_layer.opcode,
            'rcode': dns_layer.rcode
        }
        
        # Parse queries
        if dns_layer.qd:
            queries = []
            qd = dns_layer.qd
            if qd:
                query = {
                    'qname': qd.qname.decode() if isinstance(qd.qname, bytes) else str(qd.qname),
                    'qtype': qd.qtype,
                    'qclass': qd.qclass
                }
                queries.append(query)
            dns_info['queries'] = queries
        
        # Parse answers
        if dns_layer.an:
            answers = []
            count = dns_layer.ancount
            an = dns_layer.an
            
            for i in range(count):
                if an:
                    answer = {
                        'rrname': str(an.rrname),
                        'type': an.type,
                        'rdata': str(an.rdata)
                    }
                    answers.append(answer)
                    an = an.payload if hasattr(an, 'payload') else None
            
            dns_info['answers'] = answers
        
        return dns_info
    
    def _parse_http_request(self, packet) -> Dict:
        """Parse HTTP request"""
        try:
            http_layer = packet[HTTPRequest]
            return {
                'method': http_layer.Method.decode() if hasattr(http_layer, 'Method') else 'UNKNOWN',
                'host': http_layer.Host.decode() if hasattr(http_layer, 'Host') else '',
                'path': http_layer.Path.decode() if hasattr(http_layer, 'Path') else '',
                'user_agent': http_layer.User_Agent.decode() if hasattr(http_layer, 'User_Agent') else ''
            }
        except Exception as e:
            logger.debug(f"Error parsing HTTP request: {e}")
            return {'error': str(e)}
    
    def _parse_http_response(self, packet) -> Dict:
        """Parse HTTP response"""
        try:
            http_layer = packet[HTTPResponse]
            return {
                'status_code': http_layer.Status_Code.decode() if hasattr(http_layer, 'Status_Code') else '',
                'reason': http_layer.Reason_Phrase.decode() if hasattr(http_layer, 'Reason_Phrase') else ''
            }
        except Exception as e:
            logger.debug(f"Error parsing HTTP response: {e}")
            return {'error': str(e)}
    
    def extract_five_tuple(self, parsed_packet: Dict) -> Optional[tuple]:
        """
        Extract 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol) from parsed packet
        
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
                protocol = 'OTHER'
            
            return (src_ip, dst_ip, src_port, dst_port, protocol)
            
        except Exception as e:
            logger.debug(f"Error extracting 5-tuple: {e}")
            return None
    
    def get_statistics(self) -> Dict:
        """
        Get parser statistics
        
        Returns:
            Dictionary with parser statistics
        """
        return {
            'total_parsed': self.parsed_count
        }
