"""
TLS Protocol Analyzer for DPI Manager
Includes JA3/JA3S fingerprinting for TLS client/server identification.

Original JA3 implementation: Joseph (ja3_fingerprint.py)
Integrated into Phantom-shroud: October 31, 2025

Features:
- TLS metadata extraction
- JA3 client fingerprinting
- JA3S server fingerprinting
- Suspicious pattern detection
"""

import hashlib
import logging
from typing import Dict, Optional, List

try:
    from scapy.layers.inet import TCP
    from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello
    SCAPY_TLS_AVAILABLE = True
except ImportError:
    SCAPY_TLS_AVAILABLE = False

logger = logging.getLogger(__name__)


def analyze_tls(parsed_packet: Dict) -> Optional[Dict]:
    """
    Analyze TLS traffic from parsed packet
    
    Args:
        parsed_packet: Parsed packet dictionary from TrafficParser
    
    Returns:
        Dictionary with TLS metadata and fingerprints, or None
    """
    # Check if packet has TLS indicators
    protocols = parsed_packet.get('protocols', [])
    if 'TLS' not in protocols and 'SSL' not in protocols:
        return None
    
    meta = {
        'version': None,
        'cipher_suite': None,
        'ja3': None,
        'ja3s': None,
        'sni': None,
        'flags': []
    }
    
    # Extract SNI if available
    tls_info = parsed_packet.get('tls', {})
    if tls_info:
        meta['sni'] = tls_info.get('sni')
        meta['version'] = tls_info.get('version')
    
    # Try to compute JA3/JA3S from raw packet if available
    raw_pkt = parsed_packet.get('_raw_packet')
    if raw_pkt and SCAPY_TLS_AVAILABLE:
        try:
            # Compute JA3 (client fingerprint)
            ja3 = compute_ja3_from_packet(raw_pkt)
            if ja3:
                meta['ja3'] = ja3
            
            # Compute JA3S (server fingerprint)
            ja3s = compute_ja3s_from_packet(raw_pkt)
            if ja3s:
                meta['ja3s'] = ja3s
        except Exception as e:
            logger.debug(f"JA3 computation error: {e}")
    
    # Add suspicious flags
    flags = []
    
    # Check for old TLS versions
    if meta.get('version'):
        if 'TLSv1.0' in str(meta['version']) or 'SSLv3' in str(meta['version']):
            flags.append('obsolete_tls_version')
    
    # Check for suspicious JA3 hashes (known bad actors)
    if meta.get('ja3'):
        if meta['ja3'] in KNOWN_MALICIOUS_JA3:
            flags.append('known_malicious_ja3')
    
    meta['flags'] = flags
    
    return meta if any([meta['ja3'], meta['ja3s'], meta['sni']]) else None


def compute_ja3_from_packet(pkt) -> Optional[str]:
    """
    Compute JA3 fingerprint from TLS ClientHello packet
    
    JA3 Format: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
    
    Args:
        pkt: Scapy packet with TLS layer
    
    Returns:
        MD5 hash of JA3 string, or None
    """
    if not SCAPY_TLS_AVAILABLE:
        return None
    
    try:
        if not (pkt.haslayer(TCP) and pkt.haslayer(TLSClientHello)):
            return None
        
        client_hello = pkt[TLSClientHello]
        
        # Extract components
        version = str(getattr(client_hello, 'version', 0))
        
        # Cipher suites
        ciphers = getattr(client_hello, 'ciphers', [])
        cipher_str = '-'.join(str(c) for c in ciphers) if ciphers else ''
        
        # Extensions
        extensions = getattr(client_hello, 'ext', [])
        ext_types = []
        ec_list = []
        ec_pf_list = []
        
        for ext in extensions:
            if isinstance(ext, tuple) and len(ext) >= 2:
                ext_type = ext[0]
                ext_types.append(str(ext_type))
                
                # Extract elliptic curves if present
                if hasattr(ext[1], 'groups'):
                    ec_list = [str(g) for g in ext[1].groups]
                
                # Extract point formats if present
                if hasattr(ext[1], 'ecpl'):
                    ec_pf_list = [str(p) for p in ext[1].ecpl]
        
        ext_str = '-'.join(ext_types) if ext_types else ''
        ec_str = '-'.join(ec_list) if ec_list else ''
        ec_pf_str = '-'.join(ec_pf_list) if ec_pf_list else ''
        
        # Build JA3 string
        ja3_str = f"{version},{cipher_str},{ext_str},{ec_str},{ec_pf_str}"
        
        # Compute MD5 hash
        ja3_hash = hashlib.md5(ja3_str.encode()).hexdigest()
        
        logger.debug(f"JA3 computed: {ja3_hash} from {ja3_str[:100]}")
        return ja3_hash
    
    except Exception as e:
        logger.debug(f"JA3 computation error: {e}")
        return None


def compute_ja3s_from_packet(pkt) -> Optional[str]:
    """
    Compute JA3S fingerprint from TLS ServerHello packet
    
    JA3S Format: SSLVersion,Cipher,Extensions
    
    Args:
        pkt: Scapy packet with TLS layer
    
    Returns:
        MD5 hash of JA3S string, or None
    """
    if not SCAPY_TLS_AVAILABLE:
        return None
    
    try:
        if not (pkt.haslayer(TCP) and pkt.haslayer(TLSServerHello)):
            return None
        
        server_hello = pkt[TLSServerHello]
        
        # Extract components
        version = str(getattr(server_hello, 'version', 0))
        
        # Cipher suite (single value for server)
        cipher = getattr(server_hello, 'cipher', 0)
        cipher_str = str(cipher)
        
        # Extensions
        extensions = getattr(server_hello, 'ext', [])
        ext_types = []
        
        for ext in extensions:
            if isinstance(ext, tuple) and len(ext) >= 1:
                ext_types.append(str(ext[0]))
        
        ext_str = '-'.join(ext_types) if ext_types else ''
        
        # Build JA3S string
        ja3s_str = f"{version},{cipher_str},{ext_str}"
        
        # Compute MD5 hash
        ja3s_hash = hashlib.md5(ja3s_str.encode()).hexdigest()
        
        logger.debug(f"JA3S computed: {ja3s_hash}")
        return ja3s_hash
    
    except Exception as e:
        logger.debug(f"JA3S computation error: {e}")
        return None


def lookup_ja3(ja3_hash: str) -> Optional[Dict]:
    """
    Lookup JA3 hash in known fingerprint database
    
    Args:
        ja3_hash: JA3 fingerprint hash
    
    Returns:
        Dictionary with application/threat info, or None
    """
    # In production, this would query a database or API
    # For now, return known fingerprints
    
    known = KNOWN_JA3_FINGERPRINTS.get(ja3_hash)
    if known:
        return {
            'ja3': ja3_hash,
            'application': known.get('app'),
            'description': known.get('desc'),
            'threat_level': known.get('threat', 'unknown')
        }
    
    return None


# Known malicious JA3 fingerprints (sample - expand in production)
KNOWN_MALICIOUS_JA3 = {
    # Metasploit default JA3
    '9e0d43418e0233509774e09171c86818',
    # Cobalt Strike
    'a0e9f5d64349fb13191bc781f81f42e1',
    # Trickbot
    '6734f37431670b3ab4292b8f60f29984',
}


# Known JA3 fingerprints database (sample - expand in production)
KNOWN_JA3_FINGERPRINTS = {
    # Legitimate applications
    '773906b0efdefa24a7f2b8eb6985bf37': {
        'app': 'Chrome',
        'desc': 'Google Chrome browser',
        'threat': 'none'
    },
    'bc6c386f480ee97b9d9e52d472b772d8': {
        'app': 'Firefox',
        'desc': 'Mozilla Firefox browser',
        'threat': 'none'
    },
    '98e5bd2e8e22540d1abc27c5d657faee': {
        'app': 'Python requests',
        'desc': 'Python requests library',
        'threat': 'low'
    },
    
    # Suspicious/malicious
    '9e0d43418e0233509774e09171c86818': {
        'app': 'Metasploit',
        'desc': 'Metasploit Framework default',
        'threat': 'high'
    },
    'a0e9f5d64349fb13191bc781f81f42e1': {
        'app': 'Cobalt Strike',
        'desc': 'Cobalt Strike C2 framework',
        'threat': 'critical'
    },
    '6734f37431670b3ab4292b8f60f29984': {
        'app': 'Trickbot',
        'desc': 'Trickbot malware',
        'threat': 'critical'
    },
}


def get_ja3_statistics(ja3_list: List[str]) -> Dict:
    """
    Analyze list of JA3 fingerprints for statistics
    
    Args:
        ja3_list: List of JA3 hashes
    
    Returns:
        Dictionary with statistics
    """
    from collections import Counter
    
    stats = {
        'total': len(ja3_list),
        'unique': len(set(ja3_list)),
        'most_common': [],
        'malicious_count': 0,
        'suspicious': []
    }
    
    if not ja3_list:
        return stats
    
    # Count occurrences
    counter = Counter(ja3_list)
    stats['most_common'] = counter.most_common(10)
    
    # Check for malicious
    for ja3 in ja3_list:
        if ja3 in KNOWN_MALICIOUS_JA3:
            stats['malicious_count'] += 1
            if ja3 not in stats['suspicious']:
                stats['suspicious'].append(ja3)
    
    return stats
