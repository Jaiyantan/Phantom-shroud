"""
HTTP protocol analyzer for DPI Manager (Phase 2)
Takes a parsed packet dict produced by TrafficParser and extracts
lightweight metadata plus a few simple flags.
"""
from typing import Dict, Optional


def analyze_http(parsed_packet: Dict) -> Optional[Dict]:
    http = parsed_packet.get('http')
    if not http or not isinstance(http, dict):
        return None

    meta = {
        'method': http.get('method'),
        'host': http.get('host'),
        'path': http.get('path'),
        'user_agent': http.get('user_agent'),
    }

    # Simple flags
    flags = []
    ua = meta.get('user_agent')
    if ua and len(ua) > 200:
        flags.append('suspicious_ua_length')
    if meta.get('path') and any(part in meta['path'] for part in ['..', '%00', '%2e%2e']):
        flags.append('path_traversal_like')

    meta['flags'] = flags
    return meta
