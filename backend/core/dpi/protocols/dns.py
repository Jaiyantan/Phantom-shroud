"""
DNS protocol analyzer for DPI Manager (Phase 2)
Extracts basic query/response metadata and flags for unusual conditions.
"""
from typing import Dict, Optional


def analyze_dns(parsed_packet: Dict) -> Optional[Dict]:
    dns = parsed_packet.get('dns')
    if not dns or not isinstance(dns, dict):
        return None

    meta = {
        'id': dns.get('id'),
        'qr': dns.get('qr'),  # 0=query, 1=response
        'opcode': dns.get('opcode'),
        'rcode': dns.get('rcode'),
        'query': None,
        'answers': [],
    }

    queries = dns.get('queries') or []
    if queries:
        q = queries[0]
        meta['query'] = {
            'qname': (q.get('qname') or '').lower(),
            'qtype': q.get('qtype'),
            'qclass': q.get('qclass'),
        }

    answers = dns.get('answers') or []
    for a in answers:
        meta['answers'].append({
            'rrname': str(a.get('rrname')),
            'type': a.get('type'),
            'rdata': str(a.get('rdata')),
        })

    # Simple flags
    flags = []
    if meta.get('rcode') and meta['rcode'] != 0:
        flags.append('dns_error_rcode')
    if meta.get('query') and len(meta['query'].get('qname') or '') > 253:
        flags.append('oversized_qname')

    meta['flags'] = flags
    return meta
