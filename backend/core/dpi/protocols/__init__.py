"""Protocol analyzers for DPIManager (Phase 2+)
Exports simple analyze_* helpers that accept a parsed packet dict
and return lightweight metadata and flags.

Phase 2: HTTP, DNS
Phase 2.5: TLS with JA3/JA3S fingerprinting (Joseph's contribution)
"""

from .http import analyze_http
from .dns import analyze_dns
from .tls import analyze_tls, compute_ja3_from_packet, compute_ja3s_from_packet

__all__ = [
    'analyze_http',
    'analyze_dns',
    'analyze_tls',
    'compute_ja3_from_packet',
    'compute_ja3s_from_packet',
]
