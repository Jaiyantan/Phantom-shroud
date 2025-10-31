"""Protocol analyzers for DPIManager (Phase 2)
Exports simple analyze_* helpers that accept a parsed packet dict
and return lightweight metadata and flags.
"""

from .http import analyze_http
from .dns import analyze_dns

__all__ = [
    'analyze_http',
    'analyze_dns',
]
