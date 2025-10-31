"""
DPI (Deep Packet Inspection) Module
Phase 2-4 Implementation

Components:
- DPI Manager for rule-based inspection
- Protocol analyzers (HTTP, DNS, TLS)
- ML-based packet analyzer (Phase 4)
"""

from .manager import DPIManager
from .ml_analyzer import MLPacketAnalyzer

__all__ = [
    'DPIManager',
    'MLPacketAnalyzer',
]
