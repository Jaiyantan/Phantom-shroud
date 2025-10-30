"""
Basic Core Module Tests
Smoke tests for MVP validation
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from core.network_inspector import NetworkInspector
from core.dpi_engine import DPIEngine
from core.anomaly_detector import AnomalyDetector
from core.vpn_manager import VPNManager
from core.honeypot import Honeypot
from core.threat_analyzer import ThreatAnalyzer


class TestNetworkInspector(unittest.TestCase):
    """Test Network Inspector module"""
    
    def test_initialization(self):
        """Test module initializes correctly"""
        inspector = NetworkInspector()
        self.assertIsNotNone(inspector)
        self.assertIsNotNone(inspector.interface)
    
    def test_stats(self):
        """Test statistics retrieval"""
        inspector = NetworkInspector()
        stats = inspector.get_stats()
        self.assertIn('packet_count', stats)
        self.assertIn('flow_count', stats)


class TestDPIEngine(unittest.TestCase):
    """Test DPI Engine module"""
    
    def test_initialization(self):
        """Test module initializes correctly"""
        dpi = DPIEngine()
        self.assertIsNotNone(dpi)
    
    def test_protocol_distribution(self):
        """Test protocol distribution"""
        dpi = DPIEngine()
        dist = dpi.get_protocol_distribution()
        self.assertIsInstance(dist, dict)


class TestAnomalyDetector(unittest.TestCase):
    """Test Anomaly Detector module"""
    
    def test_initialization(self):
        """Test module initializes correctly"""
        detector = AnomalyDetector()
        self.assertIsNotNone(detector)
    
    def test_statistics(self):
        """Test statistics retrieval"""
        detector = AnomalyDetector()
        stats = detector.get_statistics()
        self.assertIn('total_alerts', stats)


class TestVPNManager(unittest.TestCase):
    """Test VPN Manager module"""
    
    def test_initialization(self):
        """Test module initializes correctly"""
        vpn = VPNManager()
        self.assertIsNotNone(vpn)
    
    def test_status(self):
        """Test status retrieval"""
        vpn = VPNManager()
        status = vpn.get_status()
        self.assertIn('connected', status)


class TestHoneypot(unittest.TestCase):
    """Test Honeypot module"""
    
    def test_initialization(self):
        """Test module initializes correctly"""
        honeypot = Honeypot(port=2222)
        self.assertIsNotNone(honeypot)
        self.assertEqual(honeypot.port, 2222)
    
    def test_statistics(self):
        """Test statistics retrieval"""
        honeypot = Honeypot()
        stats = honeypot.get_statistics()
        self.assertIn('total_interactions', stats)


class TestThreatAnalyzer(unittest.TestCase):
    """Test Threat Analyzer module"""
    
    def test_initialization(self):
        """Test module initializes correctly"""
        analyzer = ThreatAnalyzer()
        self.assertIsNotNone(analyzer)
    
    def test_statistics(self):
        """Test statistics retrieval"""
        analyzer = ThreatAnalyzer()
        stats = analyzer.get_statistics()
        self.assertIn('total_events', stats)


if __name__ == '__main__':
    print("Running Phantom-shroud Core Module Tests...")
    unittest.main(verbosity=2)
