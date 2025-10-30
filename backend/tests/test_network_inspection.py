"""
Unit Tests for Network Inspection System
Phase 1 Implementation
"""

import unittest
import time
from unittest.mock import Mock, patch, MagicMock
from core.network.interface import InterfaceManager
from core.network.parser import TrafficParser
from core.network.flow_tracker import FlowTracker, Flow
from core.network_inspector import NetworkInspector


class TestInterfaceManager(unittest.TestCase):
    """Test InterfaceManager class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.manager = InterfaceManager()
    
    def test_initialization(self):
        """Test InterfaceManager initialization"""
        self.assertIsNotNone(self.manager)
        self.assertIsInstance(self.manager.interfaces, list)
    
    def test_list_interfaces(self):
        """Test listing network interfaces"""
        interfaces = self.manager.list_interfaces()
        self.assertIsInstance(interfaces, list)
    
    def test_get_default_interface(self):
        """Test getting default interface"""
        default = self.manager.get_default_interface()
        # May be None if no interfaces available
        if default:
            self.assertIsInstance(default, str)
    
    def test_get_monitorable_interfaces(self):
        """Test getting monitorable interfaces"""
        monitorable = self.manager.get_monitorable_interfaces()
        self.assertIsInstance(monitorable, list)
        # Should not include loopback
        self.assertNotIn('lo', monitorable)
    
    def test_is_wireless(self):
        """Test wireless interface detection"""
        # Test common wireless interface names
        self.assertTrue(self.manager.is_wireless('wlan0'))
        self.assertTrue(self.manager.is_wireless('wlp3s0'))
        self.assertFalse(self.manager.is_wireless('eth0'))
        self.assertFalse(self.manager.is_wireless('lo'))


class TestTrafficParser(unittest.TestCase):
    """Test TrafficParser class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.parser = TrafficParser()
    
    def test_initialization(self):
        """Test TrafficParser initialization"""
        self.assertIsNotNone(self.parser)
        self.assertEqual(self.parser.parsed_count, 0)
    
    def test_get_statistics(self):
        """Test getting parser statistics"""
        stats = self.parser.get_statistics()
        self.assertIsInstance(stats, dict)
        self.assertIn('total_parsed', stats)
        self.assertEqual(stats['total_parsed'], 0)


class TestFlow(unittest.TestCase):
    """Test Flow class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.five_tuple = ('192.168.1.1', '8.8.8.8', 12345, 80, 'TCP')
        self.flow = Flow(self.five_tuple)
    
    def test_initialization(self):
        """Test Flow initialization"""
        self.assertEqual(self.flow.src_ip, '192.168.1.1')
        self.assertEqual(self.flow.dst_ip, '8.8.8.8')
        self.assertEqual(self.flow.src_port, 12345)
        self.assertEqual(self.flow.dst_port, 80)
        self.assertEqual(self.flow.protocol, 'TCP')
        self.assertEqual(self.flow.packet_count, 0)
        self.assertEqual(self.flow.byte_count, 0)
    
    def test_update(self):
        """Test flow update"""
        self.flow.update(1500, ['SYN'])
        self.assertEqual(self.flow.packet_count, 1)
        self.assertEqual(self.flow.byte_count, 1500)
        self.assertIn('SYN', self.flow.flags)
        
        self.flow.update(1000, ['ACK'])
        self.assertEqual(self.flow.packet_count, 2)
        self.assertEqual(self.flow.byte_count, 2500)
        self.assertIn('ACK', self.flow.flags)
    
    def test_duration(self):
        """Test flow duration calculation"""
        duration = self.flow.duration()
        self.assertIsInstance(duration, float)
        self.assertGreaterEqual(duration, 0)
    
    def test_to_dict(self):
        """Test flow to dictionary conversion"""
        flow_dict = self.flow.to_dict()
        self.assertIsInstance(flow_dict, dict)
        self.assertEqual(flow_dict['src_ip'], '192.168.1.1')
        self.assertEqual(flow_dict['dst_ip'], '8.8.8.8')
        self.assertEqual(flow_dict['protocol'], 'TCP')


class TestFlowTracker(unittest.TestCase):
    """Test FlowTracker class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.tracker = FlowTracker(timeout=60)
    
    def test_initialization(self):
        """Test FlowTracker initialization"""
        self.assertIsNotNone(self.tracker)
        self.assertEqual(self.tracker.timeout, 60)
        self.assertEqual(len(self.tracker.flows), 0)
    
    def test_get_statistics(self):
        """Test getting tracker statistics"""
        stats = self.tracker.get_statistics()
        self.assertIsInstance(stats, dict)
        self.assertIn('active_flows', stats)
        self.assertIn('total_flows', stats)
        self.assertIn('total_packets', stats)
        self.assertIn('total_bytes', stats)
    
    def test_get_active_flows(self):
        """Test getting active flows"""
        flows = self.tracker.get_active_flows()
        self.assertIsInstance(flows, list)
    
    def test_get_protocol_distribution(self):
        """Test getting protocol distribution"""
        distribution = self.tracker.get_protocol_distribution()
        self.assertIsInstance(distribution, dict)
    
    def test_reset_statistics(self):
        """Test resetting statistics"""
        self.tracker.reset_statistics()
        stats = self.tracker.get_statistics()
        self.assertEqual(stats['total_packets'], 0)
        self.assertEqual(stats['total_bytes'], 0)


class TestNetworkInspector(unittest.TestCase):
    """Test NetworkInspector class"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Mock network interface to avoid actual network access
        with patch('core.network.interface.InterfaceManager'):
            self.inspector = NetworkInspector(interface='eth0', auto_start=False)
    
    def test_initialization(self):
        """Test NetworkInspector initialization"""
        self.assertIsNotNone(self.inspector)
        self.assertEqual(self.inspector.interface, 'eth0')
        self.assertFalse(self.inspector.is_running)
    
    def test_get_stats(self):
        """Test getting inspector statistics"""
        stats = self.inspector.get_stats()
        self.assertIsInstance(stats, dict)
        self.assertIn('is_running', stats)
        self.assertIn('interface', stats)
        self.assertIn('flows', stats)
        self.assertIn('protocols', stats)
    
    def test_get_protocol_distribution(self):
        """Test getting protocol distribution"""
        distribution = self.inspector.get_protocol_distribution()
        self.assertIsInstance(distribution, dict)
    
    @patch('core.network.capture.PacketCapture')
    def test_start_stop(self, mock_capture):
        """Test starting and stopping inspection"""
        # Mock the capture instance
        mock_instance = MagicMock()
        mock_capture.return_value = mock_instance
        
        # Create new inspector with mocked capture
        inspector = NetworkInspector(interface='eth0', auto_start=False)
        
        # Test start
        inspector.start()
        self.assertTrue(inspector.is_running)
        
        # Test stop
        inspector.stop()
        self.assertFalse(inspector.is_running)


def run_tests():
    """Run all tests"""
    unittest.main()


if __name__ == '__main__':
    run_tests()
