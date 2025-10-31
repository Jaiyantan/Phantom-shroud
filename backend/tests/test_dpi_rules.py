import sys
import os
import unittest

# Ensure backend root is on sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_ROOT = os.path.dirname(CURRENT_DIR)
os.sys.path.insert(0, BACKEND_ROOT)

from core.dpi.rules import RuleStore, RuleError
from core.dpi.manager import DPIManager
from api.app import app as flask_app


class TestRuleStore(unittest.TestCase):
    def setUp(self):
        self.store = RuleStore()

    def test_add_match_protocol(self):
        rule = self.store.add({'type': 'match_protocol', 'protocol': 'HTTP'})
        self.assertEqual(rule['type'], 'match_protocol')
        self.assertEqual(rule['protocol'], 'HTTP')
        self.assertTrue(rule['enabled'])
        self.assertIsNotNone(rule['id'])

    def test_alias_host_equals_normalized(self):
        rule = self.store.add({'type': 'host_equals', 'value': 'example.com'})
        self.assertEqual(rule['type'], 'http_host_equals')

    def test_invalid_missing_type(self):
        with self.assertRaises(RuleError):
            self.store.add({'value': 'x'})

    def test_invalid_unsupported_type(self):
        with self.assertRaises(RuleError):
            self.store.add({'type': 'unknown_type', 'value': 'x'})

    def test_invalid_match_protocol_missing_protocol(self):
        with self.assertRaises(RuleError):
            self.store.add({'type': 'match_protocol'})

    def test_invalid_value_missing(self):
        with self.assertRaises(RuleError):
            self.store.add({'type': 'http_host_equals'})


class TestDPIManagerRuleApplication(unittest.TestCase):
    def setUp(self):
        self.dpi = DPIManager()

    def test_http_host_rule_matches(self):
        self.dpi.add_rule({'type': 'http_host_equals', 'value': 'example.com'})
        pkt = {
            'protocols': ['IP', 'TCP', 'HTTP'],
            'ip': {'src': '1.2.3.4', 'dst': '5.6.7.8'},
            'http': {'host': 'example.com', 'path': '/index.html'}
        }
        result = self.dpi.inspect_packet(pkt)
        self.assertIsNotNone(result)
        self.assertEqual(result['rule']['type'], 'http_host_equals')

    def test_dns_query_rule_matches(self):
        self.dpi.add_rule({'type': 'dns_query_equals', 'value': 'example.com'})
        pkt = {
            'protocols': ['IP', 'UDP', 'DNS'],
            'ip': {'src': '1.2.3.4', 'dst': '5.6.7.8'},
            'dns': {'id': 1, 'qr': 0, 'opcode': 0, 'rcode': 0, 'queries': [{'qname': 'example.com', 'qtype': 1, 'qclass': 1}]}
        }
        result = self.dpi.inspect_packet(pkt)
        self.assertIsNotNone(result)
        self.assertEqual(result['rule']['type'], 'dns_query_equals')


class TestDPIApiRoutes(unittest.TestCase):
    def setUp(self):
        # Inject a fresh DPIManager into the Flask app for each test
        self.app = flask_app
        self.app.config['TESTING'] = True
        self.app.config['DPI_MANAGER'] = DPIManager()
        self.client = self.app.test_client()

    def test_add_invalid_rule_returns_400(self):
        resp = self.client.post('/api/dpi/rules', json={'type': 'unknown', 'value': 'x'})
        self.assertEqual(resp.status_code, 400)

    def test_add_and_list_rules(self):
        # Add a valid rule
        r = self.client.post('/api/dpi/rules', json={'type': 'match_protocol', 'protocol': 'HTTP'})
        self.assertEqual(r.status_code, 201)
        # List rules
        resp = self.client.get('/api/dpi/rules')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertGreaterEqual(data.get('count', 0), 1)

    def test_delete_rule(self):
        # Add then delete
        add = self.client.post('/api/dpi/rules', json={'type': 'match_protocol', 'protocol': 'DNS'})
        self.assertEqual(add.status_code, 201)
        rule_id = add.get_json()['rule']['id']
        d = self.client.delete(f'/api/dpi/rules/{rule_id}')
        self.assertEqual(d.status_code, 200)


if __name__ == '__main__':
    unittest.main(verbosity=2)
