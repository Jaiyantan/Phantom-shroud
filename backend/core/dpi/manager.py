"""
DPI Manager - Phase 2 skeleton
Provides a lightweight DPI manager with in-memory inspections and rules.
"""

import logging
from collections import deque
from typing import List, Dict, Optional
import threading
from datetime import datetime

logger = logging.getLogger(__name__)


class DPIManager:
    """Simple DPI manager for Phase 2.

    Responsibilities:
    - Manage DPI rules
    - Inspect packets (lightweight) and record inspection results
    - Provide list/search of inspections
    """

    def __init__(self, config: Optional[Dict] = None, db=None, max_inspections: int = 1000):
        self.config = config or {}
        self.db = db
        from .rules import RuleStore
        self.rule_store = RuleStore()
        self._inspections = deque(maxlen=max_inspections)
        self.running = False
        self._lock = threading.Lock()
        logger.info("DPIManager initialized")

    def start(self):
        self.running = True
        logger.info("DPIManager started")

    def stop(self):
        self.running = False
        logger.info("DPIManager stopped")

    def inspect_packet(self, parsed_packet: Dict) -> Optional[Dict]:
        """Inspect a parsed packet (dictionary from TrafficParser).

        This method is intended to be fast; heavy work can be scheduled to workers.
        It returns an inspection dict when a rule or pattern matches, otherwise None.
        """
        try:
            if not parsed_packet:
                return None

            # Run lightweight protocol analyzers and enrich context
            analysis: Dict[str, Dict] = {}
            try:
                from .protocols.http import analyze_http
                from .protocols.dns import analyze_dns
                if 'HTTP' in (parsed_packet.get('protocols') or []) or parsed_packet.get('http'):
                    http_meta = analyze_http(parsed_packet)
                    if http_meta:
                        analysis['http'] = http_meta
                if 'DNS' in (parsed_packet.get('protocols') or []) or parsed_packet.get('dns'):
                    dns_meta = analyze_dns(parsed_packet)
                    if dns_meta:
                        analysis['dns'] = dns_meta
            except Exception as _e:
                logger.debug(f"Analyzer error: {_e}")

            # Evaluate rules with analyzer outputs
            proto_list = parsed_packet.get("protocols", [])
            result = None

            # Rule types: match_protocol, http_host_equals, http_path_contains, dns_query_equals, dns_rcode_not
            for rule in list(self.rule_store.all()):
                rule_id = rule.get('id')
                try:
                    if rule.get('type') == 'match_protocol':
                        if rule.get('protocol') in proto_list:
                            result = self._make_inspection(parsed_packet, rule, rule_id)
                            break
                    elif rule.get('type') in ('host_equals', 'http_host_equals'):
                        http_meta = analysis.get('http') or parsed_packet.get('http') or {}
                        host = http_meta.get('host') if isinstance(http_meta, dict) else None
                        if host and host == rule.get('value'):
                            result = self._make_inspection(parsed_packet, rule, rule_id)
                            break
                    elif rule.get('type') == 'http_path_contains':
                        http_meta = analysis.get('http') or parsed_packet.get('http') or {}
                        path = http_meta.get('path') or ''
                        if rule.get('value') and rule['value'] in path:
                            result = self._make_inspection(parsed_packet, rule, rule_id)
                            break
                    elif rule.get('type') == 'dns_query_equals':
                        dns_meta = analysis.get('dns') or {}
                        qname = ((dns_meta.get('query') or {}).get('qname') or '').lower()
                        val = str(rule.get('value') or '').lower()
                        if qname and val and qname == val:
                            result = self._make_inspection(parsed_packet, rule, rule_id)
                            break
                    elif rule.get('type') == 'dns_rcode_not':
                        dns_meta = analysis.get('dns') or {}
                        rcode = dns_meta.get('rcode')
                        if rcode is not None and rule.get('value') is not None and rcode != rule['value']:
                            result = self._make_inspection(parsed_packet, rule, rule_id)
                            break
                    # Add more rule checks here
                except Exception as e:
                    logger.debug(f"Error evaluating rule {rule_id}: {e}")

            if result:
                if analysis:
                    result['analysis'] = analysis
                with self._lock:
                    self._inspections.append(result)
                logger.info(f"DPI inspection matched rule {result.get('rule_id')}")
                return result

            return None

        except Exception as e:
            logger.error(f"DPI inspection error: {e}")
            return None

    def _make_inspection(self, parsed_packet: Dict, rule: Dict, rule_id: str) -> Dict:
        return {
            'timestamp': datetime.utcnow().isoformat(),
            'src_ip': parsed_packet.get('ip', {}).get('src'),
            'dst_ip': parsed_packet.get('ip', {}).get('dst'),
            'protocols': parsed_packet.get('protocols', []),
            'rule_id': rule_id,
            'rule': rule,
            'details': parsed_packet
        }

    def list_inspections(self, limit: int = 50, filters: Optional[Dict] = None) -> List[Dict]:
        with self._lock:
            items = list(self._inspections)
        if filters:
            # Apply basic filters
            if 'protocol' in filters:
                items = [i for i in items if filters['protocol'] in i.get('protocols', [])]
            if 'src_ip' in filters:
                items = [i for i in items if i.get('src_ip') == filters['src_ip']]
        return items[-limit:][::-1]

    def add_rule(self, rule_dict: Dict) -> Dict:
        from .rules import RuleError
        try:
            rule = self.rule_store.add(rule_dict)
            logger.info(f"Added DPI rule {rule.get('id')}: {rule.get('type')}")
            return rule
        except RuleError as e:
            logger.warning(f"Rule validation failed: {e}")
            raise

    def list_rules(self) -> List[Dict]:
        return self.rule_store.all()

    def remove_rule(self, rule_id: str):
        self.rule_store.remove(rule_id)
        logger.info(f"Removed DPI rule {rule_id}")

    def list_patterns(self) -> List[Dict]:
        # Placeholder for signature/pattern listing
        return []
