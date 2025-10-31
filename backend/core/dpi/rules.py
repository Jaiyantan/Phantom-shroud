"""
Rule validation and storage for DPI (Phase 2)
Provides a simple in-memory RuleStore with validation and normalization.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple
import re
import threading

# Supported rule types and their schemas
SUPPORTED_RULES = {
    'match_protocol': {
        'required': ['protocol'],
        'optional': ['id', 'description', 'enabled'],
    },
    'host_equals': {  # kept for backward-compat
        'required': ['value'],
        'optional': ['id', 'description', 'enabled'],
        'aliases': ['http_host_equals'],
    },
    'http_host_equals': {
        'required': ['value'],
        'optional': ['id', 'description', 'enabled'],
    },
    'http_path_contains': {
        'required': ['value'],
        'optional': ['id', 'description', 'enabled'],
    },
    'dns_query_equals': {
        'required': ['value'],
        'optional': ['id', 'description', 'enabled'],
    },
    'dns_rcode_not': {
        'required': ['value'],
        'optional': ['id', 'description', 'enabled'],
    },
}


class RuleError(ValueError):
    pass


class RuleStore:
    """Thread-safe in-memory rule store with validation."""

    def __init__(self):
        self._rules: Dict[str, Dict] = {}
        self._lock = threading.Lock()

    def _normalize_type(self, rule_type: str) -> str:
        t = (rule_type or '').strip()
        # Map aliases to canonical types
        if t == 'host_equals':
            return 'http_host_equals'
        return t

    def validate(self, rule: Dict) -> Tuple[bool, Optional[str]]:
        if not isinstance(rule, dict):
            return False, 'rule must be a JSON object'
        rtype = self._normalize_type(rule.get('type') or '')
        if not rtype:
            return False, 'rule "type" is required'
        if rtype not in SUPPORTED_RULES:
            return False, f'unsupported rule type: {rtype}'

        schema = SUPPORTED_RULES[rtype]
        for key in schema['required']:
            if key not in rule:
                return False, f'missing required field: {key}'

        # Specific constraints
        if rtype == 'match_protocol':
            if not isinstance(rule['protocol'], str) or not rule['protocol']:
                return False, 'protocol must be a non-empty string'
        else:
            # Rules with 'value'
            if not isinstance(rule.get('value'), (str, int)) or rule.get('value') in (None, ''):
                return False, 'value must be provided as string or int'

        return True, None

    def add(self, rule: Dict) -> Dict:
        ok, err = self.validate(rule)
        if not ok:
            raise RuleError(err or 'invalid rule')
        rtype = self._normalize_type(rule['type'])
        new_rule = dict(rule)
        new_rule['type'] = rtype
        # Defaults
        if 'enabled' not in new_rule:
            new_rule['enabled'] = True
        # Assign id
        with self._lock:
            rule_id = new_rule.get('id') or str(len(self._rules) + 1)
            new_rule['id'] = rule_id
            self._rules[rule_id] = new_rule
        return new_rule

    def get(self, rule_id: str) -> Optional[Dict]:
        with self._lock:
            return dict(self._rules.get(rule_id)) if rule_id in self._rules else None

    def remove(self, rule_id: str) -> None:
        with self._lock:
            if rule_id not in self._rules:
                raise KeyError('rule not found')
            del self._rules[rule_id]

    def all(self) -> List[Dict]:
        with self._lock:
            return list(self._rules.values())
