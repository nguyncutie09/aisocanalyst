"""
SOCal SIEM - Stateful Correlation Rules Engine
- YAML-based rules with regex matching
- Time-window correlation (event A -> event B within T seconds)
- Sequence detection (A -> B -> C)
- Threshold detection (N events in T seconds)
- MITRE ATT&CK mapping
"""

import json
import logging
import re
from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Optional
import yaml

logger = logging.getLogger('socal.detection.rules')


class Alert:
    """Represents a triggered security alert"""

    def __init__(self, rule: 'Rule', event: dict, correlation_events: list = None):
        self.rule = rule
        self.triggering_event = event
        self.correlation_events = correlation_events or []
        self.timestamp = datetime.utcnow().isoformat() + 'Z'
        self.id = None  # Set by storage

    def to_dict(self) -> dict:
        return {
            'id': self.id,
            'rule_id': self.rule.id,
            'rule_name': self.rule.name,
            'severity': self.rule.severity,
            'mitre_tactic': self.rule.mitre_tactic,
            'mitre_technique': self.rule.mitre_technique,
            'timestamp': self.timestamp,
            'event_timestamp': self.triggering_event.get('@timestamp'),
            'hostname': self.triggering_event.get('hostname', 'unknown'),
            'source': self.triggering_event.get('source', 'unknown'),
            'message': self.triggering_event.get('message', ''),
            'raw': self.triggering_event.get('raw', ''),
            'tags': list(set(self.rule.tags + self.triggering_event.get('tags', []))),
            'correlation_count': len(self.correlation_events),
            'status': 'open',
        }


class Rule:
    """Single detection rule with matching + correlation logic"""

    def __init__(self, rule_def: dict):
        self.id = rule_def['id']
        self.name = rule_def['name']
        self.severity = rule_def.get('severity', 'medium')
        self.mitre_tactic = rule_def.get('mitre', {}).get('tactic')
        self.mitre_technique = rule_def.get('mitre', {}).get('technique')
        self.tags = rule_def.get('tags', [])
        self.enabled = rule_def.get('enabled', True)
        self.group_by = rule_def.get('group_by', 'hostname')
        self.conditions = rule_def.get('conditions', {})
        self.correlation = rule_def.get('correlation', {})
        self.match_fields = self.conditions.get('match', {})
        self.not_match_fields = self.conditions.get('not_match', {})

        # Pre-compile regex patterns
        self._matchers = {}
        for field, pattern in self.match_fields.items():
            try:
                self._matchers[field] = re.compile(pattern, re.IGNORECASE)
            except re.error as e:
                logger.error(f"Rule {self.id}: invalid regex for {field}: {e}")
                self._matchers[field] = None

        self._neg_matchers = {}
        for field, pattern in self.not_match_fields.items():
            try:
                self._neg_matchers[field] = re.compile(pattern, re.IGNORECASE)
            except re.error as e:
                logger.error(f"Rule {self.id}: invalid neg-regex for {field}: {e}")
                self._neg_matchers[field] = None

        # Correlation state
        self.corr_type = self.correlation.get('type', 'single')
        self.corr_window = self.correlation.get('window_seconds', 300)
        self.corr_threshold = self.correlation.get('count', 5)
        self.corr_sequence = self.correlation.get('sequence', [])

    def matches(self, event: dict) -> bool:
        """Check if a single event matches this rule's conditions"""
        if not self.enabled:
            return False

        # Check match conditions (all must pass)
        for field, pattern in self._matchers.items():
            value = self._get_nested_value(event, field)
            if not value:
                return False
            if pattern and not pattern.search(str(value)):
                return False

        # Check negative match conditions (must NOT match)
        for field, pattern in self._neg_matchers.items():
            value = self._get_nested_value(event, field)
            if value and pattern and pattern.search(str(value)):
                return False

        return True

    def _get_nested_value(self, event: dict, field_path: str):
        """Get nested field value using dot notation (e.g., 'network.address')"""
        parts = field_path.split('.')
        value = event
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            else:
                return None
        return value


class CorrelationEngine:
    """
    Stateful correlation engine managing multiple rules.
    Maintains state per rule per group_by key (e.g., source_ip, hostname)
    """

    def __init__(self, rules_path: str = 'rules/custom_rules.yaml'):
        self.rules: List[Rule] = []
        self._states = defaultdict(lambda: defaultdict(list))  # {rule_id: {group_key: [(ts, event)]}}
        self._load_rules(rules_path)

    def _load_rules(self, path: str):
        try:
            with open(path, 'r') as f:
                data = yaml.safe_load(f)
                if data and 'rules' in data:
                    for rule_def in data['rules']:
                        self.rules.append(Rule(rule_def))
                    logger.info(f"Loaded {len(self.rules)} detection rules from {path}")
        except FileNotFoundError:
            logger.warning(f"Rules file not found: {path} - no rules loaded")
        except Exception as e:
            logger.error(f"Error loading rules: {e}")

    def evaluate(self, event: dict) -> List[Alert]:
        """Evaluate an event against all enabled rules"""
        alerts = []
        for rule in self.rules:
            if not rule.enabled:
                continue

            if not rule.matches(event):
                continue

            # Single event rule
            if not rule.corr_type or rule.corr_type == 'single':
                alerts.append(Alert(rule, event))
                continue

            # Correlation rule - check state
            alert = self._check_correlation(rule, event)
            if alert:
                alerts.append(alert)

        return alerts

    def _check_correlation(self, rule: Rule, event: dict) -> Optional[Alert]:
        """Check correlation state and return alert if triggered"""
        now = datetime.utcnow()

        # Get group key for state isolation
        group_key = str(event.get(rule.group_by, 'default'))
        state = self._states[rule.id][group_key]

        # Prune expired state entries
        cutoff = now - timedelta(seconds=rule.corr_window)
        state[:] = [(ts, evt) for ts, evt in state if ts > cutoff]

        if rule.corr_type == 'threshold':
            # Threshold: N matching events in window
            state.append((now, event))
            if len(state) >= rule.corr_threshold:
                alert = Alert(rule, event, [e for _, e in state])
                state.clear()
                return alert

        elif rule.corr_type == 'sequence':
            # Sequence: A -> B -> C in order within window
            sequence = rule.corr_sequence
            current_step = len(state)

            if current_step >= len(sequence):
                state.clear()
                return None

            step_rule = sequence[current_step]
            # Check current step conditions
            if self._match_step(step_rule, event):
                state.append((now, event))
                if len(state) >= len(sequence):
                    alert = Alert(rule, event, [e for _, e in state])
                    state.clear()
                    return alert

        return None

    def _match_step(self, step_rule: dict, event: dict) -> bool:
        """Check if event matches a sequence step"""
        for field, pattern in step_rule.items():
            value = event
            try:
                for key in field.split('.'):
                    value = value.get(key, {}) if isinstance(value, dict) else ''
                if not re.search(pattern, str(value), re.IGNORECASE):
                    return False
            except Exception:
                return False
        return True

    def get_rule_by_id(self, rule_id: str) -> Optional[Rule]:
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None
