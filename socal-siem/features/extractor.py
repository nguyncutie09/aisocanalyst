"""
SOCal SIEM - Feature Extractor
Converts parsed log events into ML-ready feature vectors.
Feature groups:
  - Temporal: hour, day_of_week, is_weekend
  - Event rate: events_per_window, unique_sources
  - Categorical: event_type encoding (template_id), source_type
  - Error ratio: rate of errors/failures in window
  - Network: unique IPs, port entropy
"""

import logging
import numpy as np
from collections import defaultdict
from datetime import datetime
from typing import List, Optional, Tuple

logger = logging.getLogger('socal.features')


class FeatureExtractor:
    """
    Real-time feature extraction from parsed events.
    Maintains a sliding window buffer per source/host for rate features.
    """

    def __init__(self, window_seconds: int = 300):
        self.window_seconds = window_seconds
        # Buffer: {source_key: [(timestamp, event)]}
        self._buffers = defaultdict(list)
        self._seen_templates = set()
        self._feature_dim = None

    def extract(self, event: dict) -> Tuple[np.ndarray, List[str]]:
        """
        Extract feature vector from a parsed event.
        Returns (feature_array, feature_names)
        """
        now = datetime.utcnow()
        ts = now.timestamp()

        source_key = event.get('hostname', event.get('source', 'unknown'))

        # Clean expired entries in buffer
        cutoff = ts - self.window_seconds
        self._buffers[source_key] = [
            (t, e) for t, e in self._buffers[source_key] if t > cutoff
        ]

        # Add current event
        self._buffers[source_key].append((ts, event))

        # Track templates for encoding
        tid = event.get('template_id', -1)
        if isinstance(tid, int) and tid >= 0:
            self._seen_templates.add(tid)

        # =========================================
        # EXTRACT FEATURES
        # =========================================
        features = {}
        window_events = self._buffers[source_key]

        # 1. Temporal features
        features['hour_sin'] = np.sin(2 * np.pi * now.hour / 24.0)
        features['hour_cos'] = np.cos(2 * np.pi * now.hour / 24.0)
        features['day_of_week'] = now.weekday() / 7.0
        features['is_weekend'] = 1.0 if now.weekday() >= 5 else 0.0

        # 2. Event rate features
        features['event_rate'] = len(window_events) / max(self.window_seconds, 1)

        # 3. Source diversity
        unique_types = len(set(e[1].get('source', '') for e in window_events))
        features['source_diversity'] = unique_types / 5.0  # normalize

        # 4. Error/failure ratio
        error_keywords = ['fail', 'error', 'denied', 'rejected', 'invalid', 'bad']
        error_count = sum(
            1 for _, e in window_events
            if any(kw in str(e.get('message', '')).lower() for kw in error_keywords)
            or any(kw in str(e.get('tags', [])).lower() for kw in error_keywords)
        )
        features['error_ratio'] = error_count / max(len(window_events), 1)

        # 5. Template diversity (how many unique templates in window)
        unique_templates = len(set(
            e[1].get('template_id', -1) for _, e in window_events
            if isinstance(e[1].get('template_id', -1), int) and e[1]['template_id'] >= 0
        ))
        features['template_diversity'] = min(unique_templates / 10.0, 1.0)

        # 6. Event type encoding
        source_type = event.get('source', 'unknown')
        features['is_auditd'] = 1.0 if source_type == 'auditd' else 0.0
        features['is_syslog'] = 1.0 if source_type == 'syslog' else 0.0
        features['is_suricata'] = 1.0 if source_type == 'suricata' else 0.0
        features['is_windows'] = 1.0 if source_type == 'windows_event' else 0.0

        # 7. Alert signature (Suricata alert)
        features['is_alert'] = 1.0 if event.get('tags', []) and 'suricata_alert' in event.get('tags', []) else 0.0

        # 8. Login-related
        tags = event.get('tags', [])
        features['is_login'] = 1.0 if any('login' in t for t in tags) else 0.0
        features['is_privilege'] = 1.0 if 'privilege_escalation' in tags else 0.0

        # 9. Severity encoding
        sev = event.get('severity')
        if sev is not None:
            features['severity_normalized'] = min(float(sev) / 5.0, 1.0)
        else:
            features['severity_normalized'] = 0.0

        # 10. Time since last similar event (seconds)
        last_same = None
        for t, e in reversed(window_events[:-1]):  # exclude current
            if e.get('template_id') == tid:
                last_same = t
                break
        if last_same:
            features['time_since_similar'] = min((ts - last_same) / 3600.0, 1.0)
        else:
            features['time_since_similar'] = 0.0

        # Convert to array
        feature_names = sorted(features.keys())
        feature_array = np.array([features[k] for k in feature_names], dtype=np.float32)

        self._feature_dim = len(feature_names)

        return feature_array, feature_names

    def get_feature_dim(self) -> int:
        return self._feature_dim or 0
