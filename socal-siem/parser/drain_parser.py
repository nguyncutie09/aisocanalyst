"""
SOCal SIEM - Log Parser & Event Normalizer
Uses Drain3 for template mining + regex for field extraction
Outputs ECS (Elastic Common Schema)-like normalized events
"""

import json
import logging
import re
from datetime import datetime
from typing import Optional

logger = logging.getLogger('socal.parser')


class EventNormalizer:
    """
    Normalize parsed fields into ECS-like schema.
    Handles: auditd, syslog, Suricata Eve JSON, Windows Event, generic
    """

    # Auditd pattern
    AUDITD_RE = re.compile(
        r'type=(?P<audit_type>\w+)'
        r'\s+msg=audit\((?P<timestamp_raw>[\d.]+):\d+\):'
        r'\s+pid=(?P<pid>\d+)'
        r'\s+uid=(?P<uid>\d+)'
        r'\s+auid=(?P<auid>\d+)'
        r'\s+ses=(?P<ses>\d+)'
        r"\s+msg='(?P<msg>[^']+)'"
    )

    # Syslog pattern (RFC3164)
    SYSLOG_RE = re.compile(
        r'(?P<timestamp>\w{3}\s+\d+\s+[\d:]+)\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<app>\S+?)(?:\[\d+\])?:\s*'
        r'(?P<msg>.+)'
    )

    # SSH failed password
    SSH_FAIL_RE = re.compile(
        r'Failed\s+password\s+for\s+(?P<ssh_user>\S+)\s+from\s+(?P<src_ip>\S+)\s+port\s+(?P<src_port>\d+)'
    )

    # SSH accepted
    SSH_ACCEPT_RE = re.compile(
        r'Accepted\s+password\s+for\s+(?P<ssh_user>\S+)\s+from\s+(?P<src_ip>\S+)\s+port\s+(?P<src_port>\d+)'
    )

    # Auditd USER_LOGIN detail
    AUDIT_LOGIN_RE = re.compile(
        r"op=(?P<login_op>\S+)\s+"
        r"id=(?P<login_id>\d+)\s+"
        r'exe="(?P<exe>[^"]+)"\s+'
        r'hostname=(?P<hostname>\S+)\s+'
        r'addr=(?P<addr>\S+)\s+'
        r'terminal=(?P<terminal>\S+)\s+'
        r'res=(?P<result>\S+)'
    )

    # Sudo command
    SUDO_RE = re.compile(
        r'(?P<sudo_user>\S+)\s*:\s*TTY=(?P<tty>\S+)\s*;\s*PWD=(?P<pwd>\S+)\s*;\s*USER=(?P<runas_user>\S+)\s*;\s*COMMAND=(?P<command>.+)'
    )

    # IP address
    IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    def normalize(self, raw_log: dict) -> dict:
        """
        Main entry: parse raw log text and return normalized event
        """
        raw_text = raw_log.get('raw', '')
        source_type = raw_log.get('source_type', 'unknown')

        event = {
            '@timestamp': raw_log.get('collected_at', datetime.utcnow().isoformat() + 'Z'),
            'source': source_type,
            'hostname': raw_log.get('source_host', raw_log.get('hostname', 'unknown')),
            'raw': raw_text,
            'message': '',
            'event': {},
            'user': {},
            'process': {},
            'network': {},
            'tags': [],
            'event_id': None,
            'severity': None,
        }

        if source_type == 'auditd':
            self._parse_auditd(raw_text, event)
        elif source_type == 'syslog':
            self._parse_syslog(raw_text, event)
        elif source_type == 'suricata':
            self._parse_suricata(raw_text, event)
        elif source_type == 'windows_event':
            self._parse_windows_event(raw_text, event)
        else:
            event['message'] = raw_text[:500]

        return event

    def _parse_auditd(self, raw: str, event: dict):
        m = self.AUDITD_RE.search(raw)
        if m:
            groups = m.groupdict()
            event['event_id'] = groups.get('audit_type')
            event['process']['pid'] = int(groups['pid']) if groups.get('pid') else None
            event['user']['uid'] = groups.get('uid')
            event['user']['auid'] = groups.get('auid')
            event['user']['ses'] = groups.get('ses')

            msg = groups.get('msg', '')
            event['message'] = msg

            # Parse audit detail if available
            detail_m = self.AUDIT_LOGIN_RE.search(msg)
            if detail_m:
                detail = detail_m.groupdict()
                event['event']['login_op'] = detail.get('login_op')
                event['event']['login_id'] = detail.get('login_id')
                event['process']['executable'] = detail.get('exe')
                event['hostname'] = detail.get('hostname') or event['hostname']
                event['network']['address'] = detail.get('addr')
                event['event']['terminal'] = detail.get('terminal')
                event['event']['result'] = detail.get('result')

                if detail.get('result') == 'success':
                    event['tags'].append('login_success')
                else:
                    event['tags'].append('login_failure')

        # Fallback: try audit keyword matching
        if 'failed' in raw.lower():
            event['tags'].append('failed')
        if 'success' in raw.lower():
            event['tags'].append('success')

    def _parse_syslog(self, raw: str, event: dict):
        m = self.SYSLOG_RE.search(raw)
        if m:
            groups = m.groupdict()
            event['hostname'] = groups.get('hostname', event['hostname'])
            event['process']['name'] = groups.get('app')
            msg = groups.get('msg', '')
            event['message'] = msg

            # SSH parsing
            ssh_match = self.SSH_FAIL_RE.search(msg)
            if ssh_match:
                event['event']['type'] = 'ssh_failed'
                event['user']['ssh_user'] = ssh_match.group('ssh_user')
                event['network']['address'] = ssh_match.group('src_ip')
                event['network']['port'] = int(ssh_match.group('src_port'))
                event['tags'].append('ssh_brute_force')
                event['severity'] = 'medium'
                return

            ssh_match = self.SSH_ACCEPT_RE.search(msg)
            if ssh_match:
                event['event']['type'] = 'ssh_success'
                event['user']['ssh_user'] = ssh_match.group('ssh_user')
                event['network']['address'] = ssh_match.group('src_ip')
                event['network']['port'] = int(ssh_match.group('src_port'))
                event['tags'].append('ssh_login')
                return

            # Sudo parsing
            sudo_match = self.SUDO_RE.search(msg)
            if sudo_match:
                event['event']['type'] = 'sudo_command'
                event['user']['sudo_user'] = sudo_match.group('sudo_user')
                event['user']['runas_user'] = sudo_match.group('runas_user')
                event['process']['command'] = sudo_match.group('command')
                event['tags'].append('privilege_escalation')

        # IP extraction from raw
        ips = self.IP_RE.findall(raw)
        if ips and not event.get('network', {}).get('address'):
            event['network']['address'] = ips[0]

    def _parse_suricata(self, raw: str, event: dict):
        try:
            suri = json.loads(raw)
            event_type = suri.get('event_type', 'unknown')

            event['event_id'] = f"suricata_{event_type}"
            event['event']['type'] = event_type
            event['network']['source_ip'] = suri.get('src_ip')
            event['network']['destination_ip'] = suri.get('dest_ip')
            event['network']['protocol'] = suri.get('proto', '').lower()

            if event_type == 'alert':
                alert = suri.get('alert', {})
                event['event']['signature'] = alert.get('signature')
                event['event']['category'] = alert.get('category')
                event['event']['signature_id'] = alert.get('signature_id')
                event['severity'] = alert.get('severity', 3)
                event['message'] = alert.get('signature', '')
                event['tags'].append('suricata_alert')

                if alert.get('severity', 3) <= 2:
                    event['tags'].append('high_priority')

            elif event_type == 'dns':
                dns = suri.get('dns', {})
                event['event']['dns_query'] = dns.get('rrname')
                event['event']['dns_type'] = dns.get('type')
                event['event']['dns_rcode'] = dns.get('rcode')
                event['message'] = f"DNS {dns.get('type')}: {dns.get('rrname')}"

            elif event_type == 'http':
                http = suri.get('http', {})
                event['network']['http_url'] = http.get('url')
                event['network']['http_hostname'] = http.get('hostname')
                event['network']['http_method'] = http.get('http_method')
                event['message'] = f"HTTP {http.get('http_method')} {http.get('url')}"

            # Use suricata timestamp if available
            if suri.get('timestamp'):
                event['@timestamp'] = suri['timestamp']

        except json.JSONDecodeError:
            event['message'] = raw[:500]
            event['tags'].append('parse_error')

    def _parse_windows_event(self, raw: str, event: dict):
        event['message'] = raw[:500]
        event['tags'].append('windows')

        # Extract Event ID
        m = re.search(r'Event ID:\s*(\d+)', raw)
        if m:
            event['event_id'] = int(m.group(1))

        # Extract Account Name
        m = re.search(r'Account Name:\s*(\S+)', raw)
        if m:
            event['user']['account'] = m.group(1)

        # Extract Source IP
        m = re.search(r'Source Network Address:\s*(\S+)', raw)
        if m:
            event['network']['address'] = m.group(1)

        # Map event IDs
        eid = event.get('event_id')
        if eid == 4625:
            event['event']['type'] = 'windows_logon_failure'
            event['tags'].append('login_failure')
        elif eid == 4624:
            event['event']['type'] = 'windows_logon_success'
            event['tags'].append('login_success')
        elif eid == 4688:
            event['event']['type'] = 'process_creation'
            event['tags'].append('process')
        elif eid == 5156:
            event['event']['type'] = 'network_connection'
            event['tags'].append('network')


class LogParser:
    """
    Main log parser using Drain3 for template mining
    + regex-based field extraction via EventNormalizer
    """

    def __init__(self):
        self.normalizer = EventNormalizer()

        # Drain3 template miner
        try:
            from drain3 import TemplateMiner
            from drain3.template_miner_config import TemplateMinerConfig
            config = TemplateMinerConfig()
            config.load('drain3.ini')
            self.template_miner = TemplateMiner(config=config)
            self.drain_available = True
        except (ImportError, FileNotFoundError):
            logger.warning("Drain3 not available - using regex-only parsing")
            self.template_miner = None
            self.drain_available = False
            self._fallback_templates = {}

    def parse(self, raw_log: dict) -> dict:
        """
        Parse and normalize a raw log entry.
        Returns normalized event with template_id and parameters.
        """
        # Step 1: Normalize fields
        event = self.normalizer.normalize(raw_log)

        # Step 2: Template mining with Drain3
        raw_text = raw_log.get('raw', '')
        if self.drain_available and raw_text:
            try:
                result = self.template_miner.add_log_message(raw_text)
                event['template_id'] = result.get('cluster_id')
                event['template'] = result.get('template_mined')
                event['template_count'] = result.get('total_clusters')
            except Exception as e:
                logger.debug(f"Drain3 parsing error: {e}")
                event['template_id'] = -1
                event['template'] = raw_text[:200]
        else:
            # Fallback: simple template by message prefix
            msg_hash = hash(raw_text[:100]) % 10000
            event['template_id'] = msg_hash
            event['template'] = raw_text[:200]

        return event
