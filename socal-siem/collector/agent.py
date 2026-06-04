"""
SOCal SIEM - Log Collector Agent
Collects logs from: auditd, syslog, Suricata Eve, Windows Event (WinRM), file tails
"""

import asyncio
import json
import logging
import re
import socket
from datetime import datetime
from pathlib import Path
from typing import AsyncGenerator, Callable, Optional

logger = logging.getLogger('socal.collector')


class LogCollector:
    """Base collector interface"""

    async def collect(self) -> AsyncGenerator[dict, None]:
        raise NotImplementedError

    async def run(self, callback: Callable = None):
        async for log_entry in self.collect():
            if callback:
                await callback(log_entry)
            yield log_entry


class AuditdCollector(LogCollector):
    """Collect logs from auditd audit.log file"""

    def __init__(self, path: str = '/var/log/audit/audit.log'):
        self.path = Path(path)
        self.last_position = 0
        self._running = False

    async def collect(self) -> AsyncGenerator[dict, None]:
        self._running = True
        while self._running:
            if self.path.exists():
                with open(self.path, 'r') as f:
                    f.seek(self.last_position)
                    for line in f:
                        line = line.strip()
                        if line:
                            yield {
                                'raw': line,
                                'source_type': 'auditd',
                                'collected_at': datetime.utcnow().isoformat() + 'Z'
                            }
                    self.last_position = f.tell()
            await asyncio.sleep(0.5)


class SyslogCollector(LogCollector):
    """UDP syslog receiver on port 514"""

    def __init__(self, host: str = '0.0.0.0', port: int = 514):
        self.host = host
        self.port = port
        self._running = False

    async def collect(self) -> AsyncGenerator[dict, None]:
        self._running = True
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.setblocking(False)

        loop = asyncio.get_event_loop()
        while self._running:
            try:
                data, addr = await loop.sock_recv(sock, 65535)
                yield {
                    'raw': data.decode('utf-8', errors='replace'),
                    'source_type': 'syslog',
                    'source_host': str(addr[0]),
                    'collected_at': datetime.utcnow().isoformat() + 'Z'
                }
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Syslog recv error: {e}")
                await asyncio.sleep(0.1)


class FileCollector(LogCollector):
    """Tail log files (generic)"""

    def __init__(self, path: str, source_type: str = 'file'):
        self.path = Path(path)
        self.source_type = source_type
        self.last_position = 0
        self._running = False

    async def collect(self) -> AsyncGenerator[dict, None]:
        self._running = True
        while self._running:
            if self.path.exists():
                with open(self.path, 'r') as f:
                    f.seek(self.last_position)
                    for line in f:
                        line = line.strip()
                        if line:
                            yield {
                                'raw': line,
                                'source_type': self.source_type,
                                'file_path': str(self.path),
                                'collected_at': datetime.utcnow().isoformat() + 'Z'
                            }
                    self.last_position = f.tell()
            await asyncio.sleep(0.5)


class WindowsEventCollector(LogCollector):
    """Windows Event Log via wevtutil (fallback) or WinRM"""

    def __init__(self, log_names: list = None, poll_interval: int = 10):
        self.log_names = log_names or ['Security', 'System', 'Application']
        self.poll_interval = poll_interval
        self._running = False
        self._last_seen = {}

    async def collect(self) -> AsyncGenerator[dict, None]:
        self._running = True
        while self._running:
            for log_name in self.log_names:
                try:
                    proc = await asyncio.create_subprocess_exec(
                        'wevtutil', 'qe', log_name, '/c:50', '/rd:true', '/f:text',
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout, _ = await proc.communicate()
                    events = stdout.decode('utf-8', errors='replace')
                    for block in events.strip().split('\n\n'):
                        block = block.strip()
                        if block:
                            yield {
                                'raw': block,
                                'source_type': 'windows_event',
                                'log_name': log_name,
                                'collected_at': datetime.utcnow().isoformat() + 'Z'
                            }
                except FileNotFoundError:
                    logger.warning("wevtutil not found - not a Windows system")
                    await asyncio.sleep(60)
                except Exception as e:
                    logger.error(f"Windows event error: {e}")
            await asyncio.sleep(self.poll_interval)


class MockLogGenerator(LogCollector):
    """Generate mock logs for testing"""

    def __init__(self, speed: float = 0.5):
        self.speed = speed
        self._running = False
        self._logs = self._load_samples()

    def _load_samples(self) -> list:
        return [
            # Syslog - SSH failed password
            {
                'raw': 'Jun 16 12:14:23 server1 sshd[4352]: Failed password for root from 192.168.1.100 port 22 ssh2',
                'source_type': 'syslog'
            },
            # Syslog - SSH success
            {
                'raw': 'Jun 16 12:15:01 server1 sshd[4353]: Accepted password for admin from 10.0.0.50 port 22 ssh2',
                'source_type': 'syslog'
            },
            # Auditd - USER_LOGIN success
            {
                'raw': 'type=USER_LOGIN msg=audit(1686921263.456:789): pid=1234 uid=0 auid=1000 ses=1 msg=\'op=login id=1000 exe="/usr/sbin/sshd" hostname=10.0.0.50 addr=10.0.0.50 terminal=ssh res=success\'',
                'source_type': 'auditd'
            },
            # Auditd - USER_LOGIN fail
            {
                'raw': 'type=USER_LOGIN msg=audit(1686921264.789:790): pid=1235 uid=0 auid=4294967295 ses=4294967295 msg=\'op=login id=0 exe="/usr/sbin/sshd" hostname=192.168.1.100 addr=192.168.1.100 terminal=ssh res=failed\'',
                'source_type': 'auditd'
            },
            # Suricata Eve alert
            {
                'raw': '{"timestamp":"2026-06-04T10:30:00.123456+0000","event_type":"alert","src_ip":"45.33.32.156","dest_ip":"10.0.0.5","proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2017912,"rev":5,"signature":"ET MALWARE Known malicious IP (45.33.32.156)","category":"Malware","severity":1}}',
                'source_type': 'suricata'
            },
            # Syslog - sudo command
            {
                'raw': 'Jun 16 14:22:10 server1 sudo[4401]: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash -c "cat /etc/shadow"',
                'source_type': 'syslog'
            },
            # Auditd - SYSCALL
            {
                'raw': 'type=SYSCALL msg=audit(1686922200.123:800): pid=4401 uid=1000 auid=1000 ses=2 msg=\'arch=c000003e syscall=59 success=yes exit=0 a0=7ffe8b3c a1=7ffe8b4d a2=7ffe8b5e a3=8 items=2 ppid=4399 pid=4401 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=2 comm="bash" exe="/usr/bin/bash" key="sudo_command\'',
                'source_type': 'auditd'
            },
            # Suricata - DNS query
            {
                'raw': '{"timestamp":"2026-06-04T10:31:00.654321+0000","event_type":"dns","src_ip":"10.0.0.5","dest_ip":"8.8.8.8","proto":"UDP","dns":{"type":"query","rrname":"evil-malware-panel.com","rcode":"NOERROR"}}',
                'source_type': 'suricata'
            },
            # Brute force sequence
            {
                'raw': 'Jun 16 12:14:24 server1 sshd[4354]: Failed password for root from 192.168.1.100 port 22 ssh2',
                'source_type': 'syslog'
            },
            {
                'raw': 'Jun 16 12:14:25 server1 sshd[4355]: Failed password for root from 192.168.1.100 port 22 ssh2',
                'source_type': 'syslog'
            },
            {
                'raw': 'Jun 16 12:14:26 server1 sshd[4356]: Failed password for root from 192.168.1.100 port 22 ssh2',
                'source_type': 'syslog'
            },
            {
                'raw': 'Jun 16 12:14:27 server1 sshd[4357]: Failed password for root from 192.168.1.100 port 22 ssh2',
                'source_type': 'syslog'
            },
            {
                'raw': 'Jun 16 12:14:28 server1 sshd[4358]: Failed password for root from 192.168.1.100 port 22 ssh2',
                'source_type': 'syslog'
            },
            # Normal event
            {
                'raw': 'Jun 16 12:20:00 server1 cron[4400]: (root) CMD (cd / && run-parts --report /etc/cron.hourly)',
                'source_type': 'syslog'
            },
            # Windows Event (simulated)
            {
                'raw': 'Log Name: Security\nEvent ID: 4625\nAccount Name: Administrator\nSource Network Address: 192.168.1.200\nStatus: 0xC000006A\nFailure Reason: Unknown user name or bad password.',
                'source_type': 'windows_event'
            },
            {
                'raw': 'Log Name: Security\nEvent ID: 4624\nAccount Name: admin\nSource Network Address: 10.0.0.50\nLogon Type: 3',
                'source_type': 'windows_event'
            },
        ]

    async def collect(self) -> AsyncGenerator[dict, None]:
        self._running = True
        i = 0
        while self._running:
            entry = self._logs[i % len(self._logs)].copy()
            entry['collected_at'] = datetime.utcnow().isoformat() + 'Z'
            yield entry
            i += 1
            await asyncio.sleep(self.speed)
