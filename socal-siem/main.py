"""
SOCal SIEM - Main Orchestrator Pipeline
Serves as both CLI pipeline and FastAPI backend for health checks
"""

import argparse
import asyncio
import json
import logging
import os
import signal
import sys
from datetime import datetime

from collector import MockLogGenerator, AuditdCollector, SyslogCollector, FileCollector
from parser import LogParser
from features import FeatureExtractor
from detection import CorrelationEngine, MLDetectionEngine
from ai_soc import SOCAgent

# Configure logging
logging.basicConfig(
    level=getattr(logging, os.getenv('LOG_LEVEL', 'INFO')),
    format='%(asctime)s [%(name)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
logger = logging.getLogger('socal')


class SOCalSIEM:
    """
    Main SOCal SIEM orchestrator.
    Wires all components together: collectors -> parser -> detection -> AI -> output.
    """

    def __init__(self):
        self.collectors = []
        self.parser = LogParser()
        self.feature_extractor = FeatureExtractor(window_seconds=300)
        self.ml_engine = MLDetectionEngine()
        self.rules_engine = CorrelationEngine('rules/custom_rules.yaml')
        self.soc_agent = SOCAgent(
            ollama_url=os.getenv('OLLAMA_URL', 'http://localhost:11434'),
            model=os.getenv('LLM_MODEL', 'qwen2.5:7b'),
        )

        self.running = False
        self.stats = {
            'events_processed': 0,
            'alerts_generated': 0,
            'ml_anomalies': 0,
            'started_at': None,
        }

        # Buffers for dashboard
        self.recent_events = []
        self.recent_alerts = []
        self.max_buffer = 1000

    async def start(self):
        """Start the SIEM pipeline"""
        self.running = True
        self.stats['started_at'] = datetime.utcnow().isoformat() + 'Z'
        logger.info("=" * 60)
        logger.info("SOCal SIEM Pipeline Starting...")
        logger.info("=" * 60)

        # Start collectors based on environment
        collector_tasks = []

        # Always start mock generator for demo/testing
        mock = MockLogGenerator(speed=0.3)
        collector_tasks.append(self._process_collector(mock, 'mock'))

        # Try auditd if on Linux
        if sys.platform != 'win32' and os.path.exists('/var/log/audit/audit.log'):
            collector = AuditdCollector()
            collector_tasks.append(self._process_collector(collector, 'auditd'))
            logger.info("Auditd collector started")

        # Start asyncio tasks
        await asyncio.gather(*collector_tasks, return_exceptions=True)

    async def _process_collector(self, collector, name: str):
        """Process logs from a collector through the pipeline"""
        logger.info(f"Collector '{name}' started")
        try:
            async for raw_log in collector.collect():
                if not self.running:
                    break

                await self._process_log(raw_log, name)

        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Collector '{name}' error: {e}")

    async def _process_log(self, raw_log: dict, collector_name: str):
        """Process a single log through the full pipeline"""
        try:
            # 1. Parse
            parsed = self.parser.parse(raw_log)
            if collector_name == 'mock':
                parsed['source'] = raw_log.get('source_type', 'mock')

            # 2. Feature extraction (for ML)
            features, feature_names = self.feature_extractor.extract(parsed)
            self.ml_engine.add_sample(features, feature_names)

            # 3. ML detection (once trained)
            ml_result = self.ml_engine.predict(features)

            # 4. Rule-based detection
            rule_alerts = self.rules_engine.evaluate(parsed)

            # 5. Merge ML anomaly as alert
            if ml_result['is_anomaly'] and ml_result['anomaly_score'] > 0.6:
                ml_alert = {
                    'rule_id': 'ML_ANOMALY',
                    'rule_name': f"ML Anomaly (score: {ml_result['anomaly_score']:.2f})",
                    'severity': 'high' if ml_result['anomaly_score'] > 0.8 else 'medium',
                    'mitre_tactic': None,
                    'mitre_technique': None,
                    'hostname': parsed.get('hostname', 'unknown'),
                    'source': 'ml_engine',
                    'timestamp': parsed.get('@timestamp'),
                    'event_timestamp': parsed.get('@timestamp'),
                    'message': f"Anomalous event detected: {parsed.get('message', '')[:100]}",
                    'raw': parsed.get('raw', ''),
                    'tags': ['ml_anomaly', 'behavioral'],
                    'ml_score': ml_result['anomaly_score'],
                    'ml_explanation': ml_result.get('contributing_features', []),
                    'status': 'open',
                }
                rule_alerts.append(MLAlertProxy(ml_alert))
                self.stats['ml_anomalies'] += 1

            # 6. Process alerts
            for alert in rule_alerts:
                self.stats['alerts_generated'] += 1
                alert_dict = alert.to_dict() if hasattr(alert, 'to_dict') else alert
                self.recent_alerts.append(alert_dict)
                if len(self.recent_alerts) > self.max_buffer:
                    self.recent_alerts.pop(0)

                # Log alert
                logger.warning(
                    f"[ALERT][{alert_dict.get('severity','').upper()}] "
                    f"{alert_dict.get('rule_name')} "
                    f"| host={alert_dict.get('hostname')} "
                    f"| msg={str(alert_dict.get('message',''))[:80]}"
                )

                # AI Investigation (async, non-blocking)
                if self.soc_agent.auto_investigate:
                    asyncio.create_task(self._investigate_alert(alert_dict))

            # 7. Update stats
            self.stats['events_processed'] += 1
            self.recent_events.append(parsed)
            if len(self.recent_events) > self.max_buffer:
                self.recent_events.pop(0)

        except Exception as e:
            logger.error(f"Pipeline error: {e}", exc_info=True)

    async def _investigate_alert(self, alert: dict):
        """Run AI investigation on an alert"""
        try:
            report = await self.soc_agent.investigate_alert(alert)
            logger.info(f"AI investigation complete for {alert.get('rule_name')}")
            # Store report for dashboard
            if hasattr(self, '_investigation_reports'):
                self._investigation_reports.append(report)
        except Exception as e:
            logger.error(f"AI investigation failed: {e}")

    def stop(self):
        """Graceful shutdown"""
        self.running = False
        logger.info("SOCal SIEM shutting down...")


class MLAlertProxy:
    """Wrapper to make ML alert dicts compatible with Alert interface"""
    def __init__(self, alert_dict: dict):
        self._dict = alert_dict

    def to_dict(self):
        return self._dict


async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='SOCal SIEM Pipeline')
    parser.add_argument('--mock-speed', type=float, default=0.3,
                       help='Mock log generation speed in seconds')
    parser.add_argument('--no-ml', action='store_true',
                       help='Disable ML detection')
    parser.add_argument('--no-ai', action='store_true',
                       help='Disable AI SOC investigation')
    args = parser.parse_args()

    siem = SOCalSIEM()

    if args.no_ai:
        siem.soc_agent.auto_investigate = False

    # Handle graceful shutdown
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, siem.stop)
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            pass

    try:
        await siem.start()
    except asyncio.CancelledError:
        pass
    finally:
        siem.stop()

    # Print final stats
    print(f"\n{'='*60}")
    print(f"SOCal SIEM - Session Complete")
    print(f"{'='*60}")
    print(f"Events processed: {siem.stats['events_processed']}")
    print(f"Alerts generated: {siem.stats['alerts_generated']}")
    print(f"ML anomalies:     {siem.stats['ml_anomalies']}")
    print(f"{'='*60}")


if __name__ == '__main__':
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
