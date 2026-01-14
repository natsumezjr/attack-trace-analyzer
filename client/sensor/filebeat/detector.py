#!/usr/bin/env python3
"""
Ubuntu Log Anomaly Detector

Monitors ECS-formatted logs from Filebeat and detects anomalies
using Sigma rules, marking suspicious events in the output.
"""

import json
import os
import re
import time
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any

try:
    import yaml
except ImportError:
    print("Error: PyYAML not installed. Run: pip3 install pyyaml")
    exit(1)


class RabbitPublisher:
    def __init__(self, amqp_url: str, queue_name: str):
        try:
            import pika
        except ImportError:
            print("Error: pika not installed. Add it to requirements.txt")
            exit(1)
        self._pika = pika
        self.amqp_url = amqp_url
        self.queue_name = queue_name
        self.connection = None
        self.channel = None
        self._connect()

    def _connect(self):
        params = self._pika.URLParameters(self.amqp_url)
        self.connection = self._pika.BlockingConnection(params)
        self.channel = self.connection.channel()
        self.channel.queue_declare(queue=self.queue_name, durable=True)

    def publish(self, payload: Dict[str, Any]):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        try:
            if self.connection.is_closed or self.channel.is_closed:
                self._connect()
            self.channel.basic_publish(
                exchange="",
                routing_key=self.queue_name,
                body=body,
                properties=self._pika.BasicProperties(delivery_mode=2),
            )
        except Exception:
            self._connect()
            self.channel.basic_publish(
                exchange="",
                routing_key=self.queue_name,
                body=body,
                properties=self._pika.BasicProperties(delivery_mode=2),
            )


class SigmaRule:
    """Represents a Sigma detection rule"""

    def __init__(self, rule_data: Dict[str, Any]):
        self.id = rule_data.get('id', 'unknown')
        self.title = rule_data.get('title', 'Unknown Rule')
        self.description = rule_data.get('description', '')
        self.level = rule_data.get('level', 'medium')
        self.tags = rule_data.get('tags', [])
        self.detection = rule_data.get('detection', {})
        self.logsource = rule_data.get('logsource', {})

    def match(self, log_entry: Dict[str, Any]) -> bool:
        """Check if log entry matches this rule"""
        message = log_entry.get('message', '')

        if not message:
            return False

        selection = self.detection.get('selection', [])

        if not isinstance(selection, list):
            selection = [selection]

        for sel in selection:
            if self._match_selection(message, sel):
                return True

        return False

    def _match_selection(self, message: str, selection: Any) -> bool:
        """Match a single selection criteria"""
        if isinstance(selection, dict):
            for key, value in selection.items():
                if key == 'message|contains':
                    if isinstance(value, str):
                        if value.lower() in message.lower():
                            return True
                    elif isinstance(value, list):
                        if any(v.lower() in message.lower() for v in value):
                            return True

                elif key == 'message|contains|all':
                    if isinstance(value, list):
                        if all(v.lower() in message.lower() for v in value):
                            return True

        return False


class AnomalyDetector:
    """Main anomaly detection engine"""

    def __init__(self, rules_dir: str, input_file: str, output_dir: str):
        self.rules_dir = Path(rules_dir)
        self.input_file = Path(input_file)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

        self.rules: List[SigmaRule] = []
        self.event_counter = defaultdict(int)
        self.last_position = 0

        # Stats
        self.total_logs = 0
        self.anomalies_found = 0

        # Cleanup tracking
        self.last_cleanup_time = datetime.utcnow()
        self.cleanup_interval = timedelta(minutes=1)  # 每 1 分钟检查一次
        self.retention_period = timedelta(minutes=5)  # 保留 5 分钟内的记录

        # RabbitMQ publisher
        amqp_url = os.getenv('RABBITMQ_URL', 'amqp://guest:guest@rabbitmq:5672/')
        queue_name = os.getenv('RABBITMQ_QUEUE', 'data.filebeat')
        self.publisher = RabbitPublisher(amqp_url, queue_name)

    def load_rules(self):
        """Load all Sigma rules from rules directory"""
        print(f"Loading Sigma rules from {self.rules_dir}...")

        if not self.rules_dir.exists():
            print(f"Error: Rules directory {self.rules_dir} not found")
            return

        for rule_file in self.rules_dir.glob('*.yml'):
            try:
                with open(rule_file, 'r') as f:
                    rule_data = yaml.safe_load(f)
                    rule = SigmaRule(rule_data)
                    self.rules.append(rule)
                    print(f"  ✓ Loaded: {rule.title}")
            except Exception as e:
                print(f"  ✗ Error loading {rule_file.name}: {e}")

        print(f"Loaded {len(self.rules)} detection rules\n")

    def publish_log_entry(self, log_entry: Dict[str, Any]):
        """Publish a log entry to RabbitMQ"""
        self.publisher.publish(log_entry)

    def cleanup_old_json_records(self):
        """清理 JSON 文件中 5 分钟之前的记录（已发送到消息队列）"""
        try:
            current_time = datetime.utcnow()
            cutoff_time = current_time - self.retention_period

            output_file = self.output_dir / 'ecs_logs_with_anomalies.json'
            anomalies_file = self.output_dir / 'anomalies.json'

            # 清理主输出文件
            if output_file.exists():
                self._cleanup_json_file(output_file, cutoff_time)

            # 清理异常文件
            if anomalies_file.exists():
                self._cleanup_json_file(anomalies_file, cutoff_time)

            print(f"[清理] 已清理 5 分钟前的 JSON 记录 (数据已在消息队列中发送)")

        except Exception as e:
            print(f"[清理] 清理失败: {e}")

    def _cleanup_json_file(self, file_path: Path, cutoff_time: datetime):
        """清理单个 JSON 文件中的旧记录"""
        try:
            # 读取所有记录
            recent_records = []
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        record = json.loads(line)
                        # 检查记录的时间戳
                        timestamp_str = record.get('event', {}).get('ingested') or record.get('@timestamp')
                        if timestamp_str:
                            # 解析时间戳
                            if timestamp_str.endswith('Z'):
                                timestamp_str = timestamp_str[:-1]
                            record_time = datetime.fromisoformat(timestamp_str.replace('Z', ''))

                            # 只保留 5 分钟内的记录
                            if record_time >= cutoff_time:
                                recent_records.append(record)
                    except (json.JSONDecodeError, ValueError):
                        continue

            # 重新写入最近的记录
            with open(file_path, 'w') as f:
                for record in recent_records:
                    f.write(json.dumps(record) + '\n')

        except Exception as e:
            print(f"[清理] 清理文件 {file_path} 失败: {e}")

    def process_log_entry(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Process a single log entry and mark if anomalous"""
        self.total_logs += 1

        # 确保ECS版本正确
        if 'ecs' not in log_entry:
            log_entry['ecs'] = {}
        log_entry['ecs']['version'] = '9.2.0'

        # 确保event.ingested时间存在
        if 'event' not in log_entry:
            log_entry['event'] = {}
        if 'ingested' not in log_entry['event']:
            log_entry['event']['ingested'] = datetime.utcnow().isoformat() + 'Z'

        # Check against all rules
        matched_rules = []
        for rule in self.rules:
            if rule.match(log_entry):
                # 解析MITRE ATT&CK标签
                technique_id = None
                technique_name = None
                tactic_id = None
                tactic_name = None

                for tag in rule.tags:
                    if tag.startswith('attack.t') and '.' not in tag[8:]:
                        # 如 attack.t1110
                        technique_id = tag[7:].upper()  # T1110
                    elif tag.startswith('attack.ta'):
                        # 如 attack.ta0005
                        tactic_id = tag[7:].upper()  # TA0005

                # 映射技术名称（简化示例）
                technique_names = {
                    'T1110': 'Brute Force',
                    'T1548': 'Abuse Elevation Control Mechanism',
                    'T1136': 'Create Account',
                    'T1543': 'Create or Modify System Process',
                    'T1059': 'Command and Scripting Interpreter'
                }
                tactic_names = {
                    'TA0005': 'Defense Evasion',
                    'TA0003': 'Persistence',
                    'TA0002': 'Execution',
                    'TA0006': 'Credential Access'
                }

                if technique_id:
                    technique_name = technique_names.get(technique_id, 'Unknown Technique')
                if tactic_id:
                    tactic_name = tactic_names.get(tactic_id, 'Unknown Tactic')

                # 映射严重度到数字(0-100)
                severity_map = {'low': 30, 'medium': 50, 'high': 70, 'critical': 90}
                severity_num = severity_map.get(rule.level, 50)

                matched_rules.append({
                    'rule_id': rule.id,
                    'rule_name': rule.title,
                    'severity': rule.level,
                    'severity_num': severity_num,
                    'tags': rule.tags,
                    'description': rule.description,
                    'technique_id': technique_id,
                    'technique_name': technique_name,
                    'tactic_id': tactic_id,
                    'tactic_name': tactic_name
                })

        # If anomalies detected, mark the log (following ECS v9.2.0 Finding format)
        if matched_rules:
            self.anomalies_found += 1

            # 修改为alert类型（ECS字段规范要求）
            log_entry['event']['kind'] = 'alert'
            log_entry['event']['category'] = ['intrusion_detection']
            log_entry['event']['type'] = ['indicator']
            log_entry['event']['severity'] = matched_rules[0]['severity_num']
            dataset = log_entry.get('event', {}).get('dataset')
            if not dataset or dataset == 'finding.raw':
                dataset = 'finding.raw.filebeat_sigma'
            log_entry['event']['dataset'] = dataset

            # 添加rule字段（ECS标准）
            log_entry['rule'] = {
                'id': matched_rules[0]['rule_id'],
                'name': matched_rules[0]['rule_name'],
                'ruleset': 'sigma'
            }

            # 添加risk_score（ECS标准）
            log_entry['risk'] = {
                'score': float(matched_rules[0]['severity_num'])
            }

            # 添加tags（包含ATT&CK标签）
            log_entry['tags'] = matched_rules[0]['tags']

            # 添加threat字段（MITRE ATT&CK映射，ECS要求）
            if matched_rules[0]['technique_id'] and matched_rules[0]['tactic_id']:
                log_entry['threat'] = {
                    'framework': 'MITRE ATT&CK',
                    'tactic': {
                        'id': matched_rules[0]['tactic_id'],
                        'name': matched_rules[0]['tactic_name']
                    },
                    'technique': {
                        'id': matched_rules[0]['technique_id'],
                        'name': matched_rules[0]['technique_name']
                    }
                }

            # 添加custom字段（ECS扩展，用于告警融合）
            log_entry['custom'] = {
                'finding': {
                    'stage': 'raw',
                    'providers': ['sigma-detector'],
                    'fingerprint': f"fp-{matched_rules[0]['rule_id']}-{log_entry.get('host', {}).get('id', 'unknown')}"
                },
                'evidence': {
                    'event_ids': [log_entry.get('event', {}).get('id', 'unknown')]
                }
            }

            # 保留原有的anomaly字段（向后兼容）
            log_entry['anomaly'] = {
                'detected': True,
                'detection_timestamp': datetime.utcnow().isoformat() + 'Z',
                'matched_rules': matched_rules,
                'rule_count': len(matched_rules)
            }

        return log_entry

    def watch_logs(self):
        """Monitor log file for new entries"""
        print(f"Monitoring logs: {self.input_file}")
        print(f"Output directory: {self.output_dir}")
        print(f"Press Ctrl+C to stop\n")

        output_file = self.output_dir / 'ecs_logs_with_anomalies.json'
        anomalies_file = self.output_dir / 'anomalies.json'

        # Track processed files
        processed_files = {}

        try:
            while True:
                # Find all log files (including rotated .ndjson files)
                log_files = list(self.input_file.parent.glob('ecs_logs.json*'))

                if not log_files:
                    print(f"Waiting for log files in: {self.input_file.parent}")
                    time.sleep(5)
                    continue

                # Process each file
                for log_file in sorted(log_files):
                    if not log_file.exists():
                        continue

                    # Initialize position tracker for new files
                    if log_file not in processed_files:
                        processed_files[log_file] = 0
                        print(f"Found new log file: {log_file}")

                    # Skip if no new content
                    current_size = log_file.stat().st_size
                    if current_size <= processed_files[log_file]:
                        continue

                    # Read new content from this file
                    with open(log_file, 'r') as f:
                        f.seek(processed_files[log_file])

                        for line in f:
                            line = line.strip()
                            if not line:
                                continue

                            try:
                                log_entry = json.loads(line)
                                processed_entry = self.process_log_entry(log_entry)

                                # Write all logs to output file
                                with open(output_file, 'a') as out:
                                    out.write(json.dumps(processed_entry) + '\n')

                                # Publish to RabbitMQ (both anomalies and normal logs)
                                self.publish_log_entry(processed_entry)

                                # Write anomalies to separate file
                                if 'anomaly' in processed_entry:
                                    with open(anomalies_file, 'a') as anom:
                                        anom.write(json.dumps(processed_entry, indent=2) + '\n')

                                    print(f"🚨 ANOMALY DETECTED: {processed_entry.get('message', '')[:80]}")
                                    for rule in processed_entry['anomaly']['matched_rules']:
                                        print(f"   Rule: {rule['rule_name']} (severity: {rule['severity']})")
                                        if rule['technique_id']:
                                            print(f"   MITRE ATT&CK: {rule['technique_id']} - {rule['technique_name']}")
                                    print()

                            except json.JSONDecodeError:
                                continue

                        # Update position for this file
                        processed_files[log_file] = f.tell()

                # Print stats periodically
                if self.total_logs > 0 and self.total_logs % 100 == 0:
                    print(f"Stats: {self.total_logs} logs processed, {self.anomalies_found} anomalies found")

                # 定期清理旧的 JSON 记录
                current_time = datetime.utcnow()
                if current_time - self.last_cleanup_time >= self.cleanup_interval:
                    self.cleanup_old_json_records()
                    self.last_cleanup_time = current_time

                time.sleep(1)

        except KeyboardInterrupt:
            print("\n\nStopping detector...")

            # 退出前清理 JSON 文件
            print("清理 JSON 输出文件...")
            output_file = self.output_dir / 'ecs_logs_with_anomalies.json'
            anomalies_file = self.output_dir / 'anomalies.json'

            try:
                if output_file.exists():
                    output_file.unlink()
                if anomalies_file.exists():
                    anomalies_file.unlink()
                print("✓ JSON 输出文件已清理")
            except Exception as e:
                print(f"✗ 清理失败: {e}")

            print(f"\nFinal stats:")
            print(f"  Total logs processed: {self.total_logs}")
            print(f"  Anomalies detected: {self.anomalies_found}")
            print(f"  Total published records: {self.total_logs}")
            print(f"\n所有数据已发送到消息队列")


def main():
    """Main entry point"""
    print("="*60)
    print("Ubuntu Log Anomaly Detection System")
    print("="*60)
    print()

    # Configuration
    rules_dir = os.path.join(os.path.dirname(__file__), 'rules')
    input_file = '/tmp/filebeat-output/ecs_logs.json'
    output_dir = os.path.join(os.path.dirname(__file__), 'output')

    # Initialize detector
    detector = AnomalyDetector(rules_dir, input_file, output_dir)

    # Load rules
    detector.load_rules()

    if len(detector.rules) == 0:
        print("Error: No detection rules loaded. Exiting.")
        return

    # Start monitoring
    detector.watch_logs()


if __name__ == '__main__':
    main()
