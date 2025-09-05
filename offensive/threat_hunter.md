# defensive/threat_hunter.py
```bash
import json
import re
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any
import pandas as pd
import hashlib
import ipaddress
from collections import Counter

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("DarkPhoenixThreatHunter")

class DarkPhoenixThreatHunter:
    def __init__(self):
        self.ioc_database = {
            'malicious_ips': set(),
            'suspicious_domains': set(),
            'known_hashes': set(),
            'attack_patterns': {
                'brute_force': r'Failed password for|Authentication failure',
                'sql_injection': r'(\'|--|;|union|select|from|where).*(\'|--|;|union|select|from|where)',
                'xss': r'<script|javascript:|onload=|onerror=',
                'path_traversal': r'\.\./|\.\.\\|/etc/passwd|/winnt/system32'
            }
        }
        
        self.threat_intelligence_feeds = [
            "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
            "https://feeds.dshield.org/top10-2.txt"
        ]

    def load_log_file(self, log_file: str, log_type: str = 'auto') -> List[Dict]:
        """Carga y parsea archivos de log"""
        logs = []
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    parsed_line = self._parse_log_line(line.strip(), log_type)
                    if parsed_line:
                        logs.append(parsed_line)
            
            logger.info(f"Loaded {len(logs)} log entries from {log_file}")
            return logs
            
        except Exception as e:
            logger.error(f"Error loading log file: {e}")
            return []

    def _parse_log_line(self, line: str, log_type: str) -> Dict:
        """Parseo automático de diferentes formatos de log"""
        # Detección automática del tipo de log
        if log_type == 'auto':
            if 'sshd' in line and 'Failed password' in line:
                log_type = 'ssh'
            elif 'HTTP' in line and 'GET' in line:
                log_type = 'web'
            elif 'firewall' in line.lower() or 'deny' in line.lower():
                log_type = 'firewall'
            else:
                log_type = 'generic'

        # Parseo según tipo
        if log_type == 'ssh':
            return self._parse_ssh_log(line)
        elif log_type == 'web':
            return self._parse_web_log(line)
        elif log_type == 'firewall':
            return self._parse_firewall_log(line)
        else:
            return self._parse_generic_log(line)

    def _parse_ssh_log(self, line: str) -> Dict:
        """Parseo de logs SSH"""
        pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+).*sshd.*Failed password for (\S+) from (\d+\.\d+\.\d+\.\d+)'
        match = re.search(pattern, line)
        if match:
            return {
                'timestamp': match.group(1),
                'event_type': 'ssh_failed_login',
                'username': match.group(2),
                'source_ip': match.group(3),
                'raw_line': line
            }
        return None

    def _parse_web_log(self, line: str) -> Dict:
        """Parseo de logs web (Apache/NGINX)"""
        pattern = r'(\d+\.\d+\.\d+\.\d+).*\[(.*?)\].*"(GET|POST|PUT|DELETE) (.*?) HTTP'
        match = re.search(pattern, line)
        if match:
            return {
                'source_ip': match.group(1),
                'timestamp': match.group(2),
                'http_method': match.group(3),
                'url': match.group(4),
                'raw_line': line
            }
        return None

    def _parse_firewall_log(self, line: str) -> Dict:
        """Parseo de logs de firewall"""
        # Patrón genérico para firewalls
        ip_pattern = r'\d+\.\d+\.\d+\.\d+'
        ips = re.findall(ip_pattern, line)
        
        if len(ips) >= 2:
            return {
                'source_ip': ips[0],
                'dest_ip': ips[1],
                'action': 'BLOCK' if 'deny' in line.lower() else 'ALLOW',
                'raw_line': line
            }
        return None

    def _parse_generic_log(self, line: str) -> Dict:
        """Parseo genérico para logs no reconocidos"""
        return {'raw_line': line, 'timestamp': str(datetime.now())}

    def detect_iocs(self, logs: List[Dict]) -> Dict:
        """Detección de Indicadores de Compromiso"""
        findings = {
            'malicious_ips': [],
            'suspicious_activity': [],
            'attack_patterns': [],
            'anomalies': []
        }

        for log in logs:
            # Detección de IPs maliciosas
            if 'source_ip' in log and log['source_ip'] in self.ioc_database['malicious_ips']:
                findings['malicious_ips'].append({
                    'ip': log['source_ip'],
                    'log_entry': log,
                    'confidence': 'high'
                })

            # Detección de patrones de ataque
            if 'raw_line' in log:
                raw_line = log['raw_line']
                for pattern_name, pattern in self.ioc_database['attack_patterns'].items():
                    if re.search(pattern, raw_line, re.IGNORECASE):
                        findings['attack_patterns'].append({
                            'pattern': pattern_name,
                            'log_entry': log,
                            'confidence': 'medium'
                        })

        return findings

    def analyze_behavior(self, logs: List[Dict], time_window: int = 5) -> List[Dict]:
        """Análisis de comportamiento anómalo"""
        anomalies = []
        
        # Agrupar logs por IP y timestamp
        df = pd.DataFrame(logs)
        if 'timestamp' in df.columns and 'source_ip' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
            df = df.dropna(subset=['timestamp'])
            
            # Contar eventos por IP en ventana temporal
            df['time_window'] = df['timestamp'].dt.floor(f'{time_window}min')
            ip_activity = df.groupby(['source_ip', 'time_window']).size().reset_index(name='count')
            
            # Detectar IPs con actividad anómala
            threshold = ip_activity['count'].quantile(0.95)  # Percentil 95
            suspicious_ips = ip_activity[ip_activity['count'] > threshold]
            
            for _, row in suspicious_ips.iterrows():
                anomalies.append({
                    'type': 'high_frequency_activity',
                    'ip': row['source_ip'],
                    'event_count': row['count'],
                    'time_window': str(row['time_window']),
                    'confidence': 'high'
                })
        
        return anomalies

    def correlate_events(self, findings: Dict, anomalies: List[Dict]) -> Dict:
        """Correlación de eventos y hallazgos"""
        correlated = {
            'high_confidence_threats': [],
            'medium_confidence_threats': [],
            'low_confidence_alerts': [],
            'summary': {
                'total_findings': len(findings['malicious_ips']) + len(findings['attack_patterns']),
                'total_anomalies': len(anomalies),
                'timeline': []
            }
        }

        # Correlacionar IPs maliciosas con anomalías
        for finding in findings['malicious_ips']:
            threat = {
                'type': 'known_malicious_ip',
                'ip': finding['ip'],
                'confidence': 'high',
                'evidence': [finding]
            }
            correlated['high_confidence_threats'].append(threat)

        # Correlacionar patrones de ataque
        for pattern in findings['attack_patterns']:
            threat = {
                'type': f'attack_pattern_{pattern["pattern"]}',
                'confidence': 'medium',
                'evidence': [pattern]
            }
            correlated['medium_confidence_threats'].append(threat)

        return correlated

    def generate_threat_report(self, correlation_results: Dict) -> str:
        """Genera reporte ejecutivo de amenazas"""
        report = []
        report.append("=" * 70)
        report.append("DarkPhoenix Threat Hunting Report")
        report.append("=" * 70)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        
        # Resumen ejecutivo
        summary = correlation_results['summary']
        report.append("📊 EXECUTIVE SUMMARY")
        report.append("-" * 40)
        report.append(f"High confidence threats: {len(correlation_results['high_confidence_threats'])}")
        report.append(f"Medium confidence threats: {len(correlation_results['medium_confidence_threats'])}")
        report.append(f"Total anomalies detected: {summary['total_anomalies']}")
        report.append("")
        
        # Amenazas de alta confianza
        if correlation_results['high_confidence_threats']:
            report.append("🔴 HIGH CONFIDENCE THREATS")
            report.append("-" * 40)
            for threat in correlation_results['high_confidence_threats']:
                report.append(f"IP: {threat['ip']} - Known malicious")
                report.append(f"  Evidence: {len(threat['evidence'])} events")
                report.append("")
        
        # Amenazas de media confianza
        if correlation_results['medium_confidence_threats']:
            report.append("🟡 MEDIUM CONFIDENCE THREATS")
            report.append("-" * 40)
            for threat in correlation_results['medium_confidence_threats']:
                report.append(f"Pattern: {threat['type']}")
                report.append(f"  Evidence: {len(threat['evidence'])} events")
                report.append("")
        
        # Recomendaciones
        report.append("")
        report.append("🛡️ RECOMMENDATIONS")
        report.append("-" * 40)
        if correlation_results['high_confidence_threats']:
            report.append("1. Immediately block malicious IPs at firewall level")
            report.append("2. Review affected systems for compromise")
            report.append("3. Reset credentials for potentially compromised accounts")
        else:
            report.append("No immediate critical threats detected")
            report.append("Continue monitoring and review medium confidence alerts")
        
        return "\n".join(report)

    def load_ioc_from_file(self, ioc_file: str, ioc_type: str) -> None:
        """Carga IOCs desde archivo"""
        try:
            with open(ioc_file, 'r') as f:
                iocs = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                
                if ioc_type == 'ip':
                    self.ioc_database['malicious_ips'].update(iocs)
                elif ioc_type == 'domain':
                    self.ioc_database['suspicious_domains'].update(iocs)
                elif ioc_type == 'hash':
                    self.ioc_database['known_hashes'].update(iocs)
                    
                logger.info(f"Loaded {len(iocs)} IOCs of type {ioc_type}")
                
        except FileNotFoundError:
            logger.warning(f"IOC file not found: {ioc_file}")

def threat_hunter_demo():
    """Demostración del Threat Hunter"""
    print("🔥 DarkPhoenix Threat Hunter Module")
    print("=" * 50)
    
    hunter = DarkPhoenixThreatHunter()
    
    # Cargar IOCs de ejemplo
    print("📁 Loading threat intelligence...")
    hunter.ioc_database['malicious_ips'].update(['192.168.1.100', '10.0.0.15'])
    
    # Crear logs de ejemplo para demo
    sample_logs = [
        {
            'timestamp': '2024-01-15 10:30:00',
            'source_ip': '192.168.1.100',  # IP maliciosa conocida
            'event_type': 'ssh_failed_login',
            'username': 'root',
            'raw_line': 'Failed password for root from 192.168.1.100 port 22'
        },
        {
            'timestamp': '2024-01-15 10:31:00', 
            'source_ip': '192.168.1.101',
            'event_type': 'web_request',
            'url': '/admin.php?query=SELECT * FROM users',
            'raw_line': 'GET /admin.php?query=SELECT * FROM users HTTP/1.1'
        },
        {
            'timestamp': '2024-01-15 10:32:00',
            'source_ip': '192.168.1.100',  # IP maliciosa de nuevo
            'event_type': 'firewall_block',
            'raw_line': 'Firewall blocked 192.168.1.100 for port scanning'
        }
    ]
    
    print("🔍 Analyzing logs for IOCs...")
    findings = hunter.detect_iocs(sample_logs)
    
    print("📈 Analyzing behavioral anomalies...") 
    anomalies = hunter.analyze_behavior(sample_logs)
    
    print("🔗 Correlating events...")
    correlation = hunter.correlate_events(findings, anomalies)
    
    print("📊 Generating threat report...")
    report = hunter.generate_threat_report(correlation)
    print("\n" + report)
    
    print("✅ Threat hunting demo completed")

if __name__ == "__main__":
    threat_hunter_demo()
   ```
