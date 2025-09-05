# defensive/pcap_analyzer.py
```bash
from scapy.all import *
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
import logging
from typing import Dict, List, Tuple
import json
import ipaddress
from collections import Counter
import socket

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("DarkPhoenixPCAP")

class DarkPhoenixPCAPAnalyzer:
    def __init__(self):
        self.packets = []
        self.analysis_results = {}
        self.suspicious_patterns = {
            'port_scan': r'(port.*scan|scan.*port)',
            'sql_injection': r'(\'|--|;|union|select|from|where)',
            'xss': r'(<script|javascript:|onload=|onerror=)',
            'ddos': r'(flood|syn.*flood|ddos)'
        }
        
        # Protocolos comunes y sus puertos
        self.common_ports = {
            80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 21: 'FTP', 25: 'SMTP',
            53: 'DNS', 110: 'POP3', 143: 'IMAP', 993: 'IMAPS', 995: 'POP3S',
            3389: 'RDP', 5900: 'VNC', 27017: 'MongoDB', 3306: 'MySQL'
        }

    def load_pcap(self, pcap_file: str) -> bool:
        """Carga un archivo PCAP para análisis"""
        try:
            logger.info(f"Loading PCAP file: {pcap_file}")
            self.packets = rdpcap(pcap_file)
            logger.info(f"Successfully loaded {len(self.packets)} packets")
            return True
        except Exception as e:
            logger.error(f"Error loading PCAP file: {e}")
            return False

    def basic_analysis(self) -> Dict:
        """Análisis básico del tráfico de red"""
        if not self.packets:
            return {"error": "No packets loaded"}
        
        # Estadísticas básicas
        start_time = datetime.fromtimestamp(self.packets[0].time)
        end_time = datetime.fromtimestamp(self.packets[-1].time)
        duration = end_time - start_time
        
        # Contar protocolos
        protocol_counts = Counter()
        source_ips = Counter()
        dest_ips = Counter()
        ports = Counter()
        
        for pkt in self.packets:
            if IP in pkt:
                source_ips[pkt[IP].src] += 1
                dest_ips[pkt[IP].dst] += 1
                
                # Identificar protocolo
                if TCP in pkt:
                    protocol_counts['TCP'] += 1
                    if pkt[TCP].dport in self.common_ports:
                        ports[pkt[TCP].dport] += 1
                elif UDP in pkt:
                    protocol_counts['UDP'] += 1
                    if pkt[UDP].dport in self.common_ports:
                        ports[pkt[UDP].dport] += 1
                elif ICMP in pkt:
                    protocol_counts['ICMP'] += 1
        
        self.analysis_results = {
            'general_stats': {
                'total_packets': len(self.packets),
                'time_range': {
                    'start': start_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'end': end_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'duration_seconds': duration.total_seconds()
                },
                'protocol_distribution': dict(protocol_counts),
                'packet_rate': len(self.packets) / duration.total_seconds() if duration.total_seconds() > 0 else 0
            },
            'top_talkers': {
                'source_ips': dict(source_ips.most_common(10)),
                'destination_ips': dict(dest_ips.most_common(10)),
                'common_ports': dict(ports.most_common(10))
            }
        }
        
        return self.analysis_results

    def detect_anomalies(self) -> List[Dict]:
        """Detección de anomalías en el tráfico"""
        anomalies = []
        
        if not self.packets:
            return anomalies
        
        # Detectar escaneo de puertos
        port_scan_anomalies = self._detect_port_scans()
        anomalies.extend(port_scan_anomalies)
        
        # Detectar tráfico inusual
        unusual_traffic = self._detect_unusual_traffic()
        anomalies.extend(unusual_traffic)
        
        # Detectar posibles ataques DDoS
        ddos_anomalies = self._detect_ddos()
        anomalies.extend(ddos_anomalies)
        
        # Buscar patrones sospechosos en payloads
        suspicious_payloads = self._analyze_payloads()
        anomalies.extend(suspicious_payloads)
        
        return anomalies

    def _detect_port_scans(self) -> List[Dict]:
        """Detección de escaneos de puertos"""
        scans = []
        
        if not self.packets:
            return scans
        
        # Agrupar por IP origen y puertos destino
        scan_candidates = {}
        
        for pkt in self.packets:
            if IP in pkt and TCP in pkt:
                src_ip = pkt[IP].src
                dst_port = pkt[TCP].dport
                
                if src_ip not in scan_candidates:
                    scan_candidates[src_ip] = set()
                
                scan_candidates[src_ip].add(dst_port)
        
        # Identificar IPs que escanean muchos puertos
        for ip, ports in scan_candidates.items():
            if len(ports) > 20:  # Umbral para considerar escaneo
                scans.append({
                    'type': 'port_scan',
                    'source_ip': ip,
                    'ports_scanned': len(ports),
                    'confidence': 'high',
                    'description': f'Possible port scan from {ip} to {len(ports)} different ports'
                })
        
        return scans

    def _detect_unusual_traffic(self) -> List[Dict]:
        """Detección de tráfico inusual"""
        unusual = []
        
        if not self.packets:
            return unusual
        
        # Buscar tráfico en puertos no comunes
        for pkt in self.packets:
            if IP in pkt and TCP in pkt:
                dst_port = pkt[TCP].dport
                if dst_port > 1024 and dst_port not in self.common_ports and dst_port not in range(49152, 65535):
                    unusual.append({
                        'type': 'unusual_port',
                        'source_ip': pkt[IP].src,
                        'dest_ip': pkt[IP].dst,
                        'port': dst_port,
                        'confidence': 'medium',
                        'description': f'Traffic on unusual port {dst_port} from {pkt[IP].src} to {pkt[IP].dst}'
                    })
        
        return unusual

    def _detect_ddos(self) -> List[Dict]:
        """Detección de posibles ataques DDoS"""
        ddos_alerts = []
        
        if not self.packets:
            return ddos_alerts
        
        # Agrupar paquetes por tiempo
        time_window = 1  # 1 segundo
        packet_counts = {}
        
        for pkt in self.packets:
            if IP in pkt:
                time_bucket = int(pkt.time) // time_window
                if time_bucket not in packet_counts:
                    packet_counts[time_bucket] = 0
                packet_counts[time_bucket] += 1
        
        # Buscar picos de tráfico
        if packet_counts:
            avg_packets = sum(packet_counts.values()) / len(packet_counts)
            max_packets = max(packet_counts.values())
            
            if max_packets > avg_packets * 5:  # 5 veces el promedio
                ddos_alerts.append({
                    'type': 'possible_ddos',
                    'max_packets_per_second': max_packets,
                    'average_packets': avg_packets,
                    'confidence': 'medium',
                    'description': f'Possible DDoS detected: peak of {max_packets} packets/second (avg: {avg_packets:.1f})'
                })
        
        return ddos_alerts

    def _analyze_payloads(self) -> List[Dict]:
        """Análisis de payloads en busca de patrones sospechosos"""
        suspicious = []
        
        if not self.packets:
            return suspicious
        
        for pkt in self.packets:
            if IP in pkt and TCP in pkt and pkt.haslayer(Raw):
                payload = str(pkt[Raw].load)
                
                for pattern_name, pattern in self.suspicious_patterns.items():
                    if re.search(pattern, payload, re.IGNORECASE):
                        suspicious.append({
                            'type': f'suspicious_payload_{pattern_name}',
                            'source_ip': pkt[IP].src,
                            'dest_ip': pkt[IP].dst,
                            'pattern': pattern_name,
                            'confidence': 'low',
                            'description': f'Suspicious {pattern_name} pattern in payload from {pkt[IP].src}'
                        })
        
        return suspicious

    def export_to_json(self, output_file: str) -> bool:
        """Exporta resultados a JSON"""
        try:
            results = {
                'basic_analysis': self.analysis_results,
                'anomalies': self.detect_anomalies(),
                'analysis_date': datetime.now().isoformat()
            }
            
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            logger.info(f"Results exported to {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting to JSON: {e}")
            return False

    def generate_report(self) -> str:
        """Genera reporte ejecutivo del análisis"""
        if not self.analysis_results:
            self.basic_analysis()
        
        anomalies = self.detect_anomalies()
        
        report = []
        report.append("=" * 70)
        report.append("DarkPhoenix PCAP Analysis Report")
        report.append("=" * 70)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        
        # Estadísticas generales
        stats = self.analysis_results['general_stats']
        report.append("📊 GENERAL STATISTICS")
        report.append("-" * 40)
        report.append(f"Total packets: {stats['total_packets']}")
        report.append(f"Time range: {stats['time_range']['start']} to {stats['time_range']['end']}")
        report.append(f"Duration: {stats['time_range']['duration_seconds']:.1f} seconds")
        report.append(f"Packet rate: {stats['packet_rate']:.1f} packets/second")
        report.append("")
        
        # Distribución de protocolos
        report.append("🔌 PROTOCOL DISTRIBUTION")
        report.append("-" * 40)
        for protocol, count in stats['protocol_distribution'].items():
            report.append(f"{protocol}: {count} packets")
        report.append("")
        
        # Top talkers
        talkers = self.analysis_results['top_talkers']
        report.append("🌐 TOP TALKERS")
        report.append("-" * 40)
        report.append("Source IPs:")
        for ip, count in list(talkers['source_ips'].items())[:5]:
            report.append(f"  {ip}: {count} packets")
        
        report.append("Destination IPs:")
        for ip, count in list(talkers['destination_ips'].items())[:5]:
            report.append(f"  {ip}: {count} packets")
        report.append("")
        
        # Anomalías detectadas
        report.append("🚨 SECURITY ANOMALIES")
        report.append("-" * 40)
        if anomalies:
            for anomaly in anomalies[:10]:  # Mostrar solo las 10 principales
                report.append(f"{anomaly['type'].upper()}: {anomaly['description']}")
                report.append(f"  Confidence: {anomaly['confidence']}")
                report.append("")
        else:
            report.append("No significant anomalies detected")
        report.append("")
        
        # Recomendaciones
        report.append("🛡️ RECOMMENDATIONS")
        report.append("-" * 40)
        if any(a['confidence'] == 'high' for a in anomalies):
            report.append("1. Investigate high-confidence anomalies immediately")
            report.append("2. Consider blocking malicious IPs at firewall")
            report.append("3. Review affected systems for compromise")
        else:
            report.append("No immediate critical actions required")
            report.append("Continue monitoring network traffic")
        
        return "\n".join(report)

    def visualize_traffic(self, output_file: str = 'traffic_analysis.png') -> bool:
        """Crea visualizaciones del tráfico de red"""
        try:
            if not self.analysis_results:
                self.basic_analysis()
            
            plt.style.use('dark_background')
            fig, axes = plt.subplots(2, 2, figsize=(15, 12))
            fig.suptitle('DarkPhoenix Traffic Analysis', fontsize=16, fontweight='bold')
            
            # Gráfico 1: Distribución de protocolos
            protocols = self.analysis_results['general_stats']['protocol_distribution']
            axes[0, 0].pie(protocols.values(), labels=protocols.keys(), autopct='%1.1f%%')
            axes[0, 0].set_title('Protocol Distribution')
            
            # Gráfico 2: Top source IPs
            source_ips = self.analysis_results['top_talkers']['source_ips']
            if source_ips:
                axes[0, 1].barh(list(source_ips.keys())[:5], list(source_ips.values())[:5], color='red')
                axes[0, 1].set_title('Top 5 Source IPs')
            
            # Gráfico 3: Top destination ports
            ports = self.analysis_results['top_talkers']['common_ports']
            if ports:
                port_names = [f"{port} ({self.common_ports.get(port, 'Unknown')})" for port in ports.keys()]
                axes[1, 0].barh(port_names[:5], list(ports.values())[:5], color='cyan')
                axes[1, 0].set_title('Top 5 Destination Ports')
            
            # Gráfico 4: Anomalías por tipo
            anomalies = self.detect_anomalies()
            if anomalies:
                anomaly_types = Counter([a['type'] for a in anomalies])
                axes[1, 1].bar(anomaly_types.keys(), anomaly_types.values(), color='yellow')
                axes[1, 1].set_title('Anomaly Types')
                axes[1, 1].tick_params(axis='x', rotation=45)
            else:
                axes[1, 1].text(0.5, 0.5, 'No anomalies detected', ha='center', va='center')
                axes[1, 1].set_title('Anomaly Types')
            
            plt.tight_layout()
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
            plt.close()
            
            logger.info(f"Traffic visualization saved as {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Error creating visualization: {e}")
            return False

def pcap_analyzer_demo():
    """Demostración del analizador PCAP"""
    print("🔥 DarkPhoenix PCAP Analyzer")
    print("=" * 50)
    print("⚠️  Note: This is a demo with simulated analysis")
    print("    Actual PCAP analysis would require real packet capture files\n")
    
    analyzer = DarkPhoenixPCAPAnalyzer()
    
    # Simular análisis (en realidad necesitarías un archivo PCAP)
    print("📊 Generating simulated analysis...")
    
    # Crear resultados de ejemplo
    analyzer.analysis_results = {
        'general_stats': {
            'total_packets': 1250,
            'time_range': {
                'start': '2024-01-15 10:00:00',
                'end': '2024-01-15 10:05:00',
                'duration_seconds': 300
            },
            'protocol_distribution': {'TCP': 800, 'UDP': 400, 'ICMP': 50},
            'packet_rate': 4.17
        },
        'top_talkers': {
            'source_ips': {'192.168.1.100': 300, '192.168.1.101': 250, '10.0.0.1': 200},
            'destination_ips': {'8.8.8.8': 400, '1.1.1.1': 300, '192.168.1.1': 150},
            'common_ports': {80: 300, 443: 250, 53: 200, 22: 100}
        }
    }
    
    # Generar reporte
    print("📝 Generating report...")
    report = analyzer.generate_report()
    print(report)
    
    # Crear visualización
    print("🎨 Creating visualization...")
    analyzer.visualize_traffic('pcap_analysis_demo.png')
    
    print("✅ PCAP analyzer demo completed")
    print("💾 Check 'pcap_analysis_demo.png' for visualization")

if __name__ == "__main__":
    pcap_analyzer_demo()
   ```
