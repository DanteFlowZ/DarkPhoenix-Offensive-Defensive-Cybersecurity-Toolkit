# defensive/siem_mini.py
```bash
import json
import logging
from datetime import datetime
import pandas as pd
import matplotlib.pyplot as plt
from typing import Dict, List
import seaborn as sns
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("DarkPhoenixSIEM")

class DarkPhoenixSIEM:
    def __init__(self):
        self.events = []
        self.dashboards = {}
        self.alerts = []
        self.alert_rules = {
            'brute_force': {
                'threshold': 5,
                'time_window': 300,  # 5 minutos
                'message': 'Multiple failed login attempts detected'
            },
            'port_scan': {
                'threshold': 10,
                'time_window': 60,
                'message': 'Port scanning activity detected'
            }
        }

    def ingest_event(self, event: Dict) -> None:
        """Ingesta de eventos en el SIEM"""
        event['ingestion_time'] = datetime.now().isoformat()
        event['event_id'] = f"event_{len(self.events) + 1:06d}"
        self.events.append(event)
        
        # Verificar reglas de alerta
        self._check_alert_rules(event)

    def _check_alert_rules(self, event: Dict) -> None:
        """Verifica reglas de alerta para el evento"""
        # Implementar lógica de detección de alertas
        pass

    def generate_dashboard(self, dashboard_type: str = 'security_overview') -> Dict:
        """Genera dashboard de seguridad"""
        df = pd.DataFrame(self.events)
        
        if df.empty:
            return {'error': 'No events available for dashboard'}
        
        dashboard = {
            'total_events': len(self.events),
            'timeline': self._generate_timeline_data(df),
            'top_source_ips': self._get_top_values(df, 'source_ip'),
            'top_event_types': self._get_top_values(df, 'event_type'),
            'alert_summary': {
                'total_alerts': len(self.alerts),
                'high_severity': len([a for a in self.alerts if a.get('severity') == 'high'])
            }
        }
        
        return dashboard

    def _generate_timeline_data(self, df: pd.DataFrame) -> List[Dict]:
        """Genera datos para timeline"""
        timeline_data = []
        
        if 'timestamp' in df.columns:
            df['hour'] = pd.to_datetime(df['timestamp']).dt.floor('H')
            hourly_counts = df['hour'].value_counts().sort_index()
            
            for hour, count in hourly_counts.items():
                timeline_data.append({
                    'time': hour.strftime('%Y-%m-%d %H:00'),
                    'events': count
                })
        
        return timeline_data

    def _get_top_values(self, df: pd.DataFrame, column: str, top_n: int = 10) -> List[Dict]:
        """Obtiene los valores más comunes de una columna"""
        if column not in df.columns:
            return []
        
        value_counts = df[column].value_counts().head(top_n)
        return [{'value': val, 'count': count} for val, count in value_counts.items()]

    def visualize_dashboard(self, dashboard_data: Dict) -> None:
        """Visualiza el dashboard con matplotlib"""
        plt.style.use('dark_background')
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        fig.suptitle('DarkPhoenix SIEM Dashboard', fontsize=16, fontweight='bold')
        
        # Timeline
        if dashboard_data['timeline']:
            times = [item['time'] for item in dashboard_data['timeline']]
            events = [item['events'] for item in dashboard_data['timeline']]
            axes[0, 0].plot(times, events, marker='o', color='cyan')
            axes[0, 0].set_title('Event Timeline')
            axes[0, 0].tick_params(axis='x', rotation=45)
        
        # Top IPs
        if dashboard_data['top_source_ips']:
            ips = [item['value'] for item in dashboard_data['top_source_ips']]
            counts = [item['count'] for item in dashboard_data['top_source_ips']]
            axes[0, 1].barh(ips, counts, color='red')
            axes[0, 1].set_title('Top Source IPs')
        
        # Event types
        if dashboard_data['top_event_types']:
            types = [item['value'] for item in dashboard_data['top_event_types']]
            counts = [item['count'] for item in dashboard_data['top_event_types']]
            axes[1, 0].pie(counts, labels=types, autopct='%1.1f%%')
            axes[1, 0].set_title('Event Types Distribution')
        
        # Alert summary
        alert_data = dashboard_data['alert_summary']
        axes[1, 1].bar(['Total Alerts', 'High Severity'], 
                      [alert_data['total_alerts'], alert_data['high_severity']],
                      color=['yellow', 'red'])
        axes[1, 1].set_title('Alert Summary')
        
        plt.tight_layout()
        plt.savefig('siem_dashboard.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info("Dashboard visualization saved as 'siem_dashboard.png'")

def siem_demo():
    """Demostración del mini-SIEM"""
    print("🔥 DarkPhoenix SIEM Mini Dashboard")
    print("=" * 50)
    
    siem = DarkPhoenixSIEM()
    
    # Ingestionar eventos de ejemplo
    sample_events = [
        {'timestamp': '2024-01-15 10:00:00', 'source_ip': '192.168.1.100', 'event_type': 'login_failed'},
        {'timestamp': '2024-01-15 10:01:00', 'source_ip': '192.168.1.101', 'event_type': 'login_success'},
        {'timestamp': '2024-01-15 10:02:00', 'source_ip': '192.168.1.100', 'event_type': 'login_failed'},
        {'timestamp': '2024-01-15 10:03:00', 'source_ip': '192.168.1.102', 'event_type': 'port_scan'},
        {'timestamp': '2024-01-15 10:04:00', 'source_ip': '192.168.1.100', 'event_type': 'login_failed'},
        {'timestamp': '2024-01-15 11:00:00', 'source_ip': '192.168.1.105', 'event_type': 'file_access'},
    ]
    
    print("📥 Ingesting sample events...")
    for event in sample_events:
        siem.ingest_event(event)
    
    print("📊 Generating dashboard...")
    dashboard = siem.generate_dashboard()
    
    print("🎨 Creating visualization...")
    siem.visualize_dashboard(dashboard)
    
    print("📈 Dashboard Summary:")
    print(f"Total events: {dashboard['total_events']}")
    print(f"Top IP: {dashboard['top_source_ips'][0]['value'] if dashboard['top_source_ips'] else 'N/A'}")
    print(f"Top event type: {dashboard['top_event_types'][0]['value'] if dashboard['top_event_types'] else 'N/A'}")
    
    print("✅ SIEM demo completed. Check 'siem_dashboard.png'")

if __name__ == "__main__":
    siem_demo()
    ```
