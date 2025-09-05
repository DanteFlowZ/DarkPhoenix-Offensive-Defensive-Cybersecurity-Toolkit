# defensive/threat_feed.py
```bash
import aiohttp
import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Set
import ipaddress
import csv
from collections import defaultdict
import time

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("DarkPhoenixThreatFeed")

class DarkPhoenixThreatFeed:
    def __init__(self):
        self.threat_intelligence = {
            'malicious_ips': set(),
            'suspicious_domains': set(),
            'malicious_hashes': set(),
            'c2_servers': set(),
            'last_update': None
        }
        
        # Fuentes públicas de threat intelligence
        self.public_feeds = {
            'abuseipdb': "https://api.abuseipdb.com/api/v2/blacklist",
            'emerging_threats': "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
            'dshield': "https://feeds.dshield.org/top10-2.txt",
            'alienvault': "https://reputation.alienvault.com/reputation.data",
            'malware_domains': "https://mirror1.malwaredomains.com/files/justdomains"
        }
        
        self.api_keys = {}
        self.update_interval = 3600  # 1 hora en segundos

    async def fetch_threat_feed(self, feed_url: str, feed_type: str) -> List[str]:
        """Fetch threat intelligence from a specific feed"""
        iocs = []
        try:
            async with aiohttp.ClientSession() as session:
                headers = {
                    'User-Agent': 'DarkPhoenix-Threat-Intelligence/1.0'
                }
                
                if 'abuseipdb' in feed_url and 'abuseipdb' in self.api_keys:
                    headers['Key'] = self.api_keys['abuseipdb']
                    headers['Accept'] = 'application/json'
                
                async with session.get(feed_url, headers=headers, timeout=30) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        if feed_type == 'abuseipdb':
                            iocs = self._parse_abuseipdb(content)
                        elif feed_type == 'emerging_threats':
                            iocs = self._parse_emerging_threats(content)
                        elif feed_type == 'dshield':
                            iocs = self._parse_dshield(content)
                        elif feed_type == 'alienvault':
                            iocs = self._parse_alienvault(content)
                        elif feed_type == 'malware_domains':
                            iocs = self._parse_malware_domains(content)
                        
                        logger.info(f"Fetched {len(iocs)} IOCs from {feed_type}")
                    else:
                        logger.warning(f"Failed to fetch {feed_url}: {response.status}")
        
        except Exception as e:
            logger.error(f"Error fetching {feed_url}: {e}")
        
        return iocs

    def _parse_abuseipdb(self, content: str) -> List[str]:
        """Parse AbuseIPDB JSON response"""
        iocs = []
        try:
            data = json.loads(content)
            for entry in data.get('data', []):
                iocs.append(entry['ipAddress'])
        except json.JSONDecodeError:
            logger.error("Failed to parse AbuseIPDB JSON")
        return iocs

    def _parse_emerging_threats(self, content: str) -> List[str]:
        """Parse Emerging Threats feed"""
        iocs = []
        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                iocs.append(line)
        return iocs

    def _parse_dshield(self, content: str) -> List[str]:
        """Parse DShield feed"""
        iocs = []
        for line in content.split('\n'):
            if line and not line.startswith('#'):
                parts = line.split()
                if len(parts) >= 2:
                    iocs.append(parts[0])
        return iocs

    def _parse_alienvault(self, content: str) -> List[str]:
        """Parse AlienVault reputation data"""
        iocs = []
        for line in content.split('\n'):
            if line and not line.startswith('#'):
                parts = line.split('#')
                if parts and parts[0].strip():
                    iocs.append(parts[0].strip())
        return iocs

    def _parse_malware_domains(self, content: str) -> List[str]:
        """Parse Malware Domains list"""
        return [line.strip() for line in content.split('\n') if line.strip() and not line.startswith('#')]

    async def update_all_feeds(self) -> Dict:
        """Update all threat intelligence feeds"""
        logger.info("Starting threat intelligence feed update...")
        
        results = {
            'total_iocs': 0,
            'feed_results': {},
            'update_time': datetime.now().isoformat()
        }
        
        tasks = []
        for feed_name, feed_url in self.public_feeds.items():
            tasks.append(self.fetch_threat_feed(feed_url, feed_name))
        
        # Ejecutar todas las tareas concurrentemente
        feed_results = await asyncio.gather(*tasks)
        
        # Procesar resultados
        for feed_name, iocs in zip(self.public_feeds.keys(), feed_results):
            results['feed_results'][feed_name] = len(iocs)
            results['total_iocs'] += len(iocs)
            
            # Agregar IOCs a la base de datos
            if feed_name in ['abuseipdb', 'emerging_threats', 'dshield', 'alienvault']:
                self.threat_intelligence['malicious_ips'].update(iocs)
            elif feed_name == 'malware_domains':
                self.threat_intelligence['suspicious_domains'].update(iocs)
        
        self.threat_intelligence['last_update'] = datetime.now()
        logger.info(f"Threat intelligence updated. Total IOCs: {results['total_iocs']}")
        
        return results

    def check_ip_reputation(self, ip_address: str) -> Dict:
        """Check IP reputation against threat intelligence"""
        reputation = {
            'ip': ip_address,
            'is_malicious': False,
            'sources': [],
            'confidence': 0,
            'last_seen': None
        }
        
        if ip_address in self.threat_intelligence['malicious_ips']:
            reputation['is_malicious'] = True
            reputation['sources'].append('threat_feed')
            reputation['confidence'] = 85
            reputation['last_seen'] = self.threat_intelligence['last_update']
        
        return reputation

    def check_domain_reputation(self, domain: str) -> Dict:
        """Check domain reputation against threat intelligence"""
        reputation = {
            'domain': domain,
            'is_malicious': False,
            'sources': [],
            'confidence': 0,
            'last_seen': None
        }
        
        if domain in self.threat_intelligence['suspicious_domains']:
            reputation['is_malicious'] = True
            reputation['sources'].append('malware_domains')
            reputation['confidence'] = 80
            reputation['last_seen'] = self.threat_intelligence['last_update']
        
        return reputation

    def search_iocs(self, search_term: str, ioc_type: str = None) -> List[Dict]:
        """Search for IOCs in the threat intelligence database"""
        results = []
        
        if not ioc_type or ioc_type == 'ip':
            if search_term in self.threat_intelligence['malicious_ips']:
                results.append({
                    'type': 'ip',
                    'value': search_term,
                    'reputation': 'malicious',
                    'source': 'threat_feed'
                })
        
        if not ioc_type or ioc_type == 'domain':
            if search_term in self.threat_intelligence['suspicious_domains']:
                results.append({
                    'type': 'domain',
                    'value': search_term,
                    'reputation': 'suspicious',
                    'source': 'malware_domains'
                })
        
        return results

    def export_iocs(self, output_format: str = 'json') -> bool:
        """Export threat intelligence to file"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            
            if output_format == 'json':
                filename = f'threat_intelligence_{timestamp}.json'
                with open(filename, 'w') as f:
                    json.dump({
                        'malicious_ips': list(self.threat_intelligence['malicious_ips']),
                        'suspicious_domains': list(self.threat_intelligence['suspicious_domains']),
                        'last_update': self.threat_intelligence['last_update'].isoformat() if self.threat_intelligence['last_update'] else None,
                        'total_iocs': len(self.threat_intelligence['malicious_ips']) + len(self.threat_intelligence['suspicious_domains'])
                    }, f, indent=2)
            
            elif output_format == 'csv':
                filename = f'threat_intelligence_{timestamp}.csv'
                with open(filename, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Type', 'Value', 'Source'])
                    
                    for ip in self.threat_intelligence['malicious_ips']:
                        writer.writerow(['IP', ip, 'threat_feed'])
                    
                    for domain in self.threat_intelligence['suspicious_domains']:
                        writer.writerow(['Domain', domain, 'malware_domains'])
            
            else:
                logger.error(f"Unsupported output format: {output_format}")
                return False
            
            logger.info(f"Threat intelligence exported to {filename}")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting IOCs: {e}")
            return False

    def get_stats(self) -> Dict:
        """Get statistics about the threat intelligence database"""
        return {
            'total_malicious_ips': len(self.threat_intelligence['malicious_ips']),
            'total_suspicious_domains': len(self.threat_intelligence['suspicious_domains']),
            'total_malicious_hashes': len(self.threat_intelligence['malicious_hashes']),
            'total_c2_servers': len(self.threat_intelligence['c2_servers']),
            'last_update': self.threat_intelligence['last_update'].isoformat() if self.threat_intelligence['last_update'] else 'Never',
            'update_interval_seconds': self.update_interval
        }

    def load_iocs_from_file(self, filename: str, ioc_type: str) -> bool:
        """Load IOCs from a local file"""
        try:
            with open(filename, 'r') as f:
                if filename.endswith('.json'):
                    data = json.load(f)
                    if ioc_type == 'ip':
                        self.threat_intelligence['malicious_ips'].update(data.get('ips', []))
                    elif ioc_type == 'domain':
                        self.threat_intelligence['suspicious_domains'].update(data.get('domains', []))
                else:
                    iocs = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    if ioc_type == 'ip':
                        self.threat_intelligence['malicious_ips'].update(iocs)
                    elif ioc_type == 'domain':
                        self.threat_intelligence['suspicious_domains'].update(iocs)
            
            logger.info(f"Loaded {len(iocs)} IOCs from {filename}")
            return True
            
        except Exception as e:
            logger.error(f"Error loading IOCs from file: {e}")
            return False

async def threat_feed_demo():
    """Demonstration of the threat feed functionality"""
    print("🔥 DarkPhoenix Threat Intelligence Feed")
    print("=" * 50)
    print("⚠️  Note: This is a demo with simulated threat intelligence")
    print("    Actual feeds would require API keys and internet access\n")
    
    threat_feed = DarkPhoenixThreatFeed()
    
    # Simular carga de IOCs (en realidad se necesitaría conexión a internet)
    print("📡 Simulating threat intelligence feed update...")
    
    # Agregar algunos IOCs de ejemplo
    threat_feed.threat_intelligence['malicious_ips'].update([
        '192.168.1.100',
        '10.0.0.15',
        '185.220.101.134',
        '45.133.1.12'
    ])
    
    threat_feed.threat_intelligence['suspicious_domains'].update([
        'malicious-domain.com',
        'phishing-site.org',
        'c2-server.net'
    ])
    
    threat_feed.threat_intelligence['last_update'] = datetime.now()
    
    # Mostrar estadísticas
    print("📊 Threat Intelligence Statistics:")
    stats = threat_feed.get_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    # Ejemplo de consulta de reputación
    print("\n🔍 Reputation Check Examples:")
    test_ips = ['192.168.1.100', '8.8.8.8', '10.0.0.15']
    for ip in test_ips:
        reputation = threat_feed.check_ip_reputation(ip)
        status = "🔴 MALICIOUS" if reputation['is_malicious'] else "🟢 CLEAN"
        print(f"  {ip}: {status}")
    
    # Ejemplo de búsqueda
    print("\n🔎 IOC Search Examples:")
    search_results = threat_feed.search_iocs('malicious-domain.com')
    for result in search_results:
        print(f"  Found: {result['value']} ({result['type']}) - {result['reputation'].upper()}")
    
    # Exportar IOCs
    print("\n💾 Exporting threat intelligence...")
    threat_feed.export_iocs('json')
    
    print("\n✅ Threat feed demo completed")
    print("💾 Check 'threat_intelligence_*.json' for exported data")

if __name__ == "__main__":
    asyncio.run(threat_feed_demo())
```
