# offensive/recon.py
```bash
import asyncio
import socket
import ipaddress
from typing import List, Dict, Tuple
import aiohttp
import json
from datetime import datetime

class DarkPhoenixRecon:
    def __init__(self, max_workers: int = 500, timeout: float = 2.0):
        self.max_workers = max_workers
        self.timeout = timeout
        self.open_ports = {}
        
        # Mapeo de servicios comunes
        self.common_services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS",
            995: "POP3S", 3389: "RDP", 5900: "VNC", 27017: "MongoDB"
        }
        
        # Funciones específicas para obtener banners
        self.banner_grabbers = {
            21: self._grab_ftp_banner,
            22: self._grab_ssh_banner,
            25: self._grab_smtp_banner,
            80: self._grab_http_banner,
            443: self._grab_https_banner,
            3306: self._grab_mysql_banner
        }

    async def scan_port(self, target: str, port: int) -> bool:
        """Escaneo asíncrono de un puerto individual"""
        try:
            conn = asyncio.open_connection(target, port)
            reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
            writer.close()
            await writer.wait_closed()
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False
        except Exception as e:
            print(f"Error scanning port {port}: {e}")
            return False

    async def _grab_ftp_banner(self, reader, writer) -> str:
        """Obtener banner de servicio FTP"""
        try:
            banner = await reader.read(1024)
            return banner.decode().strip()
        except:
            return "No banner grabbed"

    async def _grab_ssh_banner(self, reader, writer) -> str:
        """Obtener banner de servicio SSH"""
        try:
            banner = await reader.read(1024)
            return banner.decode().strip()
        except:
            return "No banner grabbed"

    async def _grab_http_banner(self, reader, writer) -> str:
        """Obtener banner de servicio HTTP"""
        try:
            writer.write(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            await writer.drain()
            response = await reader.read(1024)
            return response.decode().split('\r\n')[0]  # Solo la línea de estado
        except:
            return "No HTTP banner"

    async def _grab_banner(self, target: str, port: int) -> str:
        """Intenta obtener el banner del servicio según el puerto"""
        if port not in self.banner_grabbers:
            return "No banner grabber available"
        
        try:
            conn = asyncio.open_connection(target, port)
            reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
            banner = await self.banner_grabbers[port](reader, writer)
            writer.close()
            await writer.wait_closed()
            return banner
        except:
            return "Banner grab failed"

    async def scan_target(self, target: str, ports: List[int] = None) -> Dict:
        """Escanea un objetivo específico con lista de puertos"""
        if ports is None:
            ports = list(self.common_services.keys())
        
        print(f"🔍 Scanning {target} - {len(ports)} ports...")
        
        # Escaneo de puertos
        tasks = [self.scan_port(target, port) for port in ports]
        results = await asyncio.gather(*tasks)
        
        open_ports = [port for port, is_open in zip(ports, results) if is_open]
        
        # Obtención de banners para puertos abiertos
        banner_tasks = [self._grab_banner(target, port) for port in open_ports]
        banners = await asyncio.gather(*banner_tasks)
        
        # Compilar resultados
        results_dict = {}
        for port, banner in zip(open_ports, banners):
            service = self.common_services.get(port, "Unknown")
            results_dict[port] = {
                "service": service,
                "banner": banner,
                "status": "open"
            }
        
        return results_dict

    async def scan_network(self, network_cidr: str, ports: List[int] = None) -> Dict:
        """Escanea una red completa CIDR"""
        network = ipaddress.ip_network(network_cidr)
        results = {}
        
        for ip in network.hosts():
            ip_str = str(ip)
            results[ip_str] = await self.scan_target(ip_str, ports)
            
        return results

    def generate_report(self, target: str, results: Dict, output_format: str = "text") -> str:
        """Genera reporte en diferentes formatos"""
        if output_format == "text":
            return self._generate_text_report(target, results)
        elif output_format == "json":
            return self._generate_json_report(target, results)
        elif output_format == "markdown":
            return self._generate_markdown_report(target, results)
        else:
            return "Invalid format"

    def _generate_text_report(self, target: str, results: Dict) -> str:
        """Genera reporte en texto plano"""
        report = []
        report.append("=" * 60)
        report.append(f"DarkPhoenix Recon Report - {target}")
        report.append(f"Scan date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("=" * 60)
        report.append("")
        
        if not results:
            report.append("No open ports found")
            return "\n".join(report)
        
        for port, info in results.items():
            report.append(f"🚪 PORT {port}/TCP - {info['service']}")
            report.append(f"   📋 Status: {info['status']}")
            report.append(f"   🔍 Banner: {info['banner']}")
            report.append("")
        
        report.append(f"📊 Total open ports: {len(results)}")
        return "\n".join(report)

    def _generate_json_report(self, target: str, results: Dict) -> str:
        """Genera reporte en formato JSON"""
        report = {
            "target": target,
            "scan_date": datetime.now().isoformat(),
            "open_ports": results,
            "stats": {
                "total_ports_scanned": len(results),
                "total_open_ports": len(results)
            }
        }
        return json.dumps(report, indent=2)

    def _generate_markdown_report(self, target: str, results: Dict) -> str:
        """Genera reporte en formato Markdown"""
        report = []
        report.append(f"# DarkPhoenix Recon Report - {target}")
        report.append(f"**Scan date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        report.append("## Open Ports")
        report.append("")
        
        if not results:
            report.append("No open ports found.")
            return "\n".join(report)
        
        report.append("| Port | Service | Status | Banner |")
        report.append("|------|---------|--------|--------|")
        
        for port, info in results.items():
            banner = info['banner'].replace('|', '\\|')  # Escape para markdown
            report.append(f"| {port} | {info['service']} | {info['status']} | `{banner}` |")
        
        report.append("")
        report.append(f"**Total open ports:** {len(results)}")
        return "\n".join(report)

async def main():
    """Función principal de demostración"""
    print("🔥 DarkPhoenix Network Reconnaissance Tool")
    print("=" * 50)
    
    # Inicializar scanner
    scanner = DarkPhoenixRecon(max_workers=1000)
    
    # Ejemplo de escaneo
    target = "scanme.nmap.org"  # Target de prueba permitido
    ports_to_scan = [21, 22, 80, 443, 3389, 8080]
    
    print(f"🎯 Target: {target}")
    print(f"📋 Ports: {ports_to_scan}")
    print("⏳ Scanning...")
    
    try:
        # Realizar escaneo
        results = await scanner.scan_target(target, ports_to_scan)
        
        # Generar reporte
        report = scanner.generate_report(target, results, "text")
        print("\n" + report)
        
        # Guardar reporte en archivo
        with open("scan_report.txt", "w") as f:
            f.write(report)
            
        print("💾 Report saved to 'scan_report.txt'")
        
    except Exception as e:
        print(f"❌ Error during scan: {e}")

if __name__ == "__main__":
    asyncio.run(main())
```
