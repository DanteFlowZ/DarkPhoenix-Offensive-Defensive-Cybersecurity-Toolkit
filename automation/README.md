# 🚀 DarkPhoenix Cybersecurity Toolkit

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Contributions](https://img.shields.io/badge/Contributions-Welcome-brightgreen.svg)](CONTRIBUTING.md)

> **Framework modular de ciberseguridad ofensiva y defensiva para profesionales**

DarkPhoenix es un toolkit avanzado que combina técnicas de Red Team y Blue Team en un único framework diseñado para entornos controlados y educativos.

## ⚡ Características Principales

### 🔴 Offensive (Red Team)
- **Escaneo de puertos asíncrono** con detección de servicios
- **Fuerza bruta distribuida** con rotación de proxies
- **Simulador de phishing** con tracking avanzado
- **Generador de payloads** ofuscados (solo educativo)

### 🔵 Defensive (Blue Team)
- **Threat Hunter** para análisis de logs y correlación de IoCs
- **Mini-SIEM** con dashboard visual
- **Analizador de tráfico PCAP** con detección de anomalías
- **Threat Intelligence** con feeds en tiempo real

## 🛠️ Instalación

```bash
git clone https://github.com/tuusuario/DarkPhoenix.git
cd DarkPhoenix
pip install -r requirements.txt
```
---
## 🚀 Uso Rápido

```python
from offensive.recon import DarkPhoenixRecon

async def main():
    scanner = DarkPhoenixRecon()
    results = await scanner.scan_ports("192.168.1.1", [22, 80, 443])
    print(scanner.generate_report("192.168.1.1", results))

asyncio.run(main())
```
⭐ ¿Te gusta el proyecto? Dale una estrella en GitHub para apoyar el desarrollo!
