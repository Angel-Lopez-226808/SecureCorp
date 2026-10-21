"""Configuración central de SecureCorp.

Todas las rutas se pueden cambiar con variables de entorno (las pruebas lo
usan para trabajar en una carpeta temporal sin tocar tus datos reales).
"""
import os
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent

# --- Rutas -----------------------------------------------------------------
DATOS = Path(os.environ.get("SECURECORP_DATOS", RAIZ / "datos"))
LOGS = Path(os.environ.get("SECURECORP_LOGS", RAIZ / "logs"))
CERTS = Path(os.environ.get("SECURECORP_CERTS", RAIZ / "pki" / "certs"))
CONFIG = Path(os.environ.get("SECURECORP_CONFIG", RAIZ / "config"))

USUARIOS_JSON = DATOS / "usuarios.json"
CSV_PUBLICOS = DATOS / "csv" / "publicos"
CSV_PRIVADOS = DATOS / "csv" / "privados"
CSV_SUCURSAL = CSV_PRIVADOS / "sucursal"
DATOS_SUCURSAL = DATOS / "sucursal"          # lo que "vive" en la red sucursal
LOG_EVENTOS = LOGS / "eventos.log"
LOG_CLIENTE = LOGS / "cliente.log"
PSK_SITIO = CONFIG / "psk_sitio.key"        # llave precompartida entre gateways

CA_CRT = CERTS / "ca.crt"
SERVIDOR_KEY = CERTS / "servidor.key"
FULLCHAIN = CERTS / "fullchain.pem"           # servidor.crt + inter.crt

# --- Red -------------------------------------------------------------------
SERVIDOR_NOMBRE = "servidor.securecorp.local"  # nombre que va en el certificado
PUERTO_PLANO = 5000
PUERTO_TLS = 5443
PUERTO_VPN = 6443
PUERTO_IPSEC = 7500                           # UDP (demo IPSec y sitio a sitio)

# Redes simuladas
RED_MATRIZ = "10.1.0.0/24"
RED_SUCURSAL = "10.2.0.0/24"
IP_GW_MATRIZ = "10.1.0.1"
IP_GW_SUCURSAL = "10.2.0.1"
IP_SERVIDOR_APP = "10.1.0.20"
IP_EQUIPO_SUCURSAL = "10.2.0.10"
POOL_VPN = ("10.8.0.", 10, 50)                # 10.8.0.10 – 10.8.0.50

# --- Políticas ---------------------------------------------------------------
MAX_INTENTOS_LOGIN = 5
BLOQUEO_SEGUNDOS = 60
SESION_VPN_MINUTOS = 30
MAX_CSV_BYTES = 1024 * 1024                   # 1 MB
MAX_LINEA_BYTES = 4 * 1024 * 1024             # tope de un mensaje JSON
VENTANA_REPLAY = 64
