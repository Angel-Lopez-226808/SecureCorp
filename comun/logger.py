"""Registro de eventos de seguridad.

Formato de cada línea (una por evento):
    fecha | TIPO | usuario | ip | detalle

El detalle empieza con el componente entre corchetes, por ejemplo
"[gateway] rol invitado sin permiso chat".
"""
import threading
from datetime import datetime
from pathlib import Path

from comun import config

TIPOS = {
    "CONEXION", "DESCONEXION", "LOGIN_OK", "LOGIN_FALLIDO", "BLOQUEADO",
    "PERMITIDO", "DENEGADO", "ADMIN", "CERT_RECHAZADO", "TLS_ERROR",
    "VPN_CONECTADO", "VPN_DESCONECTADO", "VPN_EXPIRADA",
    "IPSEC_OK", "REPLAY", "INTEGRIDAD", "IKE_OK", "IKE_FALLIDO",
    "SITIO_A_SITIO", "SSH_ACEPTADO", "SSH_RECHAZADO",
}

_lock = threading.Lock()


def registrar(tipo: str, componente: str, detalle: str = "",
              usuario: str = "-", ip: str = "-", archivo: Path = None) -> str:
    if tipo not in TIPOS:
        raise ValueError(f"tipo de evento desconocido: {tipo}")
    archivo = Path(archivo or config.LOG_EVENTOS)
    fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    detalle = detalle.replace("\n", " ").replace("|", "/")
    linea = f"{fecha} | {tipo} | {usuario or '-'} | {ip or '-'} | [{componente}] {detalle}"
    with _lock:
        archivo.parent.mkdir(parents=True, exist_ok=True)
        with open(archivo, "a", encoding="utf-8") as f:
            f.write(linea + "\n")
    return linea


def leer(n: int = 20, tipo: str = None, archivo: Path = None) -> list:
    """Devuelve las últimas n líneas, opcionalmente solo de un tipo."""
    archivo = Path(archivo or config.LOG_EVENTOS)
    if not archivo.exists():
        return []
    with open(archivo, encoding="utf-8") as f:
        lineas = [l.rstrip("\n") for l in f if l.strip()]
    if tipo:
        tipo = tipo.upper()
        lineas = [l for l in lineas if _campo_tipo(l) == tipo]
    return lineas[-n:] if n > 0 else lineas


def _campo_tipo(linea: str) -> str:
    partes = linea.split(" | ")
    return partes[1] if len(partes) > 1 else ""
