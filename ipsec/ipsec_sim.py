"""Simulación de IPSec ESP (no es un IPSec de producción).

Lo que SÍ es real: el cifrado y la autenticación (AES-256-GCM de la librería
`cryptography`) y el algoritmo de ventana anti-replay del RFC 4303.
Lo simulado: los encabezados IP son diccionarios JSON y los paquetes viajan
dentro de UDP normal; no se toca el kernel ni las tablas de ruteo.

Estructura de un paquete ESP simulado:
    {
      "ip":  {"origen": ..., "destino": ..., "protocolo": "ESP"},   <- visible
      "esp": {"spi": 4097, "seq": 17},                              <- visible
      "cifrado": "<base64 de AES-GCM(contenido) + etiqueta de 16 bytes>"
    }

Modo transporte: el IP original queda visible; solo se cifran los datos.
Modo túnel:      se cifra el paquete completo (IP original + datos) y se le
                 pone un IP nuevo entre los dos gateways.
"""
import base64
import json
import threading

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from comun import config

TRANSPORTE = "transporte"
TUNEL = "tunel"


class ErrorIPSec(Exception):
    pass


class ReplayError(ErrorIPSec):
    """Número de secuencia repetido o demasiado viejo."""


class IntegridadError(ErrorIPSec):
    """La etiqueta GCM no coincide: el paquete fue modificado o la llave es otra."""


class VentanaAntiReplay:
    """Ventana deslizante del RFC 4303 (sección 3.4.3).

    - `maximo` es el número de secuencia más alto aceptado.
    - `mapa` es un entero usado como mapa de bits: el bit i indica si ya se
      recibió el número (maximo - i).
    Se rechaza un número ya visto o uno que quedó atrás de la ventana.
    """

    def __init__(self, tamano: int = config.VENTANA_REPLAY):
        self.tamano = tamano
        self.maximo = 0
        self.mapa = 0
        self._mascara = (1 << tamano) - 1

    def verificar(self, seq: int) -> None:
        if seq <= 0:
            raise ReplayError("número de secuencia inválido (0)")
        if seq > self.maximo:
            return
        atraso = self.maximo - seq
        if atraso >= self.tamano:
            raise ReplayError(f"seq {seq} fuera de la ventana (máximo visto {self.maximo})")
        if (self.mapa >> atraso) & 1:
            raise ReplayError(f"seq {seq} ya fue recibido: paquete repetido")

    def actualizar(self, seq: int) -> None:
        # Solo se llama DESPUÉS de verificar la integridad (como pide el RFC),
        # para que un atacante no pueda mover la ventana con paquetes falsos.
        if seq > self.maximo:
            corrimiento = seq - self.maximo
            self.mapa = ((self.mapa << corrimiento) | 1) & self._mascara
            self.maximo = seq
        else:
            self.mapa |= 1 << (self.maximo - seq)


class AsociacionSeguridad:
    """Una SA de IPSec: un sentido de tráfico, con su SPI, llave y modo."""

    def __init__(self, spi: int, clave: bytes, sal: bytes, modo: str = TUNEL,
                 ip_tunel_origen: str = None, ip_tunel_destino: str = None):
        if len(clave) != 32 or len(sal) != 4:
            raise ValueError("se requiere llave de 32 bytes (AES-256) y sal de 4 bytes")
        if modo not in (TRANSPORTE, TUNEL):
            raise ValueError("modo debe ser 'transporte' o 'tunel'")
        if modo == TUNEL and not (ip_tunel_origen and ip_tunel_destino):
            raise ValueError("el modo túnel necesita las IP de los dos gateways")
        self.spi, self.modo, self.sal = spi, modo, sal
        self.ip_tunel = (ip_tunel_origen, ip_tunel_destino)
        self._aes = AESGCM(clave)
        self._seq = 0
        self._lock = threading.Lock()
        self.ventana = VentanaAntiReplay()

    def _siguiente_seq(self) -> int:
        with self._lock:
            self._seq += 1
            return self._seq

    def _nonce(self, seq: int) -> bytes:
        # sal (4) + seq (8): como la secuencia nunca se repite, el nonce tampoco.
        return self.sal + seq.to_bytes(8, "big")

    def _aad(self, seq: int) -> bytes:
        # El encabezado ESP (SPI + seq) va autenticado aunque no cifrado.
        return self.spi.to_bytes(4, "big") + seq.to_bytes(8, "big")

    # ------------------------------------------------------------------ envío
    def encapsular(self, ip: dict, datos: bytes) -> dict:
        seq = self._siguiente_seq()
        if self.modo == TRANSPORTE:
            ip_externo = dict(ip, protocolo="ESP")
            interno = {"siguiente": ip.get("protocolo", "TCP"),
                       "datos": base64.b64encode(datos).decode()}
        else:
            ip_externo = {"origen": self.ip_tunel[0], "destino": self.ip_tunel[1],
                          "protocolo": "ESP"}
            interno = {"ip_original": ip, "datos": base64.b64encode(datos).decode()}
        texto = json.dumps(interno).encode()
        cifrado = self._aes.encrypt(self._nonce(seq), texto, self._aad(seq))
        return {"ip": ip_externo, "esp": {"spi": self.spi, "seq": seq},
                "cifrado": base64.b64encode(cifrado).decode()}

    # --------------------------------------------------------------- recepción
    def desencapsular(self, paquete: dict) -> tuple:
        """Devuelve (ip_original, datos). Lanza ReplayError o IntegridadError."""
        spi, seq = paquete["esp"]["spi"], paquete["esp"]["seq"]
        if spi != self.spi:
            raise ErrorIPSec(f"SPI desconocido: {spi}")
        with self._lock:
            self.ventana.verificar(seq)                          # 1) ¿repetido?
            try:                                                 # 2) ¿íntegro?
                texto = self._aes.decrypt(self._nonce(seq),
                                          base64.b64decode(paquete["cifrado"]),
                                          self._aad(seq))
            except InvalidTag:
                raise IntegridadError(f"seq {seq}: etiqueta inválida, paquete alterado")
            self.ventana.actualizar(seq)                         # 3) aceptar
        interno = json.loads(texto)
        datos = base64.b64decode(interno["datos"])
        if self.modo == TRANSPORTE:
            ip = dict(paquete["ip"], protocolo=interno["siguiente"])
        else:
            ip = interno["ip_original"]
        return ip, datos


# ----------------------------------------------------------------- utilidades
def a_bytes(paquete: dict) -> bytes:
    return json.dumps(paquete).encode()


def desde_bytes(datos: bytes) -> dict:
    return json.loads(datos.decode())


def describir(paquete: dict) -> str:
    """Cómo se ve el paquete para alguien que lo captura en la red."""
    ip, esp = paquete["ip"], paquete["esp"]
    muestra = paquete["cifrado"][:24]
    return (f"IP {ip['origen']} -> {ip['destino']} [{ip['protocolo']}] | "
            f"ESP spi={esp['spi']} seq={esp['seq']} | cifrado: {muestra}...")
