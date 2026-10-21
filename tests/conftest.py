"""Entorno de pruebas aislado.

Antes de importar cualquier módulo del proyecto se apuntan todas las rutas a
una carpeta temporal, se genera ahí una PKI nueva con los scripts de OpenSSL
y se inicializan los datos. Tus certificados, usuarios y logs reales no se tocan.
"""
import os
import socket
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
BASE = Path(tempfile.mkdtemp(prefix="securecorp_pruebas_"))
os.environ.update({
    "SECURECORP_DATOS": str(BASE / "datos"),
    "SECURECORP_LOGS": str(BASE / "logs"),
    "SECURECORP_CERTS": str(BASE / "certs"),
    "SECURECORP_CONFIG": str(BASE / "config"),
})
sys.path.insert(0, str(RAIZ))

subprocess.run(["bash", str(RAIZ / "pki/generar_pki.sh"), str(BASE / "certs")],
               check=True, capture_output=True)
subprocess.run(["bash", str(RAIZ / "pki/generar_certs_prueba.sh"), str(BASE / "certs")],
               check=True, capture_output=True)
subprocess.run([sys.executable, str(RAIZ / "herramientas/inicializar.py")],
               check=True, capture_output=True)

import pytest  # noqa: E402

from cliente.cliente import Cliente  # noqa: E402
from comun import config  # noqa: E402
from servidor.servidor_app import ServidorApp  # noqa: E402
from vpn.gateway import GatewayVPN  # noqa: E402

PASSWORDS = {"admin": "Admin#2026", "ana": "Ana#2026!", "invitado": "Invitado#2026"}


@pytest.fixture(scope="session")
def servidor_tls():
    srv = ServidorApp("tls", host="127.0.0.1", puerto=0).iniciar()
    yield srv
    srv.detener()


@pytest.fixture(scope="session")
def servidor_plano():
    srv = ServidorApp("plano", host="127.0.0.1", puerto=0).iniciar()
    yield srv
    srv.detener()


@pytest.fixture(scope="session")
def gateway(servidor_tls):
    gw = GatewayVPN("127.0.0.1", 0, "127.0.0.1", servidor_tls.puerto).iniciar()
    yield gw
    gw.detener()


@pytest.fixture
def conectar():
    """conectar(puerto, modo, usuario=None) -> Cliente ya conectado (y con sesión)."""
    abiertos = []

    def _conectar(puerto, modo="tls", usuario=None, password=None):
        c = Cliente("127.0.0.1", puerto, modo)
        c.conectar()
        abiertos.append(c)
        if usuario:
            r = c.login(usuario, password or PASSWORDS[usuario])
            assert r["ok"], r
        return c

    yield _conectar
    for c in abiertos:
        c.cerrar()


def leer_log(archivo=None) -> str:
    ruta = Path(archivo or config.LOG_EVENTOS)
    return ruta.read_text(encoding="utf-8") if ruta.exists() else ""


class Grabador:
    """Proxy TCP que guarda todo lo que pasa por él: nuestro 'Wireshark'."""

    def __init__(self, destino_puerto: int):
        self.capturado = bytearray()
        self._srv = socket.create_server(("127.0.0.1", 0))
        self.puerto = self._srv.getsockname()[1]
        self._destino = destino_puerto
        threading.Thread(target=self._aceptar, daemon=True).start()

    def _aceptar(self):
        cli, _ = self._srv.accept()
        srv = socket.create_connection(("127.0.0.1", self._destino))
        threading.Thread(target=self._copiar, args=(cli, srv, True), daemon=True).start()
        threading.Thread(target=self._copiar, args=(srv, cli, False), daemon=True).start()

    def _copiar(self, a, b, grabar):
        try:
            while True:
                datos = a.recv(65536)
                if not datos:
                    break
                if grabar:
                    self.capturado.extend(datos)
                b.sendall(datos)
        except OSError:
            pass
        finally:
            for s in (a, b):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
