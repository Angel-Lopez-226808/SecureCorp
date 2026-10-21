"""Autenticación de usuarios.

- Las contraseñas se guardan como hash scrypt con sal aleatoria de 16 bytes.
- La comparación usa hmac.compare_digest (tiempo constante).
- Tras MAX_INTENTOS_LOGIN fallos seguidos, la cuenta se bloquea BLOQUEO_SEGUNDOS.
"""
import hashlib
import hmac
import json
import os
import re
import threading
import time
from pathlib import Path

from comun import config
from comun.roles import ROLES

_SCRYPT = dict(n=2 ** 14, r=8, p=1, dklen=32)
_NOMBRE_VALIDO = re.compile(r"^[a-z][a-z0-9_]{2,19}$")
_lock_archivo = threading.Lock()


def hash_password(password: str, sal: bytes = None) -> tuple:
    sal = sal or os.urandom(16)
    h = hashlib.scrypt(password.encode("utf-8"), salt=sal, **_SCRYPT)
    return sal.hex(), h.hex()


def _leer(archivo: Path) -> dict:
    if not archivo.exists():
        return {"usuarios": {}}
    with open(archivo, encoding="utf-8") as f:
        return json.load(f)


def _escribir(archivo: Path, datos: dict) -> None:
    archivo.parent.mkdir(parents=True, exist_ok=True)
    tmp = archivo.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(datos, f, indent=2, ensure_ascii=False)
    os.replace(tmp, archivo)   # reemplazo atómico


def crear_usuario(nombre: str, rol: str, password: str, archivo: Path = None) -> None:
    archivo = Path(archivo or config.USUARIOS_JSON)
    if not _NOMBRE_VALIDO.match(nombre):
        raise ValueError("nombre inválido (3-20 caracteres: minúsculas, números o _)")
    if rol not in ROLES:
        raise ValueError(f"rol inválido; usa uno de: {', '.join(ROLES)}")
    if len(password) < 8:
        raise ValueError("la contraseña debe tener al menos 8 caracteres")
    with _lock_archivo:
        datos = _leer(archivo)
        if nombre in datos["usuarios"]:
            raise ValueError(f"el usuario {nombre} ya existe")
        sal, h = hash_password(password)
        datos["usuarios"][nombre] = {"rol": rol, "sal": sal, "hash": h}
        _escribir(archivo, datos)


def listar_usuarios(archivo: Path = None) -> list:
    datos = _leer(Path(archivo or config.USUARIOS_JSON))
    return [{"usuario": u, "rol": d["rol"]} for u, d in sorted(datos["usuarios"].items())]


class Autenticador:
    """Verifica credenciales y lleva el conteo de intentos fallidos."""

    def __init__(self, archivo: Path = None):
        self.archivo = Path(archivo or config.USUARIOS_JSON)
        self._fallos = {}          # usuario -> (conteo, bloqueado_hasta)
        self._lock = threading.Lock()

    def verificar(self, usuario: str, password: str):
        """Devuelve (ok, rol, motivo)."""
        usuario = (usuario or "").strip().lower()
        with self._lock:
            conteo, hasta = self._fallos.get(usuario, (0, 0.0))
            if hasta > time.time():
                restante = int(hasta - time.time()) + 1
                return False, None, f"cuenta bloqueada {restante} s por intentos fallidos"

        registro = _leer(self.archivo)["usuarios"].get(usuario)
        if registro:
            _, calculado = hash_password(password or "", bytes.fromhex(registro["sal"]))
            correcto = hmac.compare_digest(calculado, registro["hash"])
        else:
            hash_password(password or "")   # mismo costo aunque no exista el usuario
            correcto = False

        with self._lock:
            if correcto:
                self._fallos.pop(usuario, None)
                return True, registro["rol"], "ok"
            conteo, _ = self._fallos.get(usuario, (0, 0.0))
            conteo += 1
            if conteo >= config.MAX_INTENTOS_LOGIN:
                self._fallos[usuario] = (0, time.time() + config.BLOQUEO_SEGUNDOS)
                return False, None, (f"credenciales incorrectas; cuenta bloqueada "
                                     f"{config.BLOQUEO_SEGUNDOS} s")
            self._fallos[usuario] = (conteo, 0.0)
            return False, None, "usuario o contraseña incorrectos"
