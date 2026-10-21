"""Protocolo de mensajes: una línea JSON por mensaje, terminada en '\\n'.

Es el mismo formato en modo plano, TLS y VPN; lo único que cambia es el
socket que hay debajo. Por eso en Wireshark la diferencia es solo el cifrado.

  Petición:  {"id": 7, "cmd": "csv_listar"}
  Respuesta: {"re": 7, "ok": true, ...}
  Evento:    {"evento": "chat", "de": "ana", "texto": "hola"}

Nota técnica: un objeto SSL de OpenSSL no debe leerse y escribirse al mismo
tiempo desde dos hilos. Por eso el Canal usa el socket en modo no bloqueante
y protege cada lectura/escritura con un mismo candado; la espera ocurre
fuera del candado con select().
"""
import json
import select
import ssl
import threading

from comun import config

_ESPERA = (ssl.SSLWantReadError, ssl.SSLWantWriteError, BlockingIOError, InterruptedError)


class ConexionCerrada(ConnectionError):
    pass


class Canal:
    """Envuelve un socket (plano o TLS) y envía/recibe mensajes JSON."""

    def __init__(self, sock):
        self.sock = sock
        self.sock.setblocking(False)
        self._lock = threading.Lock()
        self._buf = b""
        self._cerrado = False

    def _esperar(self, leer: bool, escribir: bool) -> None:
        if self._cerrado:
            raise ConexionCerrada("canal cerrado")
        try:
            select.select([self.sock] if leer else [], [self.sock] if escribir else [], [], 1.0)
        except (ValueError, OSError):
            raise ConexionCerrada("canal cerrado")

    def enviar(self, mensaje: dict) -> None:
        datos = memoryview((json.dumps(mensaje, ensure_ascii=False) + "\n").encode("utf-8"))
        while datos:
            with self._lock:
                if self._cerrado:
                    raise ConexionCerrada("canal cerrado")
                try:
                    n = self.sock.send(datos[:65536])
                    datos = datos[n:]
                    continue
                except ssl.SSLWantReadError:
                    leer, escribir = True, False
                except _ESPERA:
                    leer, escribir = False, True
            self._esperar(leer, escribir)

    def recibir(self) -> dict:
        while b"\n" not in self._buf:
            if len(self._buf) > config.MAX_LINEA_BYTES:
                raise ValueError("mensaje demasiado grande")
            with self._lock:
                if self._cerrado:
                    raise ConexionCerrada("canal cerrado")
                try:
                    trozo = self.sock.recv(65536)
                    if not trozo:
                        raise ConexionCerrada("el otro extremo cerró la conexión")
                    self._buf += trozo
                    continue
                except ssl.SSLWantWriteError:
                    leer, escribir = False, True
                except _ESPERA:
                    leer, escribir = True, False
                except (ssl.SSLError, OSError) as e:
                    raise ConexionCerrada(str(e))
            self._esperar(leer, escribir)
        linea, self._buf = self._buf.split(b"\n", 1)
        return json.loads(linea.decode("utf-8"))

    def cerrar(self) -> None:
        with self._lock:
            if self._cerrado:
                return
            self._cerrado = True
            try:
                self.sock.close()
            except OSError:
                pass


def respuesta(peticion: dict, ok: bool = True, **datos) -> dict:
    r = {"re": peticion.get("id"), "ok": ok}
    r.update(datos)
    return r


def error(peticion: dict, mensaje: str) -> dict:
    return respuesta(peticion, ok=False, error=mensaje)
