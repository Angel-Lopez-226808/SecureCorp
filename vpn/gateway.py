"""Gateway de VPN de acceso remoto (simulado).

Representa el punto de entrada de un usuario externo a la red de la matriz:
  1. El cliente abre TLS al gateway y valida su certificado.
  2. El gateway AUTENTICA al usuario (usuario + contraseña).
  3. Le asigna una IP virtual del rango 10.8.0.10 - 10.8.0.50 y un token de
     sesión que vence en 30 minutos.
  4. En CADA petición revisa el token y la ACL del rol (AUTORIZACIÓN) antes de
     reenviarla al servidor interno. Conectarse NO da acceso a todo.
  5. El tramo gateway -> servidor también va por TLS y también valida el
     certificado del servidor.

Uso (desde la carpeta securecorp/, en la VM, con servidor_app.py --tls corriendo):
    python3 vpn/gateway.py
"""
import argparse
import secrets
import socket
import ssl
import sys
import threading
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from comun import auth, config, logger, roles, tls  # noqa: E402
from comun.protocolo import Canal, ConexionCerrada, error, respuesta  # noqa: E402

COMPONENTE = "gateway"


class PoolIP:
    def __init__(self, prefijo: str, inicio: int, fin: int):
        self._libres = [f"{prefijo}{i}" for i in range(inicio, fin + 1)]
        self._lock = threading.Lock()

    def asignar(self) -> str:
        with self._lock:
            if not self._libres:
                raise RuntimeError("no hay IPs virtuales libres")
            return self._libres.pop(0)

    def liberar(self, ip: str) -> None:
        with self._lock:
            if ip and ip not in self._libres:
                self._libres.append(ip)


class GatewayVPN:
    def __init__(self, host: str = "0.0.0.0", puerto: int = config.PUERTO_VPN,
                 servidor_host: str = "127.0.0.1", servidor_puerto: int = config.PUERTO_TLS,
                 servidor_nombre: str = config.SERVIDOR_NOMBRE,
                 duracion_min: float = config.SESION_VPN_MINUTOS):
        self.host, self.puerto = host, puerto
        self.destino = (servidor_host, servidor_puerto)
        self.servidor_nombre = servidor_nombre
        self.duracion = timedelta(minutes=duracion_min)
        self.ctx_servidor = tls.contexto_servidor()       # hacia el cliente
        self.ctx_interno = tls.contexto_cliente()         # hacia el servidor app
        self.autenticador = auth.Autenticador()
        self.pool = PoolIP(*config.POOL_VPN)
        self.activas = {}                                  # ip_virtual -> usuario
        self._sock = None

    def iniciar(self) -> "GatewayVPN":
        self._sock = socket.create_server((self.host, self.puerto))
        self.puerto = self._sock.getsockname()[1]
        threading.Thread(target=self._aceptar, daemon=True).start()
        return self

    def detener(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass

    def _aceptar(self) -> None:
        while True:
            try:
                conn, addr = self._sock.accept()
            except OSError:
                break
            threading.Thread(target=self._atender, args=(conn, addr[0]), daemon=True).start()

    # ---------------------------------------------------------------- sesión
    def _atender(self, conn: socket.socket, ip_real: str) -> None:
        try:
            conn.settimeout(10)
            conn = self.ctx_servidor.wrap_socket(conn, server_side=True)
            conn.settimeout(None)
        except (ssl.SSLError, OSError) as e:
            logger.registrar("TLS_ERROR", COMPONENTE, f"handshake fallido: {e}", ip=ip_real)
            conn.close()
            return
        cliente = Canal(conn)
        logger.registrar("CONEXION", COMPONENTE, "solicitud de conexión VPN", ip=ip_real)
        interno, sesion = None, None
        try:
            interno, sesion = self._autenticar(cliente, ip_real)
            if not sesion:
                return
            # Lo que el servidor manda (respuestas y chat) va directo al cliente.
            hilo = threading.Thread(target=self._reenviar, args=(interno, cliente), daemon=True)
            hilo.start()
            self._filtrar(cliente, interno, sesion)
            hilo.join(timeout=3)   # deja salir la última respuesta (p. ej. a 'salir')
        except (ConexionCerrada, ConnectionError, OSError, ValueError):
            pass
        finally:
            if sesion:
                self.pool.liberar(sesion["ip"])
                self.activas.pop(sesion["ip"], None)
                logger.registrar("VPN_DESCONECTADO", COMPONENTE,
                                 f"IP virtual {sesion['ip']} liberada",
                                 usuario=sesion["usuario"], ip=ip_real)
            for c in (cliente, interno):
                if c:
                    c.cerrar()

    def _autenticar(self, cliente: Canal, ip_real: str):
        """AUTENTICACIÓN: hasta 3 intentos. Devuelve (canal_interno, sesion)."""
        for _ in range(3):
            msg = cliente.recibir()
            if msg.get("cmd") == "salir":
                cliente.enviar(respuesta(msg, mensaje="hasta luego"))
                return None, None
            if msg.get("cmd") != "login":
                cliente.enviar(error(msg, "VPN: primero autentícate (login)"))
                continue
            usuario = str(msg.get("usuario", "")).strip().lower()
            ok, rol, motivo = self.autenticador.verificar(usuario, str(msg.get("password", "")))
            if not ok:
                tipo = "BLOQUEADO" if "bloqueada" in motivo else "LOGIN_FALLIDO"
                logger.registrar(tipo, COMPONENTE, f"VPN: {motivo}", usuario=usuario or "-",
                                 ip=ip_real)
                cliente.enviar(error(msg, motivo))
                continue

            ip_virtual = self.pool.asignar()
            # Tramo interno gateway -> servidor, también con TLS validado.
            raw = socket.create_connection(self.destino, timeout=10)
            interno = Canal(self.ctx_interno.wrap_socket(raw, server_hostname=self.servidor_nombre))
            interno.enviar({"id": msg.get("id"), "cmd": "login", "usuario": usuario,
                            "password": msg.get("password"), "_vpn_ip": ip_virtual})
            r = interno.recibir()
            if not r.get("ok"):
                self.pool.liberar(ip_virtual)
                interno.cerrar()
                cliente.enviar(error(msg, f"el servidor rechazó la sesión: {r.get('error')}"))
                continue

            expira = datetime.now() + self.duracion
            sesion = {"usuario": usuario, "rol": rol, "ip": ip_virtual,
                      "token": secrets.token_hex(16), "expira": expira, "ip_real": ip_real}
            self.activas[ip_virtual] = usuario
            logger.registrar("VPN_CONECTADO", COMPONENTE,
                             f"rol {rol}, IP virtual {ip_virtual}, recursos "
                             f"{','.join(roles.permisos_de(rol))}", usuario=usuario, ip=ip_real)
            cliente.enviar(respuesta(msg, usuario=usuario, rol=rol, ip_virtual=ip_virtual,
                                     token=sesion["token"], recursos=roles.permisos_de(rol),
                                     expira=expira.strftime("%H:%M:%S")))
            return interno, sesion
        cliente.enviar({"evento": "aviso", "mensaje": "demasiados intentos; conexión cerrada"})
        return None, None

    def _filtrar(self, cliente: Canal, interno: Canal, s: dict) -> None:
        """AUTORIZACIÓN en cada petición, antes de dejarla pasar a la red interna."""
        while True:
            msg = cliente.recibir()
            cmd = msg.get("cmd")
            if datetime.now() > s["expira"]:
                logger.registrar("VPN_EXPIRADA", COMPONENTE, "sesión vencida",
                                 usuario=s["usuario"], ip=s["ip"])
                cliente.enviar(error(msg, "la sesión VPN expiró; vuelve a conectarte"))
                return
            if not secrets.compare_digest(str(msg.pop("token", "")), s["token"]):
                logger.registrar("DENEGADO", COMPONENTE, "token de sesión inválido",
                                 usuario=s["usuario"], ip=s["ip"])
                cliente.enviar(error(msg, "token de sesión inválido"))
                continue
            if cmd == "login":
                cliente.enviar(error(msg, "ya hay una sesión VPN activa"))
                continue
            if not roles.comando_valido(cmd):
                cliente.enviar(error(msg, f"comando desconocido: {cmd}"))
                continue
            permiso = roles.PERMISO_POR_COMANDO[cmd]
            if not roles.autorizar(s["rol"], permiso):
                logger.registrar("DENEGADO", COMPONENTE,
                                 f"rol {s['rol']} sin permiso {permiso} (cmd {cmd}); "
                                 f"no llega a la red interna", usuario=s["usuario"], ip=s["ip"])
                cliente.enviar(error(msg, f"ACCESO DENEGADO: rol {s['rol']} sin permiso {permiso}"))
                continue
            interno.enviar(msg)
            if cmd == "salir":
                return

    @staticmethod
    def _reenviar(origen: Canal, destino: Canal) -> None:
        try:
            while True:
                destino.enviar(origen.recibir())
        except (ConexionCerrada, OSError, ValueError):
            destino.cerrar()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--puerto", type=int, default=config.PUERTO_VPN)
    ap.add_argument("--servidor", default="127.0.0.1", help="IP del servidor app (red interna)")
    ap.add_argument("--servidor-puerto", type=int, default=config.PUERTO_TLS)
    a = ap.parse_args()
    gw = GatewayVPN(a.host, a.puerto, a.servidor, a.servidor_puerto).iniciar()
    print(f"Gateway VPN escuchando en {a.host}:{gw.puerto} (TLS). "
          f"Reenvía a {a.servidor}:{a.servidor_puerto}. Pool {config.POOL_VPN[0]}"
          f"{config.POOL_VPN[1]}-{config.POOL_VPN[2]}. Ctrl+C para detener.")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        gw.detener()


if __name__ == "__main__":
    main()
