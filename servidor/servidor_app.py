"""Servidor de SecureCorp: chat, archivos CSV y funciones de administración.

Uso (desde la carpeta securecorp/, en la VM servidor):
    python3 servidor/servidor_app.py --plano            # puerto 5000, SIN cifrar
    python3 servidor/servidor_app.py --tls              # puerto 5443, con TLS
    python3 servidor/servidor_app.py --tls --cert pki/certs/pruebas/expirado/fullchain.pem \\
                                     --key pki/certs/pruebas/expirado/key.pem
        (para demostrar que el cliente rechaza un certificado malo)
"""
import argparse
import base64
import csv
import io
import os
import socket
import ssl
import sys
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from comun import auth, config, logger, roles, tls  # noqa: E402
from comun.protocolo import Canal, ConexionCerrada, error, respuesta  # noqa: E402

COMPONENTE = "servidor"


@dataclass(eq=False)
class Sesion:
    canal: Canal
    ip: str
    usuario: str = None
    rol: str = None
    ip_vpn: str = None
    conectado: str = field(default_factory=lambda: datetime.now().strftime("%H:%M:%S"))

    @property
    def origen(self) -> str:
        return f"{self.ip_vpn} (vpn)" if self.ip_vpn else self.ip


class ServidorApp:
    def __init__(self, modo: str = "tls", host: str = "0.0.0.0", puerto: int = None,
                 cert: Path = None, key: Path = None):
        assert modo in ("plano", "tls")
        self.modo = modo
        self.host = host
        self.puerto = puerto if puerto is not None else (
            config.PUERTO_TLS if modo == "tls" else config.PUERTO_PLANO)
        self.ctx = tls.contexto_servidor(cert, key) if modo == "tls" else None
        self.autenticador = auth.Autenticador()
        self.sesiones = set()
        self._lock = threading.Lock()
        self._sock = None
        self._activo = False

    # ------------------------------------------------------------------ red
    def iniciar(self) -> "ServidorApp":
        self._sock = socket.create_server((self.host, self.puerto), reuse_port=False)
        self.puerto = self._sock.getsockname()[1]
        self._activo = True
        threading.Thread(target=self._aceptar, daemon=True).start()
        return self

    def detener(self) -> None:
        self._activo = False
        try:
            self._sock.close()
        except OSError:
            pass
        with self._lock:
            for s in list(self.sesiones):
                s.canal.cerrar()

    def _aceptar(self) -> None:
        while self._activo:
            try:
                conn, addr = self._sock.accept()
            except OSError:
                break
            threading.Thread(target=self._atender, args=(conn, addr[0]), daemon=True).start()

    def _atender(self, conn: socket.socket, ip: str) -> None:
        if self.ctx:
            try:
                conn.settimeout(10)
                conn = self.ctx.wrap_socket(conn, server_side=True)
                conn.settimeout(None)
            except (ssl.SSLError, OSError) as e:
                # Típico: el cliente rechazó nuestro certificado y cortó el handshake.
                logger.registrar("TLS_ERROR", COMPONENTE, f"handshake fallido: {e}", ip=ip)
                conn.close()
                return
        sesion = Sesion(Canal(conn), ip)
        with self._lock:
            self.sesiones.add(sesion)
        logger.registrar("CONEXION", COMPONENTE, f"nueva conexión {self.modo.upper()}", ip=ip)
        try:
            while True:
                msg = sesion.canal.recibir()
                if not self._procesar(sesion, msg):
                    break
        except (ConexionCerrada, ConnectionError, OSError, ValueError):
            pass
        finally:
            with self._lock:
                self.sesiones.discard(sesion)
            sesion.canal.cerrar()
            logger.registrar("DESCONEXION", COMPONENTE, "conexión cerrada",
                             usuario=sesion.usuario, ip=sesion.origen)

    # ------------------------------------------------------------ comandos
    def _procesar(self, s: Sesion, msg: dict) -> bool:
        """Atiende un mensaje. Devuelve False si hay que cerrar la conexión."""
        cmd = msg.get("cmd")
        if cmd == "login":
            s.canal.enviar(self._login(s, msg))
            return True
        if cmd == "salir":
            s.canal.enviar(respuesta(msg, mensaje="hasta luego"))
            return False
        if not s.usuario:
            s.canal.enviar(error(msg, "primero inicia sesión (login)"))
            return True
        if not roles.comando_valido(cmd):
            s.canal.enviar(error(msg, f"comando desconocido: {cmd}"))
            return True

        # --- AUTORIZACIÓN: se revisa en CADA comando -------------------------
        permiso = roles.PERMISO_POR_COMANDO[cmd]
        if not roles.autorizar(s.rol, permiso):
            s.canal.enviar(self._denegar(s, msg, permiso))
            return True

        manejador = getattr(self, f"_cmd_{cmd}")
        try:
            s.canal.enviar(manejador(s, msg))
        except (ValueError, OSError) as e:
            s.canal.enviar(error(msg, str(e)))
        return True

    def _denegar(self, s: Sesion, msg: dict, permiso: str) -> dict:
        logger.registrar("DENEGADO", COMPONENTE, f"rol {s.rol} sin permiso {permiso} "
                         f"(cmd {msg.get('cmd')})", usuario=s.usuario, ip=s.origen)
        return error(msg, f"ACCESO DENEGADO: rol {s.rol} sin permiso {permiso}")

    def _login(self, s: Sesion, msg: dict) -> dict:
        if s.usuario:
            return error(msg, "ya hay una sesión iniciada en esta conexión")
        usuario = str(msg.get("usuario", "")).strip().lower()
        ok, rol, motivo = self.autenticador.verificar(usuario, str(msg.get("password", "")))
        s.ip_vpn = msg.get("_vpn_ip")      # lo agrega el gateway VPN, si aplica
        if not ok:
            tipo = "BLOQUEADO" if "bloqueada" in motivo else "LOGIN_FALLIDO"
            logger.registrar(tipo, COMPONENTE, motivo, usuario=usuario or "-", ip=s.origen)
            return error(msg, motivo)
        s.usuario, s.rol = usuario, rol
        logger.registrar("LOGIN_OK", COMPONENTE, f"rol {rol}", usuario=usuario, ip=s.origen)
        return respuesta(msg, usuario=usuario, rol=rol, permisos=roles.permisos_de(rol))

    def _cmd_quien(self, s, msg):
        return respuesta(msg, usuario=s.usuario, rol=s.rol, ip=s.ip, ip_vpn=s.ip_vpn,
                         permisos=roles.permisos_de(s.rol))

    def _cmd_chat(self, s, msg):
        texto = str(msg.get("texto", "")).strip()[:1000]
        if not texto:
            raise ValueError("mensaje vacío")
        evento = {"evento": "chat", "de": s.usuario, "texto": texto,
                  "hora": datetime.now().strftime("%H:%M:%S")}
        with self._lock:
            destinos = [x for x in self.sesiones
                        if x.usuario and x is not s and roles.autorizar(x.rol, "chat")]
        for d in destinos:
            try:
                d.canal.enviar(evento)
            except OSError:
                pass
        return respuesta(msg, entregado_a=len(destinos))

    # ---------------------------------------------------------------- CSV
    @staticmethod
    def _nombre_seguro(nombre: str) -> str:
        nombre = os.path.basename(str(nombre or "").replace("\\", "/"))
        if not nombre or not nombre.lower().endswith(".csv") or nombre.startswith("."):
            raise ValueError("nombre de archivo inválido (debe terminar en .csv)")
        return nombre

    def _cmd_csv_listar(self, s, msg):
        archivos = [{"nombre": p.name, "tipo": "publico", "bytes": p.stat().st_size}
                    for p in sorted(config.CSV_PUBLICOS.glob("*.csv"))]
        if roles.autorizar(s.rol, "csv_privados"):
            archivos += [{"nombre": p.name, "tipo": "privado", "bytes": p.stat().st_size}
                         for p in sorted(config.CSV_PRIVADOS.glob("*.csv"))]
            archivos += [{"nombre": f"sucursal/{p.name}", "tipo": "privado", "bytes": p.stat().st_size}
                         for p in sorted(config.CSV_SUCURSAL.glob("*.csv"))]
        logger.registrar("PERMITIDO", COMPONENTE, f"csv_listar ({len(archivos)} archivos)",
                         usuario=s.usuario, ip=s.origen)
        return respuesta(msg, archivos=archivos)

    def _cmd_csv_descargar(self, s, msg):
        pedido = str(msg.get("nombre", ""))
        if pedido.startswith("sucursal/"):
            ruta, privado = config.CSV_SUCURSAL / self._nombre_seguro(pedido), True
        else:
            nombre = self._nombre_seguro(pedido)
            ruta, privado = config.CSV_PUBLICOS / nombre, False
            if not ruta.exists():
                ruta, privado = config.CSV_PRIVADOS / nombre, True
        if not ruta.exists():
            raise ValueError(f"no existe el archivo {pedido}")
        # Defensa en profundidad: el gateway solo sabe que pide "un CSV";
        # aquí el servidor revisa si ese CSV en particular es privado.
        if privado and not roles.autorizar(s.rol, "csv_privados"):
            return self._denegar(s, msg, "csv_privados")
        contenido = ruta.read_bytes()
        logger.registrar("PERMITIDO", COMPONENTE, f"csv_descargar {pedido}",
                         usuario=s.usuario, ip=s.origen)
        return respuesta(msg, nombre=ruta.name,
                         contenido=base64.b64encode(contenido).decode("ascii"))

    def _cmd_csv_subir(self, s, msg):
        nombre = self._nombre_seguro(msg.get("nombre"))
        datos = base64.b64decode(str(msg.get("contenido", "")), validate=True)
        if len(datos) > config.MAX_CSV_BYTES:
            raise ValueError("el archivo supera 1 MB")
        try:
            filas = list(csv.reader(io.StringIO(datos.decode("utf-8"))))
        except (UnicodeDecodeError, csv.Error):
            raise ValueError("el archivo no es un CSV válido en UTF-8")
        if not filas or len(filas[0]) < 1 or not any(filas[0]):
            raise ValueError("el CSV está vacío")
        destino = config.CSV_PRIVADOS / nombre
        if destino.exists() or (config.CSV_PUBLICOS / nombre).exists():
            raise ValueError(f"ya existe un archivo llamado {nombre}")
        destino.write_bytes(datos)
        logger.registrar("PERMITIDO", COMPONENTE, f"csv_subir {nombre} ({len(filas)} filas)",
                         usuario=s.usuario, ip=s.origen)
        return respuesta(msg, nombre=nombre, filas=len(filas))

    # --------------------------------------------------------------- admin
    def _cmd_logs_ver(self, s, msg):
        n = max(1, min(int(msg.get("n", 20)), 500))
        logger.registrar("ADMIN", COMPONENTE, f"logs_ver {n}", usuario=s.usuario, ip=s.origen)
        return respuesta(msg, lineas=logger.leer(n))

    def _cmd_logs_filtrar(self, s, msg):
        tipo = str(msg.get("tipo", "")).upper()
        if tipo not in logger.TIPOS:
            raise ValueError(f"tipo desconocido; opciones: {', '.join(sorted(logger.TIPOS))}")
        n = max(1, min(int(msg.get("n", 50)), 500))
        logger.registrar("ADMIN", COMPONENTE, f"logs_filtrar {tipo}", usuario=s.usuario, ip=s.origen)
        return respuesta(msg, lineas=logger.leer(n, tipo))

    def _cmd_sesiones(self, s, msg):
        with self._lock:
            lista = [{"usuario": x.usuario, "rol": x.rol, "origen": x.origen,
                      "desde": x.conectado} for x in self.sesiones if x.usuario]
        logger.registrar("ADMIN", COMPONENTE, "sesiones", usuario=s.usuario, ip=s.origen)
        return respuesta(msg, sesiones=lista)

    def _cmd_usuarios_listar(self, s, msg):
        logger.registrar("ADMIN", COMPONENTE, "usuarios_listar", usuario=s.usuario, ip=s.origen)
        return respuesta(msg, usuarios=auth.listar_usuarios())

    def _cmd_usuarios_crear(self, s, msg):
        nombre, rol = str(msg.get("nombre", "")), str(msg.get("rol", ""))
        auth.crear_usuario(nombre, rol, str(msg.get("password", "")))
        logger.registrar("ADMIN", COMPONENTE, f"usuarios_crear {nombre} rol {rol}",
                         usuario=s.usuario, ip=s.origen)
        return respuesta(msg, mensaje=f"usuario {nombre} creado con rol {rol}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    modo = ap.add_mutually_exclusive_group(required=True)
    modo.add_argument("--plano", action="store_true", help="sin cifrar (puerto 5000)")
    modo.add_argument("--tls", action="store_true", help="con TLS (puerto 5443)")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--puerto", type=int)
    ap.add_argument("--cert", type=Path, help="fullchain a presentar (por defecto el bueno)")
    ap.add_argument("--key", type=Path, help="llave privada del certificado")
    args = ap.parse_args()

    srv = ServidorApp("plano" if args.plano else "tls", args.host, args.puerto,
                      args.cert, args.key).iniciar()
    aviso = "  <-- SIN CIFRAR, solo para comparar" if args.plano else ""
    print(f"SecureCorp servidor en modo {srv.modo.upper()} escuchando en "
          f"{args.host}:{srv.puerto}{aviso}")
    if args.tls:
        print(f"  certificado: {args.cert or config.FULLCHAIN}")
    print("Ctrl+C para detener.")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        srv.detener()
        print("\nservidor detenido")


if __name__ == "__main__":
    main()
