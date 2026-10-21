"""Cliente de consola de SecureCorp (corre en la PC cliente).

Uso (desde la carpeta securecorp/):
    # Uso normal: por la VPN de acceso remoto
    python3 cliente/cliente.py --vpn --host servidor.securecorp.local

    # Solo para la demo de comparación (directo al servidor)
    python3 cliente/cliente.py --plano --host servidor.securecorp.local
    python3 cliente/cliente.py --tls   --host servidor.securecorp.local

    --host puede ser la IP de la VM. El certificado se valida contra el nombre
    servidor.securecorp.local (cámbialo con --nombre si hace falta).
"""
import argparse
import base64
import csv
import getpass
import io
import itertools
import queue
import socket
import ssl
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from comun import config, logger, tls  # noqa: E402
from comun.protocolo import Canal, ConexionCerrada  # noqa: E402

PUERTOS = {"plano": config.PUERTO_PLANO, "tls": config.PUERTO_TLS, "vpn": config.PUERTO_VPN}


class ErrorServidor(Exception):
    pass


class Cliente:
    """Conexión al servidor (o al gateway VPN). La usan la consola y las pruebas."""

    def __init__(self, host: str, puerto: int = None, modo: str = "tls", ca: Path = None,
                 nombre: str = config.SERVIDOR_NOMBRE, timeout: float = 10):
        assert modo in PUERTOS
        self.host, self.modo, self.nombre, self.timeout = host, modo, nombre, timeout
        self.puerto = puerto or PUERTOS[modo]
        self.ca = Path(ca or config.CA_CRT)
        self.canal = None
        self.token = None                 # sesión VPN
        self.info_tls = None
        self.eventos = queue.Queue()      # mensajes que llegan sin pedirlos (chat)
        self.al_recibir_evento = None     # callback opcional para la consola
        self._pendientes = {}
        self._cerrando = False
        self._ids = itertools.count(1)
        self._lock = threading.Lock()

    # --------------------------------------------------------------- conexión
    def conectar(self) -> dict:
        """Abre la conexión. En TLS/VPN valida el certificado; si no es
        confiable lanza ssl.SSLCertVerificationError y NO se envía nada."""
        sock = socket.create_connection((self.host, self.puerto), timeout=self.timeout)
        if self.modo in ("tls", "vpn"):
            ctx = tls.contexto_cliente(self.ca)
            try:
                sock = ctx.wrap_socket(sock, server_hostname=self.nombre)
            except ssl.SSLCertVerificationError as e:
                sock.close()
                logger.registrar("CERT_RECHAZADO", "cliente",
                                 f"{self.host}:{self.puerto} -> {e.verify_message}",
                                 ip=self.host, archivo=config.LOG_CLIENTE)
                raise
            self.info_tls = tls.info_conexion(sock)
        sock.settimeout(None)
        self.canal = Canal(sock)
        threading.Thread(target=self._leer, daemon=True).start()
        return self.info_tls or {}

    def _leer(self) -> None:
        try:
            while True:
                msg = self.canal.recibir()
                if "re" in msg:
                    with self._lock:
                        q = self._pendientes.pop(msg["re"], None)
                    if q:
                        q.put(msg)
                else:
                    self.eventos.put(msg)
                    if self.al_recibir_evento:
                        self.al_recibir_evento(msg)
        except (ConexionCerrada, OSError, ValueError):
            fin = {"evento": "desconectado"}
            self.eventos.put(fin)
            with self._lock:
                pendientes, self._pendientes = list(self._pendientes.values()), {}
            for q in pendientes:
                q.put({"ok": False, "error": "conexión cerrada por el servidor"})
            if self.al_recibir_evento and not self._cerrando:
                self.al_recibir_evento(fin)

    def pedir(self, cmd: str, **datos) -> dict:
        mid = next(self._ids)
        q = queue.Queue()
        with self._lock:
            self._pendientes[mid] = q
        msg = {"id": mid, "cmd": cmd, **datos}
        if self.token:
            msg["token"] = self.token
        self.canal.enviar(msg)
        try:
            return q.get(timeout=self.timeout)
        except queue.Empty:
            raise ErrorServidor("el servidor no respondió a tiempo")

    def login(self, usuario: str, password: str) -> dict:
        r = self.pedir("login", usuario=usuario, password=password)
        if r.get("ok") and r.get("token"):
            self.token = r["token"]
        return r

    def cerrar(self) -> None:
        if self.canal and not self.canal._cerrado:
            self._cerrando = True
            try:
                self.pedir("salir")
            except (ErrorServidor, OSError):
                pass
            self.canal.cerrar()


# =============================================================== consola
AYUDA = """
Comandos (lo que puedes usar depende de tu rol):
  quien                         tu usuario, rol, IP y permisos
  chat                          entrar a la sala de chat (/salir para volver)
  csv listar                    archivos CSV a los que tienes acceso
  csv descargar <archivo>       guarda en ./descargas y muestra una vista previa
  csv subir <ruta_local.csv>    sube un CSV (se guarda como privado)
  logs ver [n]                  últimos n eventos                (admin)
  logs filtrar <TIPO> [n]       eventos de un tipo: DENEGADO, LOGIN_FALLIDO, ...  (admin)
  sesiones                      usuarios conectados              (admin)
  usuarios listar               cuentas registradas              (admin)
  usuarios crear <nombre> <rol> crea una cuenta (pide contraseña)  (admin)
  ayuda | salir
"""


def imprimir_evento(ev: dict) -> None:
    if ev.get("evento") == "chat":
        print(f"\r  [{ev.get('hora')}] {ev['de']}: {ev['texto']}\n> ", end="", flush=True)
    elif ev.get("evento") == "aviso":
        print(f"\r  ** {ev.get('mensaje')}\n> ", end="", flush=True)
    elif ev.get("evento") == "desconectado":
        print("\r  ** conexión cerrada por el servidor. Escribe 'salir'.\n> ", end="", flush=True)


def mostrar(r: dict) -> bool:
    if not r.get("ok"):
        print(f"  ✗ {r.get('error')}")
        return False
    return True


def vista_previa(datos: bytes, filas: int = 6) -> None:
    lector = list(csv.reader(io.StringIO(datos.decode("utf-8", errors="replace"))))
    if not lector:
        return
    anchos = [max(len(f[i]) if i < len(f) else 0 for f in lector[:filas])
              for i in range(len(lector[0]))]
    for n, fila in enumerate(lector[:filas]):
        print("   " + "  ".join(c.ljust(anchos[i]) for i, c in enumerate(fila)))
        if n == 0:
            print("   " + "  ".join("-" * a for a in anchos))
    if len(lector) > filas:
        print(f"   ... ({len(lector) - 1} filas en total)")


def ejecutar(cli: Cliente, linea: str) -> bool:
    """Ejecuta un comando de la consola. Devuelve False para salir."""
    partes = linea.split()
    if not partes:
        return True
    cmd, args = partes[0].lower(), partes[1:]

    if cmd in ("salir", "exit", "quit"):
        return False
    if cmd in ("ayuda", "help", "?"):
        print(AYUDA)
    elif cmd == "quien":
        r = cli.pedir("quien")
        if mostrar(r):
            print(f"  usuario: {r['usuario']}   rol: {r['rol']}   ip real: {r['ip']}"
                  f"   ip VPN: {r.get('ip_vpn') or '-'}")
            print(f"  permisos: {', '.join(r['permisos'])}")
    elif cmd == "chat":
        modo_chat(cli)
    elif cmd == "csv" and args:
        sub = args[0].lower()
        if sub == "listar":
            r = cli.pedir("csv_listar")
            if mostrar(r):
                for a in r["archivos"]:
                    print(f"  [{a['tipo']:<7}] {a['nombre']:<34} {a['bytes']:>7} bytes")
        elif sub == "descargar" and len(args) > 1:
            r = cli.pedir("csv_descargar", nombre=args[1])
            if mostrar(r):
                datos = base64.b64decode(r["contenido"])
                destino = Path("descargas") / r["nombre"]
                destino.parent.mkdir(exist_ok=True)
                destino.write_bytes(datos)
                print(f"  ✓ guardado en {destino} ({len(datos)} bytes)")
                vista_previa(datos)
        elif sub == "subir" and len(args) > 1:
            ruta = Path(args[1])
            if not ruta.is_file():
                print(f"  ✗ no encuentro {ruta}")
            else:
                r = cli.pedir("csv_subir", nombre=ruta.name,
                              contenido=base64.b64encode(ruta.read_bytes()).decode("ascii"))
                if mostrar(r):
                    print(f"  ✓ subido {r['nombre']} ({r['filas']} filas)")
        else:
            print("  uso: csv listar | csv descargar <archivo> | csv subir <ruta>")
    elif cmd == "logs" and args:
        if args[0] == "ver":
            r = cli.pedir("logs_ver", n=int(args[1]) if len(args) > 1 else 20)
        elif args[0] == "filtrar" and len(args) > 1:
            r = cli.pedir("logs_filtrar", tipo=args[1],
                          n=int(args[2]) if len(args) > 2 else 50)
        else:
            print("  uso: logs ver [n] | logs filtrar <TIPO> [n]")
            return True
        if mostrar(r):
            for l in r["lineas"] or ["  (sin eventos)"]:
                print("  " + l)
    elif cmd == "sesiones":
        r = cli.pedir("sesiones")
        if mostrar(r):
            for s in r["sesiones"]:
                print(f"  {s['usuario']:<12} {s['rol']:<9} {s['origen']:<22} desde {s['desde']}")
    elif cmd == "usuarios" and args:
        if args[0] == "listar":
            r = cli.pedir("usuarios_listar")
            if mostrar(r):
                for u in r["usuarios"]:
                    print(f"  {u['usuario']:<12} {u['rol']}")
        elif args[0] == "crear" and len(args) == 3:
            pw = getpass.getpass("  contraseña para la nueva cuenta (mín. 8): ")
            r = cli.pedir("usuarios_crear", nombre=args[1], rol=args[2], password=pw)
            if mostrar(r):
                print("  ✓ " + r["mensaje"])
        else:
            print("  uso: usuarios listar | usuarios crear <nombre> <admin|normal|invitado>")
    else:
        print("  comando no reconocido; escribe 'ayuda'")
    return True


def modo_chat(cli: Cliente) -> None:
    r = cli.pedir("quien")      # comprobación rápida de permiso antes de entrar
    if "chat" not in r.get("permisos", []):
        # Igual lo intentamos para que el servidor/gateway lo registre como DENEGADO.
        mostrar(cli.pedir("chat", texto="(intento de entrar al chat)"))
        return
    print("  Sala de chat. Escribe tus mensajes; /salir para volver al menú.")
    while True:
        try:
            texto = input("chat> ")
        except EOFError:
            return
        if texto.strip() == "/salir":
            return
        if texto.strip():
            r = cli.pedir("chat", texto=texto)
            if not r.get("ok"):
                mostrar(r)
                return


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    m = ap.add_mutually_exclusive_group(required=True)
    m.add_argument("--plano", action="store_true", help="directo, sin cifrar (5000)")
    m.add_argument("--tls", action="store_true", help="directo, con TLS (5443)")
    m.add_argument("--vpn", action="store_true", help="por el gateway VPN (6443)")
    ap.add_argument("--host", default=config.SERVIDOR_NOMBRE, help="IP o nombre del servidor")
    ap.add_argument("--puerto", type=int)
    ap.add_argument("--ca", type=Path, default=config.CA_CRT, help="certificado de la CA raíz")
    ap.add_argument("--nombre", default=config.SERVIDOR_NOMBRE,
                    help="nombre esperado en el certificado")
    ap.add_argument("--usuario")
    args = ap.parse_args()
    modo = "plano" if args.plano else "tls" if args.tls else "vpn"

    cli = Cliente(args.host, args.puerto, modo, args.ca, args.nombre)
    print(f"Conectando a {args.host}:{cli.puerto} en modo {modo.upper()}...")
    try:
        info = cli.conectar()
    except ssl.SSLCertVerificationError as e:
        print("\n  ✗ CERTIFICADO RECHAZADO — la conexión NO se estableció")
        print(f"    motivo: {e.verify_message}")
        print("    (no se envió ningún dato al servidor)")
        sys.exit(2)
    except OSError as e:
        sys.exit(f"  ✗ no se pudo conectar: {e}")

    if modo == "plano":
        print("  ⚠ conexión SIN cifrar: todo (incluida tu contraseña) viaja en texto claro")
    else:
        print(f"  ✓ {info['version']}  cifrado: {info['cifrado']}")
        print(f"  ✓ certificado de '{info['sujeto']}' emitido por '{info['emisor']}'"
              f" (válido hasta {info['valido_hasta']})")
        if info["cadena"]:
            print(f"  ✓ cadena validada: {' -> '.join(reversed(info['cadena']))}")

    for _ in range(3):
        usuario = args.usuario or input("usuario: ")
        r = cli.login(usuario, getpass.getpass("contraseña: "))
        if r.get("ok"):
            break
        mostrar(r)
        args.usuario = None
    else:
        cli.cerrar()
        sys.exit("demasiados intentos")

    print(f"  ✓ bienvenido, {r['usuario']} (rol {r['rol']})")
    if modo == "vpn":
        print(f"  ✓ VPN conectada. IP virtual asignada: {r['ip_virtual']}  "
              f"(sesión válida hasta {r['expira']})")
        print(f"  recursos disponibles para tu rol: {', '.join(r['recursos'])}")
    print("  escribe 'ayuda' para ver los comandos")

    cli.al_recibir_evento = imprimir_evento
    try:
        while True:
            try:
                linea = input("> ")
            except EOFError:
                break
            try:
                if not ejecutar(cli, linea):
                    break
            except ErrorServidor as e:
                print(f"  ✗ {e}")
            except OSError:
                print("  ✗ se perdió la conexión")
                break
    except KeyboardInterrupt:
        pass
    cli.cerrar()
    print("sesión cerrada")


if __name__ == "__main__":
    main()
