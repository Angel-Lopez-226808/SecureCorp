"""VPN sitio a sitio (simulada): une la red sucursal (10.2.0.0/24) con la red
matriz (10.1.0.0/24) mediante un túnel IPSec en MODO TÚNEL.

Diferencia con la VPN de acceso remoto:
  - Aquí NO hay usuario ni login. Se autentican los dos GATEWAYS entre sí con
    una llave precompartida (PSK), como lo haría IKE.
  - El túnel une redes completas y es permanente; cualquier equipo de la
    sucursal puede usarlo sin saber que existe.

Negociación (simula IKE con PSK):
  sucursal -> matriz : ike_init  (nonce_i, spi_i)
  matriz -> sucursal : ike_resp  (nonce_r, spi_r, auth = HMAC(PSK, "matriz"|nonces|spis))
  sucursal -> matriz : ike_auth  (auth = HMAC(PSK, "sucursal"|nonces|spis))
  matriz -> sucursal : ike_ok
  Las llaves AES de cada sentido se derivan con HKDF(PSK, nonces): son nuevas
  en cada conexión.

Uso (desde la carpeta securecorp/, ambos procesos pueden correr en la VM):
    python3 vpn/sitio_a_sitio.py --rol matriz
    python3 vpn/sitio_a_sitio.py --rol sucursal [--archivo datos/sucursal/reporte_sucursal.csv]
    python3 vpn/sitio_a_sitio.py --rol sucursal --replay        # además intenta un replay
    python3 vpn/sitio_a_sitio.py --rol sucursal --psk-falsa     # gateway impostor
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import socket
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # noqa: E402

from comun import config, logger  # noqa: E402
from ipsec import ipsec_sim as ips  # noqa: E402

COMPONENTE = "sitio-a-sitio"
TAM_TROZO = 900


def leer_psk(ruta: Path = None) -> bytes:
    return bytes.fromhex(Path(ruta or config.PSK_SITIO).read_text().strip())


def _auth(psk: bytes, quien: str, ni: bytes, nr: bytes, spi_i: int, spi_r: int) -> str:
    msg = f"{quien}|".encode() + ni + nr + spi_i.to_bytes(4, "big") + spi_r.to_bytes(4, "big")
    return hmac.new(psk, msg, hashlib.sha256).hexdigest()


def _derivar_sas(psk: bytes, ni: bytes, nr: bytes, spi_i: int, spi_r: int):
    """Devuelve (sa_sucursal_a_matriz, sa_matriz_a_sucursal)."""
    material = HKDF(algorithm=hashes.SHA256(), length=72, salt=ni + nr,
                    info=b"securecorp-ipsec-sitio").derive(psk)
    s2m = ips.AsociacionSeguridad(spi_r, material[:32], material[32:36], ips.TUNEL,
                                  config.IP_GW_SUCURSAL, config.IP_GW_MATRIZ)
    m2s = ips.AsociacionSeguridad(spi_i, material[36:68], material[68:72], ips.TUNEL,
                                  config.IP_GW_MATRIZ, config.IP_GW_SUCURSAL)
    return s2m, m2s


def _enviar(sock, msg: dict, destino) -> None:
    sock.sendto(json.dumps(msg).encode(), destino)


# ================================================================== MATRIZ
class GatewayMatriz:
    def __init__(self, host: str = "0.0.0.0", puerto: int = config.PUERTO_IPSEC,
                 psk: bytes = None, verbose: bool = False):
        self.psk = psk or leer_psk()
        self.verbose = verbose
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, puerto))
        self.puerto = self.sock.getsockname()[1]
        self.tuneles = {}          # dirección -> estado del túnel
        self.recibidos = []        # rutas guardadas
        self.rechazos = []         # (tipo, detalle)
        self._activo = True

    def _decir(self, texto: str) -> None:
        if self.verbose:
            print(f"[matriz] {texto}")

    def iniciar(self) -> "GatewayMatriz":
        threading.Thread(target=self._bucle, daemon=True).start()
        return self

    def detener(self) -> None:
        self._activo = False
        self.sock.close()

    def _bucle(self) -> None:
        while self._activo:
            try:
                datos, origen = self.sock.recvfrom(65535)
                self._procesar(json.loads(datos.decode()), origen)
            except OSError:
                break
            except (ValueError, KeyError) as e:
                self._decir(f"mensaje malformado: {e}")

    def _procesar(self, m: dict, origen) -> None:
        tipo = m.get("tipo")
        t = self.tuneles.get(origen)
        if tipo == "ike_init":
            nr, spi_r = os.urandom(16), int.from_bytes(os.urandom(4), "big")
            ni, spi_i = bytes.fromhex(m["nonce"]), int(m["spi"])
            self.tuneles[origen] = {"ni": ni, "nr": nr, "spi_i": spi_i, "spi_r": spi_r,
                                    "listo": False, "partes": {}}
            _enviar(self.sock, {"tipo": "ike_resp", "nonce": nr.hex(), "spi": spi_r,
                                "auth": _auth(self.psk, "matriz", ni, nr, spi_i, spi_r)}, origen)
            self._decir(f"IKE: propuesta de {origen[0]}, respondiendo")
        elif tipo == "ike_auth" and t:
            esperado = _auth(self.psk, "sucursal", t["ni"], t["nr"], t["spi_i"], t["spi_r"])
            if not hmac.compare_digest(esperado, str(m.get("auth", ""))):
                del self.tuneles[origen]
                self.rechazos.append(("IKE_FALLIDO", origen[0]))
                logger.registrar("IKE_FALLIDO", COMPONENTE,
                                 "el gateway remoto no demostró conocer la PSK", ip=origen[0])
                _enviar(self.sock, {"tipo": "ike_error", "motivo": "autenticación fallida"}, origen)
                self._decir(f"IKE: ✗ {origen[0]} NO conoce la llave precompartida; túnel rechazado")
                return
            t["entrada"], t["salida"] = _derivar_sas(self.psk, t["ni"], t["nr"],
                                                     t["spi_i"], t["spi_r"])
            t["listo"] = True
            logger.registrar("IKE_OK", COMPONENTE, f"túnel {config.RED_SUCURSAL} <-> "
                             f"{config.RED_MATRIZ} establecido (spi {t['spi_r']})", ip=origen[0])
            _enviar(self.sock, {"tipo": "ike_ok"}, origen)
            self._decir(f"IKE: ✓ gateway sucursal autenticado; túnel "
                        f"{config.RED_SUCURSAL} <-> {config.RED_MATRIZ} listo")
        elif tipo == "esp" and t and t["listo"]:
            self._recibir_esp(m, origen, t)
        else:
            self._decir(f"mensaje '{tipo}' ignorado: no hay túnel con {origen[0]}")

    def _recibir_esp(self, m: dict, origen, t: dict) -> None:
        self._decir(f"llega por Internet: {ips.describir(m)}")
        try:
            ip, datos = t["entrada"].desencapsular(m)
        except ips.ReplayError as e:
            self.rechazos.append(("REPLAY", str(e)))
            logger.registrar("REPLAY", COMPONENTE, str(e), ip=origen[0])
            self._decir(f"  ✗ RECHAZADO (anti-replay): {e}")
            return
        except ips.IntegridadError as e:
            self.rechazos.append(("INTEGRIDAD", str(e)))
            logger.registrar("INTEGRIDAD", COMPONENTE, str(e), ip=origen[0])
            self._decir(f"  ✗ RECHAZADO (integridad): {e}")
            return
        trozo = json.loads(datos)
        self._decir(f"  ✓ descifrado: IP original {ip['origen']} -> {ip['destino']}, "
                    f"{trozo['archivo']} parte {trozo['parte']}/{trozo['total']}")
        partes = t["partes"].setdefault(trozo["archivo"], {})
        partes[trozo["parte"]] = base64.b64decode(trozo["datos"])
        if len(partes) == trozo["total"]:
            contenido = b"".join(partes[i] for i in range(1, trozo["total"] + 1))
            nombre = os.path.basename(trozo["archivo"])
            if not nombre.endswith(".csv"):
                nombre += ".csv"
            destino = config.CSV_SUCURSAL / nombre
            destino.parent.mkdir(parents=True, exist_ok=True)
            destino.write_bytes(contenido)
            self.recibidos.append(destino)
            del t["partes"][trozo["archivo"]]
            logger.registrar("SITIO_A_SITIO", COMPONENTE,
                             f"recibido {nombre} ({len(contenido)} bytes) desde {ip['origen']} "
                             f"por el túnel", ip=origen[0])
            self._decir(f"  ✓ archivo completo guardado en {destino}")
            ack = t["salida"].encapsular(
                {"origen": config.IP_SERVIDOR_APP, "destino": ip["origen"], "protocolo": "TCP"},
                json.dumps({"recibido": nombre, "bytes": len(contenido)}).encode())
            _enviar(self.sock, {"tipo": "esp", **ack}, origen)


# ================================================================ SUCURSAL
def enviar_reporte(host: str, puerto: int, archivo: Path, psk: bytes = None,
                   replay: bool = False, verbose: bool = True, impostor: bool = False) -> dict:
    def decir(t):
        if verbose:
            print(f"[sucursal] {t}")

    psk = psk or leer_psk()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    destino = (host, puerto)

    # --- IKE (simulado) --------------------------------------------------
    ni, spi_i = os.urandom(16), int.from_bytes(os.urandom(4), "big")
    _enviar(sock, {"tipo": "ike_init", "nonce": ni.hex(), "spi": spi_i}, destino)
    resp = json.loads(sock.recvfrom(65535)[0])
    nr, spi_r = bytes.fromhex(resp["nonce"]), int(resp["spi"])
    if impostor:
        decir("[impostor] no conoce la PSK real; intenta autenticarse de todos modos...")
    elif not hmac.compare_digest(resp["auth"], _auth(psk, "matriz", ni, nr, spi_i, spi_r)):
        decir("✗ el gateway remoto NO conoce la PSK: no es la matriz. Abortando.")
        return {"ok": False, "error": "matriz no autenticada"}
    else:
        decir("IKE: ✓ la matriz demostró conocer la llave precompartida")
    _enviar(sock, {"tipo": "ike_auth", "auth": _auth(psk, "sucursal", ni, nr, spi_i, spi_r)},
            destino)
    fin = json.loads(sock.recvfrom(65535)[0])
    if fin.get("tipo") != "ike_ok":
        decir(f"✗ la matriz rechazó el túnel: {fin.get('motivo')}")
        return {"ok": False, "error": fin.get("motivo", "IKE fallido")}
    salida, entrada = _derivar_sas(psk, ni, nr, spi_i, spi_r)
    decir(f"túnel {config.RED_SUCURSAL} <-> {config.RED_MATRIZ} establecido (modo túnel)")

    # --- Envío del archivo por el túnel ------------------------------------
    contenido = Path(archivo).read_bytes()
    trozos = [contenido[i:i + TAM_TROZO] for i in range(0, len(contenido), TAM_TROZO)] or [b""]
    ip_original = {"origen": config.IP_EQUIPO_SUCURSAL, "destino": config.IP_SERVIDOR_APP,
                   "protocolo": "TCP"}
    enviados = []
    for n, t in enumerate(trozos, 1):
        carga = json.dumps({"archivo": Path(archivo).name, "parte": n, "total": len(trozos),
                            "datos": base64.b64encode(t).decode()}).encode()
        pkt = {"tipo": "esp", **salida.encapsular(ip_original, carga)}
        enviados.append(pkt)
        decir(f"parte {n}/{len(trozos)} -> {ips.describir(pkt)}")
        _enviar(sock, pkt, destino)

    ack = json.loads(sock.recvfrom(65535)[0])
    _, datos = entrada.desencapsular(ack)
    confirmacion = json.loads(datos)
    decir(f"✓ la matriz confirmó por el túnel: {confirmacion}")

    if replay:
        decir("[atacante] reenvía una copia del primer paquete ya entregado...")
        _enviar(sock, enviados[0], destino)
    return {"ok": True, "confirmacion": confirmacion, "paquetes": len(enviados)}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rol", choices=["matriz", "sucursal"], required=True)
    ap.add_argument("--host", default="127.0.0.1", help="(sucursal) IP del gateway matriz")
    ap.add_argument("--puerto", type=int, default=config.PUERTO_IPSEC)
    ap.add_argument("--archivo", type=Path, default=config.DATOS_SUCURSAL / "reporte_sucursal.csv")
    ap.add_argument("--replay", action="store_true")
    ap.add_argument("--psk-falsa", action="store_true", help="simula un gateway impostor")
    a = ap.parse_args()

    if a.rol == "matriz":
        gw = GatewayMatriz("0.0.0.0", a.puerto, verbose=True).iniciar()
        print(f"Gateway MATRIZ ({config.IP_GW_MATRIZ}, red {config.RED_MATRIZ}) escuchando "
              f"UDP {gw.puerto}. Ctrl+C para detener.")
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            gw.detener()
    else:
        psk = os.urandom(32) if a.psk_falsa else None
        try:
            r = enviar_reporte(a.host, a.puerto, a.archivo, psk, a.replay,
                               impostor=a.psk_falsa)
        except socket.timeout:
            sys.exit("[sucursal] ✗ la matriz no respondió (¿está corriendo? ¿firewall?)")
        sys.exit(0 if r["ok"] else 1)


if __name__ == "__main__":
    main()
