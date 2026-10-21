"""Demostración de IPSec simulado: modo transporte vs modo túnel y anti-replay.

Uso (desde la carpeta securecorp/):
    # Todo en una sola máquina (emisor y receptor en la misma terminal)
    python3 ipsec/demo_ipsec.py --modo transporte
    python3 ipsec/demo_ipsec.py --modo tunel
    python3 ipsec/demo_ipsec.py --modo tunel --replay --manipular

    # En dos equipos (abre 7500/udp en el firewall del receptor)
    python3 ipsec/demo_ipsec.py --rol receptor --modo tunel                 # en la VM
    python3 ipsec/demo_ipsec.py --rol emisor --modo tunel --host <IP_VM> --replay

--replay     reenvía tal cual un paquete ya entregado (ataque de repetición)
--manipular  cambia un byte del contenido cifrado de un paquete nuevo
"""
import argparse
import hashlib
import socket
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from comun import config, logger  # noqa: E402
from ipsec import ipsec_sim as ips  # noqa: E402

SPI_DEMO = 0x1001
MENSAJES = [b"Hola desde el equipo 10.2.0.10",
            b"Reporte de ventas: 137,997 MXN",
            b"Fin de la transmision"]

IP_ORIGINAL = {"origen": config.IP_EQUIPO_SUCURSAL, "destino": config.IP_SERVIDOR_APP,
               "protocolo": "TCP"}


def crear_sa(modo: str, clave: str) -> ips.AsociacionSeguridad:
    llave = hashlib.sha256(clave.encode()).digest()
    sal = hashlib.sha256((clave + ":sal").encode()).digest()[:4]
    return ips.AsociacionSeguridad(SPI_DEMO, llave, sal, modo,
                                   config.IP_GW_SUCURSAL, config.IP_GW_MATRIZ)


def receptor(modo: str, clave: str, puerto: int, listo: threading.Event = None,
             sock: socket.socket = None) -> None:
    sa = crear_sa(modo, clave)
    sock = sock or socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if not listo:
        sock.bind(("0.0.0.0", puerto))
        print(f"[receptor] escuchando UDP {puerto} en modo {modo.upper()} (Ctrl+C para salir)")
    else:
        listo.set()
    while True:
        datos, origen = sock.recvfrom(65535)
        pkt = ips.desde_bytes(datos)
        print(f"\n[receptor] llegó por la red: {ips.describir(pkt)}")
        try:
            ip, contenido = sa.desencapsular(pkt)
            print(f"[receptor] ✓ ACEPTADO  original: IP {ip['origen']} -> {ip['destino']} "
                  f"[{ip['protocolo']}]  datos: {contenido.decode()!r}")
            logger.registrar("IPSEC_OK", "ipsec-demo",
                             f"modo {modo} seq {pkt['esp']['seq']}", ip=origen[0])
            sock.sendto(b"ok", origen)
        except ips.ReplayError as e:
            print(f"[receptor] ✗ RECHAZADO por anti-replay: {e}")
            logger.registrar("REPLAY", "ipsec-demo", str(e), ip=origen[0])
            sock.sendto(b"replay", origen)
        except ips.IntegridadError as e:
            print(f"[receptor] ✗ RECHAZADO por integridad: {e}")
            logger.registrar("INTEGRIDAD", "ipsec-demo", str(e), ip=origen[0])
            sock.sendto(b"integridad", origen)


def emisor(modo: str, clave: str, host: str, puerto: int, replay: bool, manipular: bool) -> list:
    sa = crear_sa(modo, clave)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    resultados = []

    def enviar(datos: bytes, etiqueta: str):
        sock.sendto(datos, (host, puerto))
        try:
            r = sock.recvfrom(64)[0].decode()
        except socket.timeout:
            r = "sin respuesta"
        resultados.append((etiqueta, r))
        return r

    print(f"=== IPSec modo {modo.upper()} ===")
    if modo == ips.TRANSPORTE:
        print("El encabezado IP original queda VISIBLE; solo se cifran los datos.")
    else:
        print("Todo el paquete original va CIFRADO; afuera solo se ven los gateways.")

    enviados = []
    for msg in MENSAJES:
        pkt = sa.encapsular(IP_ORIGINAL, msg)
        crudo = ips.a_bytes(pkt)
        enviados.append(crudo)
        print(f"\n[emisor] original : IP {IP_ORIGINAL['origen']} -> {IP_ORIGINAL['destino']} "
              f"[TCP]  datos: {msg.decode()!r}")
        print(f"[emisor] en la red: {ips.describir(pkt)}")
        enviar(crudo, f"seq {pkt['esp']['seq']}")

    if replay:
        print("\n[atacante] reenvía una copia exacta del paquete seq 2 ...")
        enviar(enviados[1], "replay seq 2")
    if manipular:
        pkt = sa.encapsular(IP_ORIGINAL, b"Transferir 1,000,000 MXN")
        c = bytearray(ips.base64.b64decode(pkt["cifrado"]))
        c[5] ^= 0xFF                                  # se altera un byte en tránsito
        pkt["cifrado"] = ips.base64.b64encode(bytes(c)).decode()
        print(f"\n[atacante] modifica un byte del paquete seq {pkt['esp']['seq']} ...")
        enviar(ips.a_bytes(pkt), f"manipulado seq {pkt['esp']['seq']}")

    print("\n=== Resumen ===")
    for etiqueta, r in resultados:
        print(f"  {etiqueta:<22} -> {r}")
    return resultados


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--modo", choices=[ips.TRANSPORTE, ips.TUNEL], default=ips.TUNEL)
    ap.add_argument("--rol", choices=["local", "emisor", "receptor"], default="local")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--puerto", type=int, default=config.PUERTO_IPSEC)
    ap.add_argument("--clave", default="demo-securecorp",
                    help="frase compartida para derivar la llave (igual en ambos lados)")
    ap.add_argument("--replay", action="store_true")
    ap.add_argument("--manipular", action="store_true")
    a = ap.parse_args()

    if a.rol == "receptor":
        try:
            receptor(a.modo, a.clave, a.puerto)
        except KeyboardInterrupt:
            pass
    elif a.rol == "emisor":
        emisor(a.modo, a.clave, a.host, a.puerto, a.replay, a.manipular)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        listo = threading.Event()
        threading.Thread(target=receptor, args=(a.modo, a.clave, 0, listo, sock),
                         daemon=True).start()
        listo.wait()
        emisor(a.modo, a.clave, "127.0.0.1", sock.getsockname()[1], a.replay, a.manipular)


if __name__ == "__main__":
    main()
