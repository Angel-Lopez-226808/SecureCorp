"""Requerimiento: IPSec en modo transporte y modo túnel, y protección contra replay."""
import base64
import os
import subprocess
import sys

import pytest

from conftest import RAIZ
from ipsec import ipsec_sim as ips

IP = {"origen": "10.2.0.10", "destino": "10.1.0.20", "protocolo": "TCP"}
SECRETO = b"nomina de octubre: 412000"


def _par(modo):
    k, sal = os.urandom(32), os.urandom(4)
    args = (0x2001, k, sal, modo, "10.2.0.1", "10.1.0.1")
    return ips.AsociacionSeguridad(*args), ips.AsociacionSeguridad(*args)


def test_modo_transporte_conserva_ip_original_y_cifra_datos():
    emisor, receptor = _par(ips.TRANSPORTE)
    pkt = emisor.encapsular(IP, SECRETO)
    crudo = ips.a_bytes(pkt)
    assert pkt["ip"]["origen"] == "10.2.0.10" and pkt["ip"]["destino"] == "10.1.0.20"
    assert pkt["ip"]["protocolo"] == "ESP"
    assert SECRETO not in crudo and base64.b64encode(SECRETO) not in crudo
    ip, datos = receptor.desencapsular(ips.desde_bytes(crudo))
    assert ip == IP and datos == SECRETO


def test_modo_tunel_oculta_el_paquete_completo():
    emisor, receptor = _par(ips.TUNEL)
    pkt = emisor.encapsular(IP, SECRETO)
    crudo = ips.a_bytes(pkt)
    assert pkt["ip"] == {"origen": "10.2.0.1", "destino": "10.1.0.1", "protocolo": "ESP"}
    assert b"10.2.0.10" not in crudo and b"10.1.0.20" not in crudo   # IPs internas ocultas
    assert SECRETO not in crudo
    ip, datos = receptor.desencapsular(pkt)
    assert ip == IP and datos == SECRETO


def test_replay_paquete_repetido_es_rechazado():
    emisor, receptor = _par(ips.TUNEL)
    p1, p2 = emisor.encapsular(IP, b"uno"), emisor.encapsular(IP, b"dos")
    receptor.desencapsular(p1)
    receptor.desencapsular(p2)
    with pytest.raises(ips.ReplayError, match="ya fue recibido"):
        receptor.desencapsular(p1)


def test_ventana_acepta_desorden_pero_no_paquetes_viejos():
    emisor, receptor = _par(ips.TUNEL)
    paquetes = [emisor.encapsular(IP, f"m{i}".encode()) for i in range(1, 101)]
    receptor.desencapsular(paquetes[10])          # seq 11
    receptor.desencapsular(paquetes[5])           # seq 6: llega tarde pero dentro de la ventana
    receptor.desencapsular(paquetes[99])          # seq 100
    with pytest.raises(ips.ReplayError, match="fuera de la ventana"):
        receptor.desencapsular(paquetes[20])      # seq 21 < 100 - 64


def test_paquete_alterado_es_rechazado_y_no_mueve_la_ventana():
    emisor, receptor = _par(ips.TUNEL)
    pkt = emisor.encapsular(IP, b"Transferir 100 MXN")
    alterado = dict(pkt, cifrado=base64.b64encode(
        bytes([b ^ 1 if i == 3 else b for i, b in enumerate(base64.b64decode(pkt["cifrado"]))])
    ).decode())
    with pytest.raises(ips.IntegridadError):
        receptor.desencapsular(alterado)
    assert receptor.desencapsular(pkt)[1] == b"Transferir 100 MXN"   # el genuino sí entra


def test_numero_de_secuencia_forjado_es_rechazado():
    emisor, receptor = _par(ips.TUNEL)
    pkt = emisor.encapsular(IP, b"hola")
    pkt["esp"]["seq"] = 999                       # el atacante cambia la secuencia
    with pytest.raises(ips.IntegridadError):      # va autenticada (AAD): no cuela
        receptor.desencapsular(pkt)


@pytest.mark.parametrize("modo", ["transporte", "tunel"])
def test_demo_ipsec_por_udp(modo):
    r = subprocess.run([sys.executable, str(RAIZ / "ipsec/demo_ipsec.py"), "--modo", modo,
                        "--replay", "--manipular"], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    salida = r.stdout
    assert "replay seq 2           -> replay" in salida
    assert "-> integridad" in salida
    assert salida.count("-> ok") == 3
    if modo == "tunel":
        assert "IP 10.2.0.1 -> 10.1.0.1 [ESP]" in salida
    else:
        assert "IP 10.2.0.10 -> 10.1.0.20 [ESP]" in salida
