"""Requerimientos: comunicación cliente-servidor, TLS, certificados y PKI."""
import ssl
import subprocess
import time

import pytest

from cliente.cliente import Cliente
from comun import config
from conftest import PASSWORDS, Grabador, leer_log
from servidor.servidor_app import ServidorApp


def _sesion_capturada(puerto_real, modo):
    g = Grabador(puerto_real)
    c = Cliente("127.0.0.1", g.puerto, modo)
    c.conectar()
    assert c.login("ana", PASSWORDS["ana"])["ok"]
    assert c.pedir("chat", texto="reunion secreta a las 5")["ok"]
    c.cerrar()
    time.sleep(0.2)
    return bytes(g.capturado)


def test_plano_viaja_en_texto_claro(servidor_plano):
    capturado = _sesion_capturada(servidor_plano.puerto, "plano")
    assert PASSWORDS["ana"].encode() in capturado          # la contraseña se ve
    assert b"reunion secreta a las 5" in capturado         # el chat se ve


def test_tls_viaja_cifrado(servidor_tls):
    capturado = _sesion_capturada(servidor_tls.puerto, "tls")
    assert capturado[0] == 0x16                             # registro TLS Handshake
    assert PASSWORDS["ana"].encode() not in capturado
    assert b"reunion secreta" not in capturado
    assert b"login" not in capturado


def test_tls_muestra_version_cifrado_y_cadena(servidor_tls):
    c = Cliente("127.0.0.1", servidor_tls.puerto, "tls")
    info = c.conectar()
    c.cerrar()
    assert info["version"] in ("TLSv1.2", "TLSv1.3")
    assert info["sujeto"] == config.SERVIDOR_NOMBRE
    assert info["emisor"] == "SecureCorp Intermediate CA"
    if info["cadena"]:                                      # Python 3.13+
        assert info["cadena"] == [config.SERVIDOR_NOMBRE, "SecureCorp Intermediate CA",
                                  "SecureCorp Root CA"]


def test_cadena_de_confianza_con_openssl():
    certs = config.CERTS
    ok = subprocess.run(["openssl", "verify", "-CAfile", certs / "ca.crt", "-untrusted",
                         certs / "inter.crt", certs / "servidor.crt"], capture_output=True, text=True)
    assert ok.returncode == 0 and "OK" in ok.stdout
    # Sin la intermedia no se puede llegar a la raíz: la cadena se rompe.
    roto = subprocess.run(["openssl", "verify", "-CAfile", certs / "ca.crt",
                           certs / "servidor.crt"], capture_output=True, text=True)
    assert roto.returncode != 0


@pytest.mark.parametrize("caso, motivo_esperado", [
    ("autofirmado", "self-signed"),
    ("ca_falsa", "unable to get local issuer certificate"),
    ("nombre_incorrecto", "Hostname mismatch"),
    ("expirado", "certificate has expired"),
    ("sin_intermedia", "unable to get local issuer certificate"),
])
def test_cliente_rechaza_certificados_no_confiables(caso, motivo_esperado):
    d = config.CERTS / "pruebas" / caso
    srv = ServidorApp("tls", host="127.0.0.1", puerto=0,
                      cert=d / "fullchain.pem", key=d / "key.pem").iniciar()
    try:
        c = Cliente("127.0.0.1", srv.puerto, "tls")
        with pytest.raises(ssl.SSLCertVerificationError) as e:
            c.conectar()
        assert motivo_esperado.lower() in e.value.verify_message.lower()
        assert c.canal is None                     # no se llegó a enviar nada
        time.sleep(0.2)
        assert "CERT_RECHAZADO" in leer_log(config.LOG_CLIENTE)
        assert "TLS_ERROR" in leer_log()           # el servidor vio el handshake abortado
    finally:
        srv.detener()


def test_cliente_sin_la_ca_correcta_rechaza_incluso_el_certificado_bueno(servidor_tls):
    falsa = config.CERTS / "pruebas" / "ca_falsa" / "ca_falsa.crt"
    c = Cliente("127.0.0.1", servidor_tls.puerto, "tls", ca=falsa)
    with pytest.raises(ssl.SSLCertVerificationError):
        c.conectar()
