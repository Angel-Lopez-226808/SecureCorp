"""Contextos TLS reales (módulo ssl de Python, que usa OpenSSL).

Servidor: presenta fullchain.pem (su certificado + el de la CA intermedia).
Cliente:  confía SOLO en ca.crt (la raíz) y valida la cadena completa
          raíz -> intermedia -> servidor, las fechas y el nombre del servidor.
"""
import ssl
from pathlib import Path

from comun import config


def contexto_servidor(cert: Path = None, key: Path = None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(cert or config.FULLCHAIN), str(key or config.SERVIDOR_KEY))
    return ctx


def contexto_cliente(ca: Path = None) -> ssl.SSLContext:
    # create_default_context ya exige: certificado válido (CERT_REQUIRED),
    # nombre correcto (check_hostname) y cadena hasta una raíz de confianza.
    ctx = ssl.create_default_context(cafile=str(ca or config.CA_CRT))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def _cn(nombre) -> str:
    for rdn in nombre:
        for clave, valor in rdn:
            if clave == "commonName":
                return valor
    return "?"


def info_conexion(sock: ssl.SSLSocket) -> dict:
    """Datos de la sesión TLS ya establecida, para mostrarlos al usuario."""
    cert = sock.getpeercert()
    info = {
        "version": sock.version(),
        "cifrado": sock.cipher()[0],
        "sujeto": _cn(cert.get("subject", ())),
        "emisor": _cn(cert.get("issuer", ())),
        "valido_hasta": cert.get("notAfter"),
        "cadena": [],
    }
    # Python 3.13+ puede mostrar la cadena que se validó.
    if hasattr(sock, "get_verified_chain"):
        try:
            from cryptography import x509
            for der in sock.get_verified_chain():
                c = x509.load_der_x509_certificate(bytes(der))
                cn = c.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                info["cadena"].append(cn[0].value if cn else "?")
        except Exception:
            pass
    return info
