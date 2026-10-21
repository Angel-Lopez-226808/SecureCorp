"""Genera un certificado de servidor YA VENCIDO, firmado por la CA intermedia real.

Así la única razón para rechazarlo es la fecha (la firma y el nombre son buenos).

Uso: python3 pki/generar_cert_expirado.py <carpeta_certs> <carpeta_salida>
"""
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

NOMBRE = "servidor.securecorp.local"


def main(certs: Path, salida: Path) -> None:
    salida.mkdir(parents=True, exist_ok=True)
    inter_crt = x509.load_pem_x509_certificate((certs / "inter.crt").read_bytes())
    inter_key = serialization.load_pem_private_key((certs / "inter.key").read_bytes(), None)

    llave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sujeto = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureCorp"),
                        x509.NameAttribute(NameOID.COMMON_NAME, NOMBRE)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(sujeto)
        .issuer_name(inter_crt.subject)
        .public_key(llave.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2025, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2025, 2, 1, tzinfo=timezone.utc))   # ya venció
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True,
                                     content_commitment=False, data_encipherment=False,
                                     key_agreement=False, key_cert_sign=False,
                                     crl_sign=False, encipher_only=False,
                                     decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(NOMBRE)]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(llave.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(inter_key.public_key()),
                       critical=False)
        .sign(inter_key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM)
    (salida / "cert.pem").write_bytes(pem)
    (salida / "fullchain.pem").write_bytes(pem + (certs / "inter.crt").read_bytes())
    (salida / "key.pem").write_bytes(llave.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(Path(sys.argv[1]), Path(sys.argv[2]))
