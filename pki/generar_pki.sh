#!/usr/bin/env bash
# =============================================================================
#  PKI de SecureCorp con OpenSSL
#
#  Crea la cadena de confianza de tres eslabones:
#     CA raíz  ->  CA intermedia  ->  certificado del servidor
#
#  Uso:  bash pki/generar_pki.sh [carpeta_salida]     (por defecto pki/certs)
#
#  Archivos que produce:
#     ca.crt / ca.key           CA raíz (ca.crt se copia al cliente; ca.key es secreta)
#     inter.crt / inter.key     CA intermedia
#     servidor.crt / .key       certificado de servidor.securecorp.local
#     fullchain.pem             servidor.crt + inter.crt (lo que presenta el servidor)
# =============================================================================
set -euo pipefail

SALIDA="${1:-$(dirname "$0")/certs}"
NOMBRE="servidor.securecorp.local"
mkdir -p "$SALIDA"
cd "$SALIDA"

echo "==> 1/4  CA raíz (10 años, 4096 bits)"
openssl req -x509 -newkey rsa:4096 -nodes -days 3650 -sha256 \
  -keyout ca.key -out ca.crt -subj "/O=SecureCorp/CN=SecureCorp Root CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" 2>/dev/null

echo "==> 2/4  CA intermedia, firmada por la raíz"
openssl req -newkey rsa:4096 -nodes -sha256 -keyout inter.key -out inter.csr \
  -subj "/O=SecureCorp/CN=SecureCorp Intermediate CA" 2>/dev/null
cat > inter.ext <<EOF
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
openssl x509 -req -in inter.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out inter.crt -days 1825 -sha256 -extfile inter.ext 2>/dev/null

echo "==> 3/4  Certificado del servidor ($NOMBRE), firmado por la intermedia"
openssl req -newkey rsa:2048 -nodes -sha256 -keyout servidor.key -out servidor.csr \
  -subj "/O=SecureCorp/CN=$NOMBRE" 2>/dev/null
cat > servidor.ext <<EOF
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:$NOMBRE
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
openssl x509 -req -in servidor.csr -CA inter.crt -CAkey inter.key -CAcreateserial \
  -out servidor.crt -days 90 -sha256 -extfile servidor.ext 2>/dev/null
cat servidor.crt inter.crt > fullchain.pem

echo "==> 4/4  Verificando la cadena raíz -> intermedia -> servidor"
openssl verify -CAfile ca.crt -untrusted inter.crt servidor.crt

chmod 600 ./*.key
rm -f ./*.csr
echo
echo "Listo. Copia SOLO ca.crt a la PC cliente (las .key nunca salen del servidor)."
