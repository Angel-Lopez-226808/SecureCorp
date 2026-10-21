#!/usr/bin/env bash
# =============================================================================
#  Certificados "malos" para demostrar que el cliente los RECHAZA.
#  Requiere haber corrido antes generar_pki.sh (usa la CA intermedia real).
#
#  Uso:  bash pki/generar_certs_prueba.sh [carpeta_certs]   (por defecto pki/certs)
#
#  Crea en <carpeta>/pruebas/<caso>/ un cert.pem, key.pem y fullchain.pem:
#     autofirmado        se firma a sí mismo; nadie da fe de él
#     ca_falsa           firmado por una CA que se llama igual pero NO es la nuestra
#     nombre_incorrecto  firmado por nuestra CA, pero para otro.securecorp.local
#     expirado           firmado por nuestra CA, pero ya venció (lo hace Python)
#     sin_intermedia     el certificado bueno SIN la intermedia: cadena incompleta
# =============================================================================
set -euo pipefail

CERTS="${1:-$(dirname "$0")/certs}"
AQUI="$(cd "$(dirname "$0")" && pwd)"
P="$CERTS/pruebas"
mkdir -p "$P"/{autofirmado,ca_falsa,nombre_incorrecto,expirado,sin_intermedia}

ext_servidor() {   # $1 = nombre DNS
cat <<EOF
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:$1
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
}

echo "==> autofirmado"
openssl req -x509 -newkey rsa:2048 -nodes -days 90 -sha256 \
  -keyout "$P/autofirmado/key.pem" -out "$P/autofirmado/cert.pem" \
  -subj "/O=SecureCorp/CN=servidor.securecorp.local" \
  -addext "subjectAltName=DNS:servidor.securecorp.local" 2>/dev/null
cp "$P/autofirmado/cert.pem" "$P/autofirmado/fullchain.pem"

echo "==> ca_falsa (una CA impostora con el mismo nombre)"
D="$P/ca_falsa"
openssl req -x509 -newkey rsa:2048 -nodes -days 365 -sha256 \
  -keyout "$D/ca_falsa.key" -out "$D/ca_falsa.crt" -subj "/O=SecureCorp/CN=SecureCorp Root CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -sha256 -keyout "$D/key.pem" -out "$D/req.csr" \
  -subj "/O=SecureCorp/CN=servidor.securecorp.local" 2>/dev/null
ext_servidor servidor.securecorp.local > "$D/ext"
openssl x509 -req -in "$D/req.csr" -CA "$D/ca_falsa.crt" -CAkey "$D/ca_falsa.key" \
  -CAcreateserial -out "$D/cert.pem" -days 90 -sha256 -extfile "$D/ext" 2>/dev/null
cp "$D/cert.pem" "$D/fullchain.pem"

echo "==> nombre_incorrecto (para otro.securecorp.local)"
D="$P/nombre_incorrecto"
openssl req -newkey rsa:2048 -nodes -sha256 -keyout "$D/key.pem" -out "$D/req.csr" \
  -subj "/O=SecureCorp/CN=otro.securecorp.local" 2>/dev/null
ext_servidor otro.securecorp.local > "$D/ext"
openssl x509 -req -in "$D/req.csr" -CA "$CERTS/inter.crt" -CAkey "$CERTS/inter.key" \
  -CAcreateserial -out "$D/cert.pem" -days 90 -sha256 -extfile "$D/ext" 2>/dev/null
cat "$D/cert.pem" "$CERTS/inter.crt" > "$D/fullchain.pem"

echo "==> expirado (OpenSSL no emite fechas pasadas fácil; lo genera Python)"
python3 "$AQUI/generar_cert_expirado.py" "$CERTS" "$P/expirado"

echo "==> sin_intermedia (cadena incompleta)"
cp "$CERTS/servidor.crt" "$P/sin_intermedia/cert.pem"
cp "$CERTS/servidor.crt" "$P/sin_intermedia/fullchain.pem"
cp "$CERTS/servidor.key" "$P/sin_intermedia/key.pem"

rm -f "$P"/*/*.csr "$P"/*/ext
chmod 600 "$P"/*/*.key "$P"/*/key.pem
echo "Listo: certificados de prueba en $P"
