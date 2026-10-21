#!/usr/bin/env bash
# Levanta en segundo plano todos los servicios de SecureCorp en la VM:
#   servidor plano (5000), servidor TLS (5443), gateway VPN (6443),
#   gateway matriz sitio a sitio (7500/udp).
# Uso (desde la carpeta securecorp/, con el venv activado):
#   bash scripts/iniciar_servidor.sh
#   bash scripts/detener_servidor.sh
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p run logs

if [[ ! -f pki/certs/fullchain.pem ]]; then
  echo "Falta la PKI. Corre primero: bash pki/generar_pki.sh"; exit 1
fi
[[ -f datos/usuarios.json ]] || python3 herramientas/inicializar.py

iniciar() {   # $1 = nombre, resto = comando
  local nombre="$1"; shift
  if [[ -f "run/$nombre.pid" ]] && kill -0 "$(cat "run/$nombre.pid")" 2>/dev/null; then
    echo "  $nombre ya está corriendo (pid $(cat "run/$nombre.pid"))"; return
  fi
  nohup "$@" > "logs/$nombre.out" 2>&1 &
  echo $! > "run/$nombre.pid"
  echo "  $nombre iniciado (pid $!), salida en logs/$nombre.out"
}

iniciar servidor_plano python3 servidor/servidor_app.py --plano
iniciar servidor_tls   python3 servidor/servidor_app.py --tls
sleep 1
iniciar gateway_vpn    python3 vpn/gateway.py
iniciar matriz         python3 vpn/sitio_a_sitio.py --rol matriz
sleep 1
echo
echo "Puertos abiertos:"
ss -tulnp 2>/dev/null | grep -E ':(5000|5443|6443|7500)\b' || echo "  (instala iproute2 para ver puertos con ss)"
echo
echo "Eventos en vivo: tail -f logs/eventos.log"
