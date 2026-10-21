#!/usr/bin/env bash
# =============================================================================
#  Configura el acceso administrativo por SSH de SecureCorp (en la VM Ubuntu).
#
#  ANTES de correrlo, en la PC cliente:
#     ssh-keygen -t ed25519
#     scp ~/.ssh/id_ed25519.pub TU_USUARIO@servidor.securecorp.local:/tmp/admin.pub
#       (en Windows: scp $env:USERPROFILE\.ssh\id_ed25519.pub ...)
#
#  Luego, en la VM:
#     sudo bash ssh/configurar_ssh.sh /tmp/admin.pub
#
#  Qué hace:
#   - crea el grupo secureadmins y el usuario secadmin (miembro del grupo)
#   - crea el usuario ana FUERA del grupo, para demostrar el rechazo
#   - agrega TU usuario actual al grupo (para que no te quedes fuera)
#   - instala la llave pública para secadmin y para tu usuario
#   - instala securecorp.conf, lo valida con sshd -t y reinicia SSH
#  Deja abierta la consola de VirtualBox por si algo sale mal.
# =============================================================================
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Ejecuta con sudo: sudo bash $0 /ruta/a/llave.pub"; exit 1
fi
LLAVE="${1:-}"
if [[ -z "$LLAVE" || ! -f "$LLAVE" ]]; then
  echo "Falta la llave pública. Uso: sudo bash $0 /tmp/admin.pub"
  echo "Sin una llave instalada NO se desactivan las contraseñas (te quedarías fuera)."
  exit 1
fi
if ! grep -qE '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-)' "$LLAVE"; then
  echo "El archivo $LLAVE no parece una llave pública SSH"; exit 1
fi
AQUI="$(cd "$(dirname "$0")" && pwd)"
YO="${SUDO_USER:-}"

instalar_llave() {   # $1 = usuario
  local home; home="$(getent passwd "$1" | cut -d: -f6)"
  install -d -m 700 -o "$1" -g "$1" "$home/.ssh"
  touch "$home/.ssh/authorized_keys"
  grep -qxF "$(cat "$LLAVE")" "$home/.ssh/authorized_keys" || cat "$LLAVE" >> "$home/.ssh/authorized_keys"
  chown "$1:$1" "$home/.ssh/authorized_keys"; chmod 600 "$home/.ssh/authorized_keys"
}

echo "==> grupo y usuarios"
groupadd -f secureadmins
id secadmin &>/dev/null || adduser --disabled-password --gecos "SecureCorp admin" secadmin >/dev/null
usermod -aG secureadmins secadmin
id ana &>/dev/null || adduser --disabled-password --gecos "Usuaria sin acceso SSH" ana >/dev/null
gpasswd -d ana secureadmins &>/dev/null || true
if [[ -n "$YO" && "$YO" != "root" ]]; then
  usermod -aG secureadmins "$YO"
  instalar_llave "$YO"
  echo "    $YO agregado a secureadmins (para que no pierdas el acceso)"
fi
instalar_llave secadmin

echo "==> configuración de sshd"
install -m 644 "$AQUI/securecorp.conf" /etc/ssh/sshd_config.d/securecorp.conf
sshd -t
systemctl restart ssh 2>/dev/null || systemctl restart sshd
echo
echo "Listo. Pruebas desde la PC cliente:"
echo "   ssh secadmin@servidor.securecorp.local     -> debe entrar con la llave"
echo "   ssh ana@servidor.securecorp.local          -> rechazado (no está en secureadmins)"
echo "   ssh root@servidor.securecorp.local         -> rechazado (PermitRootLogin no)"
echo "   ssh -i otra_llave secadmin@...             -> rechazado (llave no autorizada)"
echo "Intentos registrados: sudo python3 ssh/ssh_reporte.py"
