"""Autorización: qué puede hacer cada rol.

Autenticar = comprobar QUIÉN eres (login, una vez).
Autorizar  = comprobar si PUEDES hacer algo (en cada comando).

Esta ACL es la única fuente de verdad: la consultan el gateway VPN y el
servidor, así que un permiso se cambia en un solo lugar.
"""

ROLES = ("admin", "normal", "invitado")

PERMISOS = {
    "chat":         "Enviar y recibir mensajes de chat",
    "csv_publicos": "Listar y descargar CSV públicos",
    "csv_privados": "Listar y descargar CSV privados",
    "csv_subir":    "Subir CSV",
    "logs":         "Ver y filtrar el registro de eventos",
    "sesiones":     "Ver las sesiones activas",
    "usuarios":     "Listar y crear usuarios",
}

ACL = {
    "admin":    set(PERMISOS),
    "normal":   {"chat", "csv_publicos", "csv_privados", "csv_subir"},
    "invitado": {"csv_publicos"},
}

# Permiso mínimo que exige cada comando del protocolo.
# None = no requiere permiso (solo estar autenticado).
PERMISO_POR_COMANDO = {
    "quien":           None,
    "salir":           None,
    "chat":            "chat",
    "csv_listar":      "csv_publicos",
    "csv_descargar":   "csv_publicos",   # los privados los revisa el servidor
    "csv_subir":       "csv_subir",
    "logs_ver":        "logs",
    "logs_filtrar":    "logs",
    "sesiones":        "sesiones",
    "usuarios_listar": "usuarios",
    "usuarios_crear":  "usuarios",
}


def autorizar(rol: str, permiso) -> bool:
    if permiso is None:
        return True
    return permiso in ACL.get(rol, set())


def permisos_de(rol: str) -> list:
    return sorted(ACL.get(rol, set()))


def comando_valido(cmd: str) -> bool:
    return cmd in PERMISO_POR_COMANDO
