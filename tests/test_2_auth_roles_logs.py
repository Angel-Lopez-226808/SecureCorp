"""Requerimiento: autenticación, autorización por rol y registro de eventos."""
import base64
import json
import time

import pytest

from comun import auth, config
from conftest import PASSWORDS, leer_log


def test_contrasenas_guardadas_como_hash():
    contenido = config.USUARIOS_JSON.read_text()
    for pw in PASSWORDS.values():
        assert pw not in contenido
    datos = json.loads(contenido)["usuarios"]["ana"]
    assert len(datos["sal"]) == 32 and len(datos["hash"]) == 64


def test_login_correcto_e_incorrecto(servidor_tls, conectar):
    c = conectar(servidor_tls.puerto)
    r = c.login("ana", "equivocada")
    assert not r["ok"] and "incorrectos" in r["error"]
    assert "LOGIN_FALLIDO | ana" in leer_log()
    assert c.login("ana", PASSWORDS["ana"])["ok"]
    assert "LOGIN_OK | ana" in leer_log()


def test_sin_login_no_hay_acceso(servidor_tls, conectar):
    c = conectar(servidor_tls.puerto)
    r = c.pedir("csv_listar")
    assert not r["ok"] and "inicia sesión" in r["error"]


def test_bloqueo_tras_intentos_fallidos(servidor_tls, conectar):
    auth.crear_usuario("bloqueo_test", "normal", "Correcta#123")
    c = conectar(servidor_tls.puerto)
    for _ in range(config.MAX_INTENTOS_LOGIN):
        assert not c.login("bloqueo_test", "mala")["ok"]
    r = c.login("bloqueo_test", "Correcta#123")    # aun con la buena: bloqueada
    assert not r["ok"] and "bloqueada" in r["error"]
    assert "BLOQUEADO | bloqueo_test" in leer_log()


# Autenticarse NO da acceso a todo: cada comando se autoriza por rol.
MATRIZ = [
    # comando,          datos,                                    admin, normal, invitado
    ("quien",           {},                                        True,  True,  True),
    ("chat",            {"texto": "hola"},                         True,  True,  False),
    ("csv_listar",      {},                                        True,  True,  True),
    ("csv_descargar",   {"nombre": "catalogo_productos.csv"},      True,  True,  True),
    ("csv_descargar",   {"nombre": "ventas_q3.csv"},               True,  True,  False),
    ("logs_ver",        {"n": 5},                                  True,  False, False),
    ("logs_filtrar",    {"tipo": "DENEGADO"},                      True,  False, False),
    ("sesiones",        {},                                        True,  False, False),
    ("usuarios_listar", {},                                        True,  False, False),
]


@pytest.mark.parametrize("rol_idx, usuario", [(0, "admin"), (1, "ana"), (2, "invitado")])
def test_matriz_de_permisos(servidor_tls, conectar, rol_idx, usuario):
    c = conectar(servidor_tls.puerto, usuario=usuario)
    for cmd, datos, *esperado in MATRIZ:
        r = c.pedir(cmd, **datos)
        assert r["ok"] == esperado[rol_idx], (usuario, cmd, datos, r)
        if not esperado[rol_idx]:
            assert "ACCESO DENEGADO" in r["error"]


def test_invitado_no_ve_csv_privados_en_la_lista(servidor_tls, conectar):
    c = conectar(servidor_tls.puerto, usuario="invitado")
    tipos = {a["tipo"] for a in c.pedir("csv_listar")["archivos"]}
    assert tipos == {"publico"}


def test_subir_csv(servidor_tls, conectar):
    ana = conectar(servidor_tls.puerto, usuario="ana")
    contenido = base64.b64encode(b"a,b\n1,2\n").decode()
    r = ana.pedir("csv_subir", nombre="prueba_subida.csv", contenido=contenido)
    assert r["ok"] and (config.CSV_PRIVADOS / "prueba_subida.csv").exists()
    # Un nombre con ruta no puede escapar de la carpeta
    r = ana.pedir("csv_subir", nombre="../../escape_test.csv", contenido=contenido)
    assert r["ok"] and r["nombre"] == "escape_test.csv"
    assert not (config.DATOS / "escape_test.csv").exists()
    assert (config.CSV_PRIVADOS / "escape_test.csv").exists()
    # Solo CSV
    r = ana.pedir("csv_subir", nombre="virus.exe", contenido=contenido)
    assert not r["ok"]
    # El invitado no puede subir
    inv = conectar(servidor_tls.puerto, usuario="invitado")
    assert not inv.pedir("csv_subir", nombre="x.csv", contenido=contenido)["ok"]


def test_chat_solo_llega_a_quien_tiene_permiso(servidor_tls, conectar):
    ana = conectar(servidor_tls.puerto, usuario="ana")
    admin = conectar(servidor_tls.puerto, usuario="admin")
    inv = conectar(servidor_tls.puerto, usuario="invitado")
    assert ana.pedir("chat", texto="hola equipo")["ok"]
    time.sleep(0.3)
    ev = admin.eventos.get(timeout=2)
    assert ev["evento"] == "chat" and ev["de"] == "ana" and ev["texto"] == "hola equipo"
    assert inv.eventos.empty()


def test_admin_crea_usuario_y_queda_registrado(servidor_tls, conectar):
    admin = conectar(servidor_tls.puerto, usuario="admin")
    r = admin.pedir("usuarios_crear", nombre="pedro", rol="invitado", password="Pedro#2026")
    assert r["ok"]
    assert "ADMIN | admin" in leer_log() and "usuarios_crear pedro" in leer_log()
    assert conectar(servidor_tls.puerto, usuario="pedro", password="Pedro#2026")


def test_logs_registran_conexiones_permitidos_y_denegados(servidor_tls, conectar):
    inv = conectar(servidor_tls.puerto, usuario="invitado")
    inv.pedir("chat", texto="intento")
    inv.pedir("csv_descargar", nombre="catalogo_productos.csv")
    admin = conectar(servidor_tls.puerto, usuario="admin")
    denegados = admin.pedir("logs_filtrar", tipo="DENEGADO")["lineas"]
    assert any("invitado" in l and "chat" in l for l in denegados)
    log = leer_log()
    for tipo in ("CONEXION", "LOGIN_OK", "PERMITIDO", "DENEGADO", "ADMIN"):
        assert f"| {tipo} |" in log
