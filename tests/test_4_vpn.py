"""Requerimientos: VPN de acceso remoto con acceso limitado por rol, y VPN sitio a sitio."""
import os
import time

from comun import config
from conftest import PASSWORDS, leer_log
from vpn.gateway import GatewayVPN
from vpn.sitio_a_sitio import GatewayMatriz, enviar_reporte


# ------------------------------------------------------- acceso remoto
def test_conexion_vpn_asigna_ip_virtual_y_recursos_por_rol(gateway, conectar):
    esperados = {"admin": 7, "ana": 4, "invitado": 1}
    for usuario, n in esperados.items():
        c = conectar(gateway.puerto, "vpn")
        r = c.login(usuario, PASSWORDS[usuario])
        assert r["ok"] and r["ip_virtual"].startswith("10.8.0.")
        assert len(r["recursos"]) == n and r["token"]
    assert "VPN_CONECTADO | invitado" in leer_log()


def test_vpn_rechaza_credenciales_incorrectas(gateway, conectar):
    c = conectar(gateway.puerto, "vpn")
    r = c.login("ana", "no-es-esta")
    assert not r["ok"]
    assert "[gateway] VPN: usuario o contraseña incorrectos" in leer_log()


def test_vpn_no_da_acceso_ilimitado_al_invitado(gateway, conectar):
    c = conectar(gateway.puerto, "vpn", usuario="invitado")
    # Lo bloquea el gateway: la petición ni siquiera llega a la red interna
    for cmd, datos in (("chat", {"texto": "hola"}), ("csv_subir", {"nombre": "x.csv"}),
                       ("logs_ver", {}), ("sesiones", {})):
        r = c.pedir(cmd, **datos)
        assert not r["ok"] and "ACCESO DENEGADO" in r["error"], cmd
    assert "no llega a la red interna" in leer_log()
    # CSV privado: el gateway lo deja pasar (es "un CSV"), el servidor lo frena
    r = c.pedir("csv_descargar", nombre="nomina_resumen.csv")
    assert not r["ok"] and "csv_privados" in r["error"]
    # Lo que sí le corresponde funciona
    assert c.pedir("csv_descargar", nombre="catalogo_productos.csv")["ok"]


def test_usuario_normal_por_vpn(gateway, conectar):
    c = conectar(gateway.puerto, "vpn", usuario="ana")
    assert c.pedir("chat", texto="hola desde casa")["ok"]
    assert c.pedir("csv_descargar", nombre="ventas_q3.csv")["ok"]
    assert not c.pedir("logs_ver")["ok"]


def test_admin_ve_sesiones_vpn(gateway, conectar):
    conectar(gateway.puerto, "vpn", usuario="ana")
    admin = conectar(gateway.puerto, "vpn", usuario="admin")
    sesiones = admin.pedir("sesiones")["sesiones"]
    assert any(s["usuario"] == "ana" and "(vpn)" in s["origen"] for s in sesiones)


def test_token_de_sesion_invalido_es_rechazado(gateway, conectar):
    c = conectar(gateway.puerto, "vpn", usuario="ana")
    c.token = "0" * 32
    r = c.pedir("csv_listar")
    assert not r["ok"] and "token" in r["error"]


def test_sesion_vpn_expira(servidor_tls, conectar):
    gw = GatewayVPN("127.0.0.1", 0, "127.0.0.1", servidor_tls.puerto,
                    duracion_min=0.01).iniciar()       # 0.6 segundos
    try:
        c = conectar(gw.puerto, "vpn", usuario="ana")
        assert c.pedir("csv_listar")["ok"]
        time.sleep(1)
        r = c.pedir("csv_listar")
        assert not r["ok"] and "expiró" in r["error"]
        assert "VPN_EXPIRADA | ana" in leer_log()
    finally:
        gw.detener()


def test_ip_virtual_se_libera_al_desconectar(gateway, conectar):
    c = conectar(gateway.puerto, "vpn", usuario="invitado")
    ip = c.pedir("quien")["ip_vpn"]
    c.cerrar()
    time.sleep(0.5)
    assert ip not in gateway.activas
    assert f"IP virtual {ip} liberada" in leer_log()


# --------------------------------------------------------- sitio a sitio
def test_sitio_a_sitio_envia_reporte_por_el_tunel():
    matriz = GatewayMatriz("127.0.0.1", 0).iniciar()
    try:
        archivo = config.DATOS_SUCURSAL / "reporte_sucursal.csv"
        r = enviar_reporte("127.0.0.1", matriz.puerto, archivo, verbose=False)
        assert r["ok"] and r["confirmacion"]["recibido"] == "reporte_sucursal.csv"
        time.sleep(0.2)
        guardado = config.CSV_SUCURSAL / "reporte_sucursal.csv"
        assert guardado.read_bytes() == archivo.read_bytes()
        log = leer_log()
        assert "IKE_OK" in log and "SITIO_A_SITIO" in log
    finally:
        matriz.detener()


def test_sitio_a_sitio_no_usa_usuarios_sino_llave_entre_gateways():
    matriz = GatewayMatriz("127.0.0.1", 0).iniciar()
    try:
        antes = leer_log().count("LOGIN_")
        r = enviar_reporte("127.0.0.1", matriz.puerto, config.DATOS_SUCURSAL /
                           "reporte_sucursal.csv", psk=os.urandom(32), verbose=False,
                           impostor=True)
        assert not r["ok"]
        time.sleep(0.2)
        assert ("IKE_FALLIDO", "127.0.0.1") in matriz.rechazos
        assert leer_log().count("LOGIN_") == antes      # nunca hubo login de usuario
    finally:
        matriz.detener()


def test_sitio_a_sitio_detecta_replay():
    matriz = GatewayMatriz("127.0.0.1", 0).iniciar()
    try:
        enviar_reporte("127.0.0.1", matriz.puerto, config.DATOS_SUCURSAL /
                       "reporte_sucursal.csv", replay=True, verbose=False)
        time.sleep(0.3)
        assert any(t == "REPLAY" for t, _ in matriz.rechazos)
    finally:
        matriz.detener()
