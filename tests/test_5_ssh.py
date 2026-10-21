"""Requerimiento: SSH con autenticación, restricción a usuarios autorizados y registro.

Las conexiones SSH reales se prueban entre las dos PC (ver README). Aquí se
valida la configuración y el análisis del log. La muestra sshd_real.log es la
salida real de OpenSSH 9.6 con securecorp.conf aplicado: secadmin entra con su
llave; ana, root, una llave equivocada y un usuario inexistente son rechazados.
"""
from pathlib import Path

from conftest import RAIZ, leer_log
from ssh import ssh_reporte

MUESTRAS = Path(__file__).parent / "muestras"


def test_configuracion_endurecida():
    conf = (RAIZ / "ssh" / "securecorp.conf").read_text()
    for directiva in ("PermitRootLogin no", "PasswordAuthentication no",
                      "PubkeyAuthentication yes", "AllowGroups secureadmins",
                      "MaxAuthTries 3", "LogLevel VERBOSE"):
        assert directiva in conf


def test_reporte_con_log_real_de_openssh():
    eventos = ssh_reporte.analizar((MUESTRAS / "sshd_real.log").read_text().splitlines())
    resumen = {(e["tipo"], e["usuario"]) for e in eventos}
    assert ("ACEPTADO", "secadmin") in resumen                 # autorizado
    assert ("NO_PERMITIDO", "ana") in resumen                  # fuera del grupo
    assert ("NO_PERMITIDO", "root") in resumen
    assert ("FALLIDO", "secadmin") in resumen                  # llave equivocada
    assert ("USUARIO_INVALIDO", "hacker") in resumen
    assert sum(e["tipo"] == "ACEPTADO" for e in eventos) == 1  # nadie más entró


def test_reporte_con_formato_de_ubuntu():
    eventos = ssh_reporte.analizar((MUESTRAS / "auth_ubuntu.log").read_text().splitlines())
    assert [e["tipo"] for e in eventos] == ["ACEPTADO", "NO_PERMITIDO", "USUARIO_INVALIDO",
                                            "FALLIDO"]
    assert eventos[0]["fecha"] == "2026-10-20 03:10:01"
    assert eventos[0]["ip"] == "192.168.1.20"


def test_exportar_a_eventos_log(monkeypatch):
    monkeypatch.setattr("sys.argv", ["ssh_reporte.py", "--archivo",
                                     str(MUESTRAS / "auth_ubuntu.log"), "--exportar"])
    ssh_reporte.main()
    log = leer_log()
    assert "SSH_ACEPTADO | secadmin | 192.168.1.20" in log
    assert "SSH_RECHAZADO | ana | 192.168.1.20" in log
