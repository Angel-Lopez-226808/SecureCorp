"""Resumen de los intentos de conexión SSH registrados por el sistema.

Uso (en la VM):
    sudo python3 ssh/ssh_reporte.py                  # lee /var/log/auth.log o journalctl
    sudo python3 ssh/ssh_reporte.py --exportar       # además los copia a logs/eventos.log
    python3 ssh/ssh_reporte.py --archivo muestra.log # analiza un archivo concreto
"""
import argparse
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from comun import logger  # noqa: E402

PATRONES = [
    ("ACEPTADO", re.compile(r"Accepted (?P<metodo>\S+) for (?P<usuario>\S+) from (?P<ip>\S+) port")),
    ("NO_PERMITIDO", re.compile(r"User (?P<usuario>\S+) from (?P<ip>\S+) not allowed because (?P<motivo>.+)")),
    ("USUARIO_INVALIDO", re.compile(r"Invalid user (?P<usuario>\S+) from (?P<ip>\S+)")),
    ("FALLIDO", re.compile(r"Failed (?P<metodo>\S+) for (?:invalid user )?(?P<usuario>\S+) from (?P<ip>\S+) port")),
    ("MAX_INTENTOS", re.compile(r"maximum authentication attempts exceeded for (?:invalid user )?(?P<usuario>\S+) from (?P<ip>\S+)")),
    ("ROOT_RECHAZADO", re.compile(r"ROOT LOGIN REFUSED FROM (?P<ip>\S+)")),
    ("SIN_AUTENTICAR", re.compile(r"Connection closed by authenticating user (?P<usuario>\S+) "
                                  r"(?P<ip>\S+) port \d+ \[preauth\]")),
]
_MESES = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def analizar(lineas) -> list:
    eventos = []
    for linea in lineas:
        for tipo, patron in PATRONES:
            m = patron.search(linea)
            if m:
                partes = linea.split()
                if partes[0][:4].isdigit() and "T" in partes[0]:      # 2026-10-20T03:00:00
                    fecha = partes[0][:19].replace("T", " ")
                elif partes[0] in _MESES:                              # Oct 20 03:00:00
                    fecha = " ".join(partes[:3])
                else:                                                  # sshd -E (sin fecha)
                    fecha = "-"
                d = m.groupdict()
                eventos.append({"fecha": fecha, "tipo": tipo, "usuario": d.get("usuario", "root"),
                                "ip": d.get("ip", "-"),
                                "detalle": d.get("motivo") or d.get("metodo") or ""})
                break
    return eventos


def leer_fuente(archivo: Path = None) -> list:
    if archivo:
        return archivo.read_text(errors="replace").splitlines()
    auth_log = Path("/var/log/auth.log")
    if auth_log.exists():
        return auth_log.read_text(errors="replace").splitlines()
    try:
        salida = subprocess.run(["journalctl", "-u", "ssh", "-u", "sshd", "--no-pager",
                                 "-o", "short-iso"], capture_output=True, text=True, check=False)
        return salida.stdout.splitlines()
    except FileNotFoundError:
        sys.exit("No encontré /var/log/auth.log ni journalctl")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--archivo", type=Path)
    ap.add_argument("--exportar", action="store_true",
                    help="agrega los eventos a logs/eventos.log (SSH_ACEPTADO / SSH_RECHAZADO)")
    a = ap.parse_args()

    eventos = analizar(leer_fuente(a.archivo))
    if not eventos:
        print("No hay intentos de SSH registrados (¿corriste con sudo?)")
        return
    print(f"{'FECHA':<26} {'RESULTADO':<17} {'USUARIO':<12} {'IP':<16} DETALLE")
    for e in eventos:
        print(f"{e['fecha']:<26} {e['tipo']:<17} {e['usuario']:<12} {e['ip']:<16} {e['detalle']}")
    print("\nResumen:")
    for (tipo, usuario), n in sorted(Counter((e["tipo"], e["usuario"]) for e in eventos).items()):
        print(f"  {tipo:<17} {usuario:<12} {n} vez/veces")
    if a.exportar:
        for e in eventos:
            logger.registrar("SSH_ACEPTADO" if e["tipo"] == "ACEPTADO" else "SSH_RECHAZADO",
                             "ssh", f"{e['tipo']} {e['detalle']} ({e['fecha']})".strip(),
                             usuario=e["usuario"], ip=e["ip"])
        print(f"\n{len(eventos)} eventos copiados a logs/eventos.log")


if __name__ == "__main__":
    main()
