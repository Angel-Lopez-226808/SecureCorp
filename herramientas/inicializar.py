"""Prepara los datos de SecureCorp: usuarios de ejemplo, CSV de ejemplo y la
llave precompartida del túnel sitio a sitio.

Uso (desde la carpeta securecorp/):
    python3 herramientas/inicializar.py            # crea lo que falte
    python3 herramientas/inicializar.py --forzar   # borra usuarios y los recrea
"""
import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from comun import auth, config  # noqa: E402

USUARIOS_DEMO = [
    ("admin", "admin", "Admin#2026"),
    ("ana", "normal", "Ana#2026!"),
    ("invitado", "invitado", "Invitado#2026"),
]

CSV_DEMO = {
    config.CSV_PUBLICOS / "catalogo_productos.csv":
        "codigo,producto,precio_mxn\nP-100,Servidor 1U,45999\nP-200,Switch 24p,8999\n"
        "P-300,Rack 42U,15499\nP-400,UPS 3kVA,21999\n",
    config.CSV_PUBLICOS / "directorio_sucursales.csv":
        "sucursal,ciudad,telefono\nMatriz,Ciudad Juarez,656-000-0001\n"
        "Sucursal Norte,Chihuahua,614-000-0002\n",
    config.CSV_PRIVADOS / "ventas_q3.csv":
        "mes,region,ventas_mxn\njulio,norte,1250000\nagosto,norte,1310500\n"
        "septiembre,norte,1402300\njulio,centro,980000\n",
    config.CSV_PRIVADOS / "nomina_resumen.csv":
        "departamento,empleados,costo_mensual_mxn\nTI,8,412000\nVentas,12,388000\n"
        "Almacen,6,156000\n",
    config.DATOS_SUCURSAL / "reporte_sucursal.csv":
        "fecha,producto,unidades,total_mxn\n2026-10-19,Servidor 1U,3,137997\n"
        "2026-10-19,UPS 3kVA,2,43998\n2026-10-20,Switch 24p,5,44995\n",
}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--forzar", action="store_true", help="recrear usuarios.json")
    args = ap.parse_args()

    for carpeta in (config.CSV_PUBLICOS, config.CSV_PRIVADOS, config.CSV_SUCURSAL,
                    config.DATOS_SUCURSAL, config.LOGS, config.CONFIG):
        carpeta.mkdir(parents=True, exist_ok=True)

    if args.forzar and config.USUARIOS_JSON.exists():
        config.USUARIOS_JSON.unlink()
    existentes = {u["usuario"] for u in auth.listar_usuarios()}
    for nombre, rol, password in USUARIOS_DEMO:
        if nombre not in existentes:
            auth.crear_usuario(nombre, rol, password)
            print(f"  usuario creado: {nombre:<9} rol={rol:<9} contraseña={password}")

    for ruta, contenido in CSV_DEMO.items():
        if not ruta.exists():
            ruta.write_text(contenido, encoding="utf-8")
            print(f"  CSV de ejemplo: {ruta.relative_to(config.DATOS)}")

    if not config.PSK_SITIO.exists():
        config.PSK_SITIO.write_text(os.urandom(32).hex() + "\n")
        os.chmod(config.PSK_SITIO, 0o600)
        print(f"  llave precompartida sitio a sitio: {config.PSK_SITIO}")

    print("Datos listos. Cambia las contraseñas de ejemplo si vas a exponer el servidor.")


if __name__ == "__main__":
    main()
