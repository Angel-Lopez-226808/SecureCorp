# SecureCorp — Infraestructura de comunicaciones seguras

Proyecto de la materia de Seguridad de la Información. Simula la red de una pequeña
empresa con **matriz** y **sucursal**, donde los empleados chatean e intercambian
archivos CSV. Cada tipo de comunicación usa el mecanismo de seguridad que le corresponde.

| Mecanismo | En el proyecto | Qué protege o resuelve |
|---|---|---|
| TLS | **Real** (`ssl` de Python / OpenSSL) | La sesión cliente-servidor |
| Certificados y PKI | **Reales** (OpenSSL) | La identidad del servidor (cadena raíz → intermedia → servidor) |
| SSH | **Real** (OpenSSH) | La administración remota del servidor |
| IPSec ESP | Simulado (AES-256-GCM real + ventana anti-replay del RFC 4303) | Tráfico entre equipos o redes; modos transporte y túnel |
| VPN de acceso remoto | Simulada | La entrada de un usuario externo, con acceso limitado por rol |
| VPN sitio a sitio | Simulada (IKE con PSK + IPSec modo túnel) | La unión permanente entre la red matriz y la red sucursal |

---

## 1. Arquitectura

```
   PC CLIENTE                                VM SERVIDOR (Ubuntu Server 26.04)
 ┌──────────────┐                ┌──────────────────────────────────────────────────┐
 │ cliente.py   │── VPN: TLS ───▶│ gateway.py :6443  ── autentica, IP 10.8.0.x, ACL │
 │ (usuario o   │   + login      │        │ (solo si la ACL lo permite, por TLS)    │
 │  invitado)   │                │        ▼                                         │
 │              │── TLS :5443 ──▶│ servidor_app.py  :5443 TLS / :5000 plano          │
 │              │── plano :5000 ▶│   chat · CSV · logs · usuarios                    │
 │ Wireshark    │                │        ▲                    ▲                     │
 │              │                │        │ entrega reporte    │ firma el cert       │
 │ admin (llave)│── SSH :22 ────▶│ OpenSSH (solo grupo     CA raíz + intermedia      │
 └──────────────┘                │   secureadmins)         (OpenSSL)                 │
                                 │        ▲                                         │
                                 │ sitio_a_sitio.py --rol matriz  :7500/udp          │
                                 └────────┼─────────────────────────────────────────┘
                                          │ túnel IPSec (modo túnel, anti-replay, PSK)
                                 ┌────────┴──────────────┐
                                 │ RED SUCURSAL 10.2.0.0/24
                                 │ sitio_a_sitio.py --rol sucursal
                                 └───────────────────────┘
```

| Componente | Equipo | Puerto | Función |
|---|---|---|---|
| `servidor/servidor_app.py --plano` | VM | 5000/tcp | Chat y CSV **sin cifrar**; solo para comparar en Wireshark |
| `servidor/servidor_app.py --tls` | VM | 5443/tcp | Chat y CSV sobre TLS |
| `vpn/gateway.py` | VM | 6443/tcp | VPN de acceso remoto: autentica, asigna IP virtual, filtra por rol |
| `vpn/sitio_a_sitio.py --rol matriz` | VM | 7500/udp | Extremo matriz del túnel IPSec sitio a sitio |
| OpenSSH | VM | 22/tcp | Administración remota, solo grupo `secureadmins` |
| `pki/` (OpenSSL) | VM | — | CA raíz, CA intermedia y certificados |
| `cliente/cliente.py` | PC cliente | — | Consola del usuario |

**Protocolo.** Cliente y servidor intercambian líneas JSON (`{"id": 3, "cmd": "chat", "texto": "hola"}`).
Es el mismo formato en modo plano, TLS y VPN, así que en Wireshark la única diferencia es el cifrado.

**Estructura del código**

```
securecorp/
├── comun/        config.py, protocolo.py, tls.py, auth.py, roles.py, logger.py
├── pki/          generar_pki.sh, generar_certs_prueba.sh, generar_cert_expirado.py
├── servidor/     servidor_app.py
├── cliente/      cliente.py
├── ipsec/        ipsec_sim.py, demo_ipsec.py
├── vpn/          gateway.py, sitio_a_sitio.py
├── ssh/          securecorp.conf, configurar_ssh.sh, ssh_reporte.py
├── herramientas/ inicializar.py
├── scripts/      iniciar_servidor.sh, detener_servidor.sh
└── tests/        pruebas pytest (45 casos)
```

---

## 2. Instalación

### VM servidor (Ubuntu Server)

```bash
sudo apt update && sudo apt install -y python3-venv python3-pip openssl git
cd ~/securecorp                       # la carpeta del proyecto
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

bash pki/generar_pki.sh               # 1) CA raíz, intermedia y certificado del servidor
bash pki/generar_certs_prueba.sh      # 2) certificados "malos" para las pruebas de rechazo
python3 herramientas/inicializar.py   # 3) usuarios, CSV de ejemplo y llave PSK

sudo ufw allow OpenSSH
sudo ufw allow 5000/tcp && sudo ufw allow 5443/tcp && sudo ufw allow 6443/tcp
sudo ufw allow 7500/udp               # solo si haces la demo IPSec entre dos equipos
sudo ufw enable
```

### PC cliente (Windows, Linux o Mac)

1. Copia la carpeta del proyecto (con `git clone` o un zip). El cliente solo usa `cliente/` y `comun/`.
2. Copia **solo** `pki/certs/ca.crt` desde la VM a `pki/certs/ca.crt` del cliente:
   `scp tuusuario@IP_VM:securecorp/pki/certs/ca.crt pki/certs/`
3. Instala dependencias: `python -m venv venv`, actívalo y `pip install -r requirements.txt`.
4. Agrega al archivo hosts la línea `IP_DE_LA_VM  servidor.securecorp.local`
   (Windows: `C:\Windows\System32\drivers\etc\hosts` como administrador; Linux/Mac: `/etc/hosts`).
   Alternativa sin hosts: usa `--host IP_DE_LA_VM`; el certificado se sigue validando contra el nombre.
5. Instala Wireshark.

> En Windows usa `python` en lugar de `python3`.

### Usuarios de ejemplo

| Usuario | Rol | Contraseña |
|---|---|---|
| `admin` | admin | `Admin#2026` |
| `ana` | normal | `Ana#2026!` |
| `invitado` | invitado | `Invitado#2026` |

Las contraseñas se guardan como hash `scrypt` con sal en `datos/usuarios.json`; nunca en texto plano.

---

## 3. Ejecución

### Levantar todo en la VM

```bash
source venv/bin/activate
bash scripts/iniciar_servidor.sh      # servidor plano, servidor TLS, gateway VPN y gateway matriz
tail -f logs/eventos.log              # eventos en vivo (otra terminal)
bash scripts/detener_servidor.sh      # para apagar
```

También puedes correr cada uno en su propia terminal, por ejemplo `python3 servidor/servidor_app.py --tls`.

### Conectarse desde la PC cliente

```bash
python3 cliente/cliente.py --vpn                 # uso normal: por la VPN de acceso remoto
python3 cliente/cliente.py --tls                 # directo con TLS (demo)
python3 cliente/cliente.py --plano               # directo SIN cifrar (demo)
```

### Comandos de la consola

| Comando | Admin | Normal | Invitado |
|---|:-:|:-:|:-:|
| `quien` — usuario, rol, IP real e IP VPN | ✓ | ✓ | ✓ |
| `chat` — sala de chat (`/salir` para volver) | ✓ | ✓ | ✗ |
| `csv listar` | ✓ | ✓ | solo públicos |
| `csv descargar <archivo>` — guarda en `./descargas` y muestra vista previa | ✓ | ✓ | solo públicos |
| `csv subir <ruta.csv>` — máx. 1 MB, se guarda como privado | ✓ | ✓ | ✗ |
| `logs ver [n]` / `logs filtrar <TIPO> [n]` | ✓ | ✗ | ✗ |
| `sesiones` — usuarios conectados | ✓ | ✗ | ✗ |
| `usuarios listar` / `usuarios crear <nombre> <rol>` | ✓ | ✗ | ✗ |
| SSH al servidor (`ssh secadmin@servidor.securecorp.local`) | ✓ | ✗ | ✗ |

### Registro de eventos

Todo queda en `logs/eventos.log` con el formato `fecha | TIPO | usuario | ip | [componente] detalle`:

```
2026-10-20 03:06:09 | VPN_CONECTADO | invitado | 192.168.1.20 | [gateway] rol invitado, IP virtual 10.8.0.10, recursos csv_publicos
2026-10-20 03:06:09 | DENEGADO | invitado | 10.8.0.10 | [gateway] rol invitado sin permiso chat (cmd chat); no llega a la red interna
2026-10-20 03:06:09 | DENEGADO | invitado | 10.8.0.10 (vpn) | [servidor] rol invitado sin permiso csv_privados (cmd csv_descargar)
2026-10-20 03:06:39 | ADMIN | admin | 10.8.0.11 (vpn) | [servidor] usuarios_crear pedro rol invitado
```

Tipos: `CONEXION`, `DESCONEXION`, `LOGIN_OK`, `LOGIN_FALLIDO`, `BLOQUEADO`, `PERMITIDO`, `DENEGADO`,
`ADMIN`, `CERT_RECHAZADO` (en `logs/cliente.log`), `TLS_ERROR`, `VPN_CONECTADO`, `VPN_DESCONECTADO`,
`VPN_EXPIRADA`, `IPSEC_OK`, `REPLAY`, `INTEGRIDAD`, `IKE_OK`, `IKE_FALLIDO`, `SITIO_A_SITIO`,
`SSH_ACEPTADO`, `SSH_RECHAZADO`.

---

## 4. Función de cada mecanismo

### TLS
Protege la **sesión** entre el cliente y el servidor: confidencialidad (nadie lee lo que viaja),
integridad (nadie lo modifica) y autenticación del servidor. El servidor exige mínimo TLS 1.2 y en la
práctica negocia TLS 1.3 con `TLS_AES_256_GCM_SHA384`. Al conectar, el cliente muestra la versión,
el cifrado y la cadena validada. Si el certificado no es confiable, **corta antes de enviar un solo byte**.

### PKI y cadena de confianza
`pki/generar_pki.sh` crea tres eslabones con OpenSSL:

```
SecureCorp Root CA  (ca.crt, 10 años, la única en la que confía el cliente)
   └── SecureCorp Intermediate CA  (inter.crt, pathlen:0: no puede crear más CAs)
          └── servidor.securecorp.local  (servidor.crt, 90 días, serverAuth, SAN)
```

El servidor presenta `fullchain.pem` (su certificado + la intermedia). El cliente solo tiene
`ca.crt` y reconstruye la cadena: firma de la intermedia por la raíz, firma del servidor por la
intermedia, fechas vigentes y nombre correcto. La llave de la raíz nunca sale de la VM.

| Certificado de prueba | Por qué se rechaza |
|---|---|
| `autofirmado` | Nadie da fe de él (`self-signed certificate`) |
| `ca_falsa` | Lo firmó una CA que se llama igual pero no es la nuestra (`unable to get local issuer certificate`) |
| `nombre_incorrecto` | Es válido, pero para `otro.securecorp.local` (`Hostname mismatch`) |
| `expirado` | Firmado por nuestra CA, pero venció (`certificate has expired`) |
| `sin_intermedia` | El certificado bueno sin la intermedia: la cadena no llega a la raíz |

### SSH
Acceso administrativo real con OpenSSH (`ssh/securecorp.conf`):
- **Autenticación:** solo llave pública (`PasswordAuthentication no`); nada de contraseñas.
- **Restricción:** `AllowGroups secureadmins` y `PermitRootLogin no`; `ana` existe en el sistema pero no puede entrar.
- **Registro:** `LogLevel VERBOSE` (incluye la huella de la llave). `ssh/ssh_reporte.py` resume los intentos
  y con `--exportar` los copia a `logs/eventos.log`.

### IPSec (simulado)
`ipsec/ipsec_sim.py` implementa el formato ESP: SPI, número de secuencia y contenido cifrado con
AES-256-GCM. El encabezado ESP va autenticado (AAD), así que no se puede alterar la secuencia.
- **Modo transporte:** el IP original queda visible; solo se cifran los datos. Para comunicación equipo a equipo.
- **Modo túnel:** se cifra el paquete completo y se antepone un IP nuevo entre gateways. Quien captura
  solo ve `10.2.0.1 -> 10.1.0.1`; las IPs internas quedan ocultas. Para unir redes.
- **Anti-replay:** ventana deslizante de 64 posiciones (RFC 4303). Rechaza números repetidos o demasiado
  viejos. La ventana solo avanza después de verificar la integridad, para que un paquete falso no la mueva.

### VPN de acceso remoto (simulada)
`vpn/gateway.py` es la puerta de entrada de un usuario externo:
1. TLS con el cliente (validando el certificado).
2. **Autenticación** del usuario (3 intentos, bloqueo tras 5 fallos).
3. IP virtual del pool `10.8.0.10–50` y token de sesión que vence a los 30 min.
4. **Autorización en cada petición**: si el rol no tiene el permiso, la petición **no llega a la red interna**.
5. El tramo gateway → servidor también va por TLS validado, y el servidor vuelve a revisar el rol
   (defensa en profundidad: el gateway sabe que pides "un CSV"; el servidor sabe si ese CSV es privado).

### VPN sitio a sitio (simulada)
`vpn/sitio_a_sitio.py` une la red sucursal `10.2.0.0/24` con la matriz `10.1.0.0/24`:
- **No hay usuarios ni login.** Se autentican los **gateways** con una llave precompartida (PSK),
  mediante un intercambio tipo IKE: nonces + HMAC. Un gateway impostor es rechazado (`IKE_FALLIDO`).
- Las llaves AES de cada sentido se derivan con HKDF a partir de la PSK y los nonces: son nuevas en cada conexión.
- Todo el tráfico va en IPSec **modo túnel**. La sucursal envía `reporte_sucursal.csv`; la matriz lo guarda
  en `datos/csv/privados/sucursal/`, donde el admin y los usuarios normales lo pueden descargar.

---

## 5. Diferencias entre los mecanismos

| Mecanismo | Capa | Qué protege | Quién se autentica | Alcance |
|---|---|---|---|---|
| TLS | Transporte / aplicación | Una sesión de una aplicación | El servidor, con su certificado | Una conexión |
| PKI | Infraestructura | La confianza en las identidades | La CA da fe del servidor | Toda la organización |
| SSH | Aplicación | La administración remota de un equipo | La persona, con su llave | Un equipo |
| IPSec | Red | Paquetes entre equipos o redes | Los extremos, con llaves de SA | Todo el tráfico IP entre extremos |
| VPN acceso remoto | Red (sobre TLS aquí) | La entrada de una persona a la red privada | El usuario, con credenciales | Una persona → una red, limitada por rol |
| VPN sitio a sitio | Red (IPSec modo túnel) | El tráfico permanente entre dos redes | Los gateways, con PSK | Red ↔ red, transparente para los usuarios |

Ideas clave para la exposición:
- **TLS protege una conversación; IPSec protege todo lo que pasa entre dos puntos de la red.**
- **Acceso remoto = una persona entrando; sitio a sitio = dos oficinas unidas.**
- **Autenticarse no es estar autorizado:** el invitado entra a la VPN, pero no puede chatear.
- Los mecanismos se apilan: un chat por VPN va dentro de TLS hacia el gateway, y del gateway al servidor otra vez en TLS.

---

## 6. Pruebas

### Automáticas

```bash
python3 -m pytest -v tests/
```

Generan su propia PKI y datos en una carpeta temporal (no tocan los tuyos). 45 casos:

| Archivo | Requerimiento que demuestra |
|---|---|
| `test_1_tls_pki.py` | Plano vs TLS (un proxy graba los bytes: en plano se ve la contraseña, en TLS no), versión y cadena, `openssl verify`, rechazo de los 5 certificados malos |
| `test_2_auth_roles_logs.py` | Hash de contraseñas, login correcto/incorrecto, bloqueo, matriz de permisos por rol, subida de CSV, chat por rol, operaciones de admin y registro |
| `test_3_ipsec.py` | Modo transporte vs túnel, replay, ventana, paquete alterado, secuencia forjada, demo por UDP |
| `test_4_vpn.py` | IP virtual y recursos por rol, rechazo de credenciales, restricciones posteriores a la conexión, token, expiración, sitio a sitio, impostor, replay en el túnel |
| `test_5_ssh.py` | Configuración endurecida y análisis de un log **real** de OpenSSH con accesos autorizados y rechazados |

### Guion de la demo en vivo (dos computadoras)

| # | Requerimiento | Qué hacer | Resultado esperado |
|---|---|---|---|
| 1 | Plano vs TLS | Wireshark con filtro `tcp.port == 5000`; `cliente.py --plano`, login y chat. Clic derecho → *Follow → TCP Stream*. Repite con `tcp.port == 5443` y `--tls` | Plano: se lee la contraseña y el chat. TLS: solo *Application Data* |
| 2 | Validación de certificado | `cliente.py --tls` | Muestra TLS 1.3, cifrado y cadena Root → Intermediate → servidor |
| 3 | Rechazo de certificados | En la VM: `python3 servidor/servidor_app.py --tls --puerto 5444 --cert pki/certs/pruebas/expirado/fullchain.pem --key pki/certs/pruebas/expirado/key.pem` (abre 5444 en ufw). En el cliente: `cliente.py --tls --puerto 5444`. Repite con `autofirmado`, `ca_falsa`, `nombre_incorrecto` y `sin_intermedia` | `CERTIFICADO RECHAZADO` con el motivo de cada caso |
| 4 | SSH autorizado | `ssh secadmin@servidor.securecorp.local` | Entra con la llave |
| 5 | SSH no autorizado | `ssh ana@...`, `ssh root@...`, `ssh -i otra_llave secadmin@...` | `Permission denied`; en la VM `sudo python3 ssh/ssh_reporte.py` los lista |
| 6 | IPSec transporte | `python3 ipsec/demo_ipsec.py --modo transporte` | Afuera se ve `10.2.0.10 -> 10.1.0.20 [ESP]` |
| 7 | IPSec túnel | `python3 ipsec/demo_ipsec.py --modo tunel` | Afuera solo se ve `10.2.0.1 -> 10.1.0.1 [ESP]` |
| 8 | Replay | `python3 ipsec/demo_ipsec.py --modo tunel --replay --manipular` | `RECHAZADO por anti-replay` y `RECHAZADO por integridad` |
| 9 | Conexión VPN | `cliente.py --vpn` con cada usuario y con una contraseña mala | IP virtual 10.8.0.x y recursos por rol; la mala se rechaza |
| 10 | Restricciones tras conectarse | Como `invitado`: `chat`, `csv subir`, `csv descargar ventas_q3.csv`, `logs ver` | `ACCESO DENEGADO` en las cuatro |
| 11 | Admin | Como `admin`: `logs filtrar DENEGADO`, `sesiones`, `usuarios crear` | Se ven los rechazos anteriores y queda `ADMIN` en el log |
| 12 | Sitio a sitio | `python3 vpn/sitio_a_sitio.py --rol sucursal` (con la matriz corriendo); luego `--replay` y `--psk-falsa` | Llega el CSV por el túnel; el replay y el impostor se rechazan |

Para la demo IPSec entre dos equipos: en la VM `python3 ipsec/demo_ipsec.py --rol receptor --modo tunel --puerto 7600`
y en el cliente `python3 ipsec/demo_ipsec.py --rol emisor --modo tunel --host IP_VM --puerto 7600 --replay`
(abre `7600/udp`; el 7500 lo usa el gateway matriz). Reinicia el receptor entre corridas: su ventana
anti-replay recuerda los números de secuencia ya vistos, así que una segunda corrida del emisor con la
misma llave sería rechazada completa como replay (que es justo lo que debe pasar).

### Configurar SSH (una sola vez)

```bash
# En la PC cliente
ssh-keygen -t ed25519
scp ~/.ssh/id_ed25519.pub TUUSUARIO@servidor.securecorp.local:/tmp/admin.pub

# En la VM (deja abierta la consola de VirtualBox por si acaso)
sudo bash ssh/configurar_ssh.sh /tmp/admin.pub
```

El script crea el grupo `secureadmins`, el usuario `secadmin` (con tu llave), el usuario `ana` fuera
del grupo, te agrega a ti al grupo para que no pierdas el acceso, instala `securecorp.conf`, lo valida
con `sshd -t` y reinicia SSH. Una segunda llave para la prueba de rechazo: `ssh-keygen -t ed25519 -f otra_llave`.

---

## 7. Limitaciones de seguridad

- **IPSec y las VPN son simulaciones.** No hay IKE real, no se modifican las tablas de ruteo y los
  paquetes ESP viajan dentro de UDP o TCP normales en espacio de usuario.
- **La demo de IPSec usa una llave fija** derivada de una frase. Al repetir la demo con la misma llave, los
  números de secuencia (y por tanto los nonces de GCM) se repiten entre ejecuciones; en IPSec real las SA se
  renegocian. El túnel sitio a sitio sí deriva llaves nuevas en cada conexión.
- **La PSK sitio a sitio está en un archivo** (`config/psk_sitio.key`), no en un almacén seguro de llaves.
- **Sin revocación:** no hay CRL ni OCSP; un certificado comprometido sigue siendo válido hasta que vence.
- **La llave de la CA raíz vive en la misma VM** que los servicios. En producción estaría fuera de línea
  y solo la intermedia firmaría.
- **El servidor confía en la IP virtual que declara el gateway** (`_vpn_ip`) sin autenticarlo; lo correcto
  sería TLS mutuo (certificado de cliente para el gateway).
- **Los logs son archivos locales** sin protección contra modificación ni envío a un servidor central.
- **Sin segundo factor** y sin límite de tasa por IP; solo el bloqueo temporal por cuenta.
- **Todo corre en la misma VM** (gateway, servidor, CA): si se compromete, se compromete todo. En una red
  real el gateway estaría en una DMZ separada.
- **Los mensajes de chat no se cifran de extremo a extremo:** el servidor los ve en claro.
