# Despliegue de SegSoft

```
                 ┌──────────── Vercel ────────────┐
 navegador ────► │ segsoft-frontend (SPA, dist/)  │   https://app.<dominio>
                 └───────────────┬────────────────┘
                                 │ HTTPS (VITE_API_BASE_URL)
                 ┌──────────── Servidor con Docker (este directorio) ───────────┐
                 │ caddy :443 ──► backend :8080 ──► engine :8001 (red interna)  │   https://api.<dominio>
                 │                   │      volumen compartido sandbox ◄─┘      │
                 │                   └──► postgres :5432 (volumen pgdata)       │
                 └──────────────────────────────────────────────────────────────┘
```

- **Frontend en Vercel:** es una SPA estática.
- **Backend y motor juntos en un servidor:** el backend le pasa al motor la *ruta* del
  repositorio dentro de `/tmp/pdgseg-sandbox` y el motor lee los archivos de ahí, así que
  necesitan el mismo disco. Vercel no ejecuta Java ni comparte disco entre servicios.
- **Mismo dominio para frontend y backend** (`app.` y `api.` del mismo dominio): la cookie de
  sesión es `SameSite=Strict`. Con dominios distintos (por ejemplo `*.vercel.app` y la IP del
  servidor) la sesión se pierde cada vez que se recarga la página. Sin dominio propio, la
  alternativa es el proxy de Vercel (ver "Despliegue actual").

## Despliegue actual (sin dominio propio)

Desplegado el 2026-10-21. Sin un dominio compartido, el navegador solo habla con Vercel:
`segsoft-frontend/vercel.json` reenvía `/api/*` al backend, así que la cookie de sesión queda en
el dominio de Vercel.

```
navegador ─► https://segsoft-frontend.vercel.app                  (Vercel, proyecto segsoft-frontend)
                └─ /api/* ─► https://segsoft-icesi.westus3.cloudapp.azure.com   (VM de Azure)
                                └─ Caddy → backend → engine + PostgreSQL
```

| Pieza | Detalle |
|---|---|
| Frontend | Vercel, importado del espejo de GitHub `JEGH18/segsoft-frontend` (rama `main`): cada push a `main` en GitHub redespliega. **Sin** variables de entorno: sin `VITE_API_BASE_URL` el frontend llama a `/api/...` en su propio origen |
| Proxy | `vercel.json`: `/api/:path*` → `https://segsoft-icesi.westus3.cloudapp.azure.com/api/:path*`, antes de la regla de la SPA |
| VM | Azure for Students, VM `segsoft`, región **West US 3**, `Standard_B2als_v2` (2 vCPU, 4 GB, x64), Ubuntu 24.04, disco Standard SSD de 30 GB, 2 GB de swap, usuario SSH `Segsoft` |
| Nombre del backend | *DNS name label* `segsoft-icesi` de la IP pública `segsoft-ip` (estática, 20.168.55.230). Caddy obtiene el certificado de Let's Encrypt para ese nombre |
| Red | Grupo de seguridad con 22, 80 y 443 abiertos. El backend solo escucha en `127.0.0.1:8080` y el motor no publica puertos |
| Código en la VM | `/opt/segsoft/segsoft-backend` y `/opt/segsoft/segsoft-motorpython`, clonados del **espejo de GitHub** (p2tools pide credenciales y no se guardan en el servidor) |
| Secretos | `/opt/segsoft/segsoft-backend/deploy/.env` (permisos 600), generado con `generar-env.sh segsoft-icesi.westus3.cloudapp.azure.com https://segsoft-frontend.vercel.app` |
| Apagado | *Auto-shutdown* de Azure a las 02:00 (hora de Bogotá). Al encenderla con **Start** todo se levanta solo (Docker y los contenedores con `restart: unless-stopped`) |

**Restricciones de la suscripción Azure for Students** (por si hay que recrear la VM):

- Solo permite las regiones `westus3`, `southcentralus`, `canadacentral`, `brazilsouth` y
  `chilecentral` (política *Allowed resource deployment regions*). Las demás fallan al crear con
  `RequestDisallowedByAzure`.
- La cuota por familia varía por región (`D2als_v7` tiene 0 vCPU en West US 3). En South
  Central US los B2 disponibles son ARM. Para revisar, en Cloud Shell:

  ```bash
  az vm list-usage -l westus3 --query '[?limit > `0`].{familia:localName, usado:currentValue, limite:limit}' -o table
  ```
- Los créditos (100 USD) vencen el 12 de febrero de 2027. La VM cuesta unos 0,0376 USD por hora
  encendida, más el disco.

**Ver las contraseñas de las cuentas** (en tu terminal, no las compartas por chat):
`ssh Segsoft@20.168.55.230 'grep SEGSOFT_ACCOUNTS /opt/segsoft/segsoft-backend/deploy/.env'`.

**Actualizar el backend o el motor** (después de llevar los cambios de p2tools al espejo de GitHub):
`ssh Segsoft@20.168.55.230`, y en `/opt/segsoft/segsoft-backend/deploy`:
`git -C .. pull && git -C ../../segsoft-motorpython pull && docker compose up -d --build`.

**Límite conocido:** las subidas pasan por el proxy de Vercel, cuyo límite de tamaño no está
documentado. Los ZIP de prueba (unos 20 KB) pasan; uno cercano a los 100 MB podría fallar. Con
un dominio propio (`app.`/`api.`) el frontend llamaría al backend directamente: basta con
definir `VITE_API_BASE_URL` en Vercel y la regla del proxy deja de usarse.

## Requisitos

- Una máquina virtual Linux con **Docker** (con el plugin `compose`), **2 GB de RAM** o más y
  los puertos **80 y 443** abiertos.
- Un **dominio** con dos registros DNS: `api.<dominio>` → IP del servidor (registro A) y
  `app.<dominio>` → Vercel (lo indica Vercel al agregar el dominio).
- Una cuenta de Vercel.

## 1. Servidor: backend, motor y base de datos

```bash
sudo mkdir -p /opt/segsoft && sudo chown "$USER" /opt/segsoft && cd /opt/segsoft
git clone https://pi2tools.icesi.edu.co/bitbucket/scm/segsoft/segsoft-backend.git
git clone https://pi2tools.icesi.edu.co/bitbucket/scm/segsoft/segsoft-motorpython.git
# p2tools pide usuario y contraseña. Para no dejarlos en el servidor, se puede clonar el
# espejo público: https://github.com/JEGH18/segsoft-backend.git y .../segsoft-motorpython.git
cd segsoft-backend/deploy

./generar-env.sh api.<dominio> https://app.<dominio>   # anota las contraseñas que imprime
docker compose up -d --build
```

`generar-env.sh` crea `deploy/.env` (permisos 600, ignorado por git) con la contraseña de la
base de datos, `JWT_SECRET`, `INTERNAL_SERVICE_TOKEN` y las cuentas `admin`, `auditor`, `dev` y
`usuario` con contraseñas aleatorias. **Ninguna contraseña está en los repositorios.**

Comprobar:

```bash
docker compose ps                                  # los 4 servicios en "running" / "healthy"
curl https://api.<dominio>/actuator/health         # {"status":"UP",...}
docker compose logs backend | grep "Cuentas de producción listas"
```

## 2. Frontend en Vercel

Vercel solo se conecta a GitHub, GitLab y Bitbucket **Cloud**; p2tools es Bitbucket Server.
Dos opciones:

- **Espejo de GitHub (despliegue automático en cada push):** en Vercel, *Add New → Project*,
  importar `JEGH18/segsoft-frontend`.
- **CLI, desde un clon de p2tools:** `npx vercel` (la primera vez) y `npx vercel --prod`.

Configuración del proyecto (el `vercel.json` del repositorio ya fija preset, build y salida):

| Variable de entorno | Valor |
|---|---|
| `VITE_API_BASE_URL` | `https://api.<dominio>` |

`VITE_API_BASE_URL` se incrusta **al compilar**: si cambia, hay que volver a desplegar. Por
último, en *Settings → Domains* agregar `app.<dominio>`.

## 3. Prueba final

Entrar en `https://app.<dominio>` con `admin` y analizar los tres ZIP de
`segsoft-docs/pruebas-usuarios/`. El cumplimiento ponderado debe ser 8,85 %, 88,68 % y 100 %.

## Operación

| Acción | Comando (en `deploy/`) |
|---|---|
| Apagar entre sesiones de prueba (conserva los datos) | `docker compose stop` |
| Encender | `docker compose start` |
| Ver logs | `docker compose logs -f backend` |
| Actualizar a la última versión | `git -C .. pull && git -C ../../segsoft-motorpython pull && docker compose up -d --build` |
| Respaldo de la base de datos | `docker compose exec -T postgres pg_dump -U segsoft segsoft > respaldo-$(date +%F).sql` |
| Restaurar un respaldo | `docker compose exec -T postgres psql -U segsoft segsoft < respaldo.sql` |
| Borrar todo, incluidos los datos | `docker compose down -v` |

**Cambiar contraseñas o cuentas:** editar `SEGSOFT_ACCOUNTS` en `deploy/.env`
(`usuario:ROL:contraseña`, separadas por `;`; roles `DEVELOPER`, `AUDITOR` o `SECURITY_ADMIN`;
contraseñas de 12 caracteres o más) y `docker compose up -d backend`. Las cuentas se aplican en
cada arranque.

## Seguridad

- El backend arranca con el perfil `prod`: no crea las cuentas de demostración, y **se niega a
  arrancar** si `SEGSOFT_ACCOUNTS` falta, es inválida o no incluye un `SECURITY_ADMIN`. La
  migración V3 crea `admin` con la contraseña pública `admin123`: esta configuración la
  reemplaza en cada arranque. Las cuentas de demostración que no estén en `SEGSOFT_ACCOUNTS` y
  conserven su contraseña pública se deshabilitan.
- Solo Caddy queda expuesto. El motor no tiene puertos publicados y el backend solo escucha en
  `127.0.0.1:8080` (diagnóstico desde el propio servidor).
- Sin sesión, la API solo responde al login, al estado del servicio y a la documentación
  Swagger.
- Apaga el servidor (`docker compose stop`) cuando no haya sesiones de prueba.

## Problemas frecuentes

| Síntoma | Causa probable |
|---|---|
| La sesión se pierde al recargar la página | Frontend y backend en dominios distintos (ver arriba) |
| "Network Error" o error de CORS en la consola del navegador | `FRONTEND_ORIGIN` en `.env` no coincide exactamente con la URL del frontend (sin `/` final) |
| El backend se reinicia en bucle con "SEGSOFT_ACCOUNTS inválida" | El mensaje dice qué entrada corregir en `.env` |
| Caddy no obtiene el certificado | El DNS de `api.<dominio>` aún no apunta al servidor, o los puertos 80/443 están cerrados |
| Al recargar `/reports/...` aparece un 404 de Vercel | Falta el `vercel.json` en el despliegue |
