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
  servidor) la sesión se pierde cada vez que se recarga la página.

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
