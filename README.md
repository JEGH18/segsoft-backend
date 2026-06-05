# segsoft-backend

Backend del sistema **SegSoft** — plataforma de análisis de cumplimiento de seguridad para repositorios de código fuente. Proyecto de grado (PDG) — Universidad Icesi.

## Descripción

API REST construida con Spring Boot que orquesta el análisis de seguridad: recibe repositorios (ZIP o Git), los indexa, ejecuta reglas de cumplimiento a través del motor Python y almacena los hallazgos.

## Tecnologías

| Componente | Versión |
|---|---|
| Java | 17 |
| Spring Boot | 3.3.0 |
| Gradle | 8.10.1 |
| PostgreSQL | 15 |
| Flyway | (incluido en Spring Boot) |
| JWT (JJWT) | HS256 |

## Arquitectura

```
cliente HTTP
    │
    ▼
AnalysisController  ──▶  AnalysisExecutionService
                               │
                    ┌──────────┴──────────┐
                    ▼                     ▼
           FileInventoryService      EngineClient
           (indexa archivos)         (llama al motor Python)
                    │
                    ▼
              PostgreSQL (Flyway migrations V1–V18)
```

**Flujo de análisis:**
1. Usuario sube un ZIP o URL Git → Spring extrae en `/tmp/pdgseg-sandbox/<userId>/<repoId>/`
2. `FileInventoryService` indexa archivos en `repository_files` (lenguaje, tipo de artefacto, sha256)
3. Al iniciar análisis, `AnalysisExecutionService` itera reglas × archivos y llama al motor Python via `EngineClient`
4. Los hallazgos se persisten en `findings`; los resultados por política en `policy_results`

## Requisitos previos

- Java 17
- PostgreSQL local con base de datos `pdgseg_test` y usuario `pdgseg_test`
- Motor Python corriendo en `http://localhost:18001` (ver `segsoft-motorpython`)

## Configuración local

La aplicación usa valores por defecto para desarrollo local — no requiere archivo `.env`:

| Variable | Default local |
|---|---|
| DB | `localhost:5432/pdgseg_test` |
| Motor Python | `http://localhost:18001` |
| JWT secret | `dev-secret-for-local-development-minimum-32-chars-ok` |
| Token interno | `dev-internal-token` |
| Sandbox | `/tmp/pdgseg-sandbox` |

## Cómo ejecutar

```bash
# 1. Levantar PostgreSQL (Docker)
docker compose up -d db

# 2. Iniciar el backend
./gradlew bootRun
```

La API queda disponible en `http://localhost:8080`. Las migraciones Flyway se aplican automáticamente al arrancar.

## Usuarios de desarrollo

| Usuario | Contraseña | Rol |
|---|---|---|
| `admin` | `admin123` | SECURITY_ADMIN |
| `auditor` | `auditor123` | AUDITOR |
| `dev` | `dev123` | DEVELOPER |

## Endpoints principales

| Método | Ruta | Descripción |
|---|---|---|
| POST | `/api/v1/auth/login` | Autenticación, devuelve JWT |
| POST | `/api/v1/repositories` | Subir ZIP |
| POST | `/api/v1/repositories/git` | Clonar repositorio Git |
| POST | `/api/v1/repositories/{id}/policy-selection` | Seleccionar políticas |
| POST | `/api/v1/analyses` | Iniciar análisis |
| GET | `/api/v1/analyses/{id}/results` | Resultados del análisis |
| GET | `/api/v1/analyses/{id}/findings` | Listado de hallazgos (paginado) |
| GET | `/api/v1/policies` | Catálogo de políticas |

## Políticas y reglas seed

Las migraciones `V12` y `V14` insertan 18 políticas y 18 reglas que cubren 5 categorías:

- `SQL_INJECTION` — consultas parametrizadas, SELECT *, parámetros HTTP en query
- `XSS` — innerHTML, dangerouslySetInnerHTML, v-html, CSP
- `AUTHENTICATION_FAILURE` — JWT sin expiración, rate limiting, contraseñas débiles, MFA
- `INSECURE_DATA_HANDLING` — secretos hardcodeados, logs con datos sensibles, TLS
- `DEPENDENCY_VULNERABILITY` — CVEs conocidos (Log4Shell, Struts2), checksums, actualizaciones

## Estructura del proyecto

```
src/main/java/co/icesi/pdgseg/
├── controller/        # REST controllers
├── service/           # Lógica de negocio
│   ├── AnalysisExecutionService.java   # Orquestador de análisis
│   ├── EngineClient.java               # Cliente HTTP al motor Python
│   ├── FileInventoryService.java       # Indexación de archivos
│   └── ZipExtractorService.java        # Extracción segura de ZIPs
├── entity/            # Entidades JPA
├── repository/        # Spring Data repositories
├── dto/               # DTOs de request/response/snapshot
└── security/          # JWT filter, autenticación

src/main/resources/
├── db/migration/      # Migraciones Flyway (V1–V18)
└── default-exclusions.yml  # Directorios y archivos excluidos del inventario
```
