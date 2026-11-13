# Observabilidad de SegSoft

Cómo saber si el sistema está operativo, dónde se demora un análisis y qué pasó con una
petición que falló, sin reproducir el flujo a mano.

## Healthchecks

| Endpoint | Autenticación | Responde |
|---|---|---|
| `GET /actuator/health/liveness` | ninguna | `200 {"status":"UP"}` si el proceso está vivo. No mira dependencias: un motor caído no es motivo para reiniciar el backend |
| `GET /actuator/health/readiness` | ninguna | `200` si PostgreSQL, el almacenamiento sandbox y el motor responden; `503` si alguno falla. Muestra el estado de cada dependencia; los detalles (tiempos, tipo de error) solo con sesión |
| `GET /actuator/health` | ninguna | estado global (las mismas dependencias más espacio en disco) |
| `GET /actuator/info` | ninguna | versión y fecha del build |
| `GET /actuator/prometheus` | `SECURITY_ADMIN` | métricas en formato Prometheus |

Cualquier otro endpoint de Actuator responde 403.

Dependencias de readiness:

| Componente | Comprobación |
|---|---|
| `postgres` | `SELECT 1` sobre una conexión del pool |
| `sandbox` | escribe, lee y borra un archivo temporal en `SANDBOX_ROOT` |
| `engine` | `GET /internal/health` del motor con el token de servicio (timeout `ENGINE_HEALTH_TIMEOUT_MS`, 2 s) |

```bash
curl -s https://segsoft-icesi.westus3.cloudapp.azure.com/actuator/health/readiness
# {"status":"UP","components":{"engine":{"status":"UP"},"postgres":{"status":"UP"},
#  "readinessState":{"status":"UP"},"sandbox":{"status":"UP"}}}
```

## Métricas

`/actuator/prometheus` publica las métricas de Spring Boot (HTTP, JVM, pool de conexiones) y
las de los análisis:

| Métrica | Tipo | Etiquetas | Qué mide |
|---|---|---|---|
| `analyses_executed_total` | contador | `status` (COMPLETED, FAILED, CANCELLED) | análisis terminados |
| `analyses_running_current` | gauge | | análisis en ejecución ahora |
| `rule_execution_duration_seconds` | histograma | `ruleType`, `outcome` | cada petición al motor (una regla sobre un lote de archivos) |
| `rule_execution_errors_total` | contador | `ruleType`, `errorCode` | errores que reportó el motor (`RULE_TIMEOUT`, `PATH_OUTSIDE_SANDBOX`, …) o fallos al llamarlo (`ENGINE_ERROR`) |

Para encontrar el cuello de botella en el motor: el p95 de `rule_execution_duration_seconds`
por `ruleType` muestra qué tipo de regla se demora, y `rule_execution_errors_total` por
`errorCode` muestra si las reglas se están cortando por tiempo.

## Logs y traceId

El backend y el motor escriben una línea JSON por evento, con los mismos campos base:

```json
{"timestamp":"2026-11-12T23:35:09.611Z","level":"WARN","traceId":"8e15868b-619b-4571-9b96-6f2d98c8d503",
 "message":"El motor no ejecutó la regla ruleId=… tipo=PATTERN_REGEX archivos=5: …",
 "logger":"co.icesi.pdgseg.service.AnalysisExecutionService",
 "context":{"service":"pdgseg-backend","thread":"analysis-3"}}
```

- `timestamp` es ISO-8601 en UTC; `level` es `INFO`, `WARN` o `ERROR` (también `DEBUG`/`TRACE`).
- Cada petición HTTP recibe un `traceId` (UUID v4) al entrar. Si el cliente envía un
  `X-Trace-Id` o un `traceparent` (W3C) bien formado, se usa ese. El backend lo devuelve en el
  header `X-Trace-Id` y en todo cuerpo de error.
- Un análisis conserva el `traceId` de la petición que lo inició, también en su hilo asíncrono,
  y el backend se lo envía al motor en `X-Trace-Id`: los logs de las dos aplicaciones para ese
  análisis comparten el mismo id.
- Antes de escribirse, cada valor pasa por el enmascarado de secretos: contraseñas y tokens en
  forma `clave=valor`, el header `Authorization` (`Bearer *****`), JWT, tokens de API
  `pdgseg_…`, credenciales en URLs y llaves privadas. Lo mismo en el motor.

**Diagnosticar un error.** Un error inesperado llega al cliente así, sin stack trace:

```json
{"errorCode":"INTERNAL_ERROR","traceId":"45abb11a-9abe-475f-aec0-dff45accfeee","message":"Ocurrió un error inesperado"}
```

El stack trace queda en el log con ese `traceId`:

```bash
cd /opt/segsoft/segsoft-backend/deploy
docker compose logs backend engine | grep 45abb11a-9abe-475f-aec0-dff45accfeee
```

## Demostración con Grafana

`docker-compose.yml` de esta carpeta levanta Prometheus, que lee `/actuator/prometheus` cada
15 s, y Grafana con el dashboard **SegSoft - Backend** ya cargado: análisis en ejecución y
terminados, errores de reglas por código, duración p95 y media de las reglas por tipo,
peticiones y latencia de la API, y memoria de la JVM.

1. Con el despliegue encendido (`deploy/docker-compose.yml`), crear un token de API desde una
   cuenta `SECURITY_ADMIN` (en la aplicación, ícono de llave, «Tokens de API») y guardarlo en
   `deploy/observability/prometheus-token` (el `.gitignore` lo excluye).
2. Levantar la demostración:

   ```bash
   cd deploy/observability
   GRAFANA_ADMIN_PASSWORD='<una contraseña>' docker compose up -d
   ```
3. Abrir Grafana en `http://127.0.0.1:3000` (usuario `admin`). En la VM los puertos solo
   escuchan en la propia máquina; desde un equipo: `ssh -L 3000:127.0.0.1:3000 Segsoft@<vm>`.
   Prometheus queda en `http://127.0.0.1:9090` (*Status → Targets* debe mostrar
   `segsoft-backend` en `UP`).

Con el backend corriendo en el equipo y no en Docker (perfil dev, puerto 8090): cambiar el
target de `prometheus.yml` a `host.docker.internal:8090` y crear una vez la red
(`docker network create segsoft_default`).

## Pruebas

| Prueba | Qué verifica |
|---|---|
| `ObservabilityIntegrationTest` | liveness (`{"status":"UP"}`, público, < 100 ms), readiness con sus tres dependencias y 503 con el motor caído, health, info, permisos de prometheus y sus métricas, traceId en respuestas, logs JSON sin el token de `Authorization` |
| `ReadinessDatabaseDownIntegrationTest` | detiene su PostgreSQL (Testcontainers) y readiness pasa a 503 |
| `UnhandledExceptionResponseTest` | el 500 solo lleva `errorCode`, `traceId` y `message`; el stack trace queda en el log con el mismo `traceId` |
| `TraceIdFilterTest`, `SecretLogValueMaskerTest`, `ApiErrorAttributesTest` | traceId, enmascarado de logs y página `/error` |
| `AnalysisExecutionServiceTest` | las cuatro métricas de análisis |
| motor: `tests/unit/test_logging.py` | campos base, traceId del backend y enmascarado en los logs del motor |
