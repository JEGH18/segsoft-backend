-- V38: recomendaciones de las reglas originales en cualquier base de datos.
--
-- V18/V19 escribieron "suggestedAction" en las 18 reglas sembradas por V14/V17,
-- y V29 reparó el payload roto de la regla pip-audit, pero los tres buscaban las
-- reglas por id fijo (WHERE id = '...'). V14 y V27 crean las reglas con
-- gen_random_uuid(), así que esos ids solo existían en la base donde se
-- escribieron: en una base creada desde cero (producción) ninguna de esas
-- sentencias encontraba su fila. Resultado: los hallazgos de esas reglas se
-- guardaban sin recomendación y la interfaz mostraba siempre el texto genérico,
-- y la regla pip-audit quedaba con un payload que no es JSON válido.
--
-- Aquí cada regla se identifica por su contenido (tipo y descripción). Es
-- idempotente: solo toca reglas que todavía no tienen "suggestedAction" (no pisa
-- una recomendación editada) y payloads que siguen rotos. Los textos son los de
-- V19 (y V29 para pip-audit).

-- Lee un payload TEXT como jsonb, o NULL si no es JSON válido, para que una fila
-- rota no aborte la migración al evaluar el WHERE.
CREATE OR REPLACE FUNCTION pg_temp.payload_json(payload TEXT) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN
    RETURN payload::jsonb;
EXCEPTION WHEN others THEN
    RETURN NULL;
END;
$$;

-- ── pip-audit: payload concatenado ({...}{...}) que V29 no alcanzó a reparar ──

UPDATE rules SET payload =
    '{"description":"Escaneo de CVEs en dependencias Python del proyecto","suggestedAction":"Ejecuta pip-audit (o Safety) en el pipeline de CI/CD para bloquear builds con dependencias Python que tengan CVEs conocidos sin parche disponible.","known_vulnerable":[{"ecosystem":"pypi","package":"jinja2","below_version":"2.11.3","cve":"CVE-2020-28493"},{"ecosystem":"pypi","package":"django","below_version":"3.2.13","cve":"CVE-2022-28346"}]}'
WHERE type = 'DEPENDENCY_CHECK'
  AND payload LIKE '%pip-audit%}{%'
  AND pg_temp.payload_json(payload) IS NULL;

-- ── Recomendación de cada regla sembrada por V14/V17 ──

UPDATE rules SET payload = (pg_temp.payload_json(payload)
        || jsonb_build_object('suggestedAction', 'Usa sentencias parametrizadas (PreparedStatement) en vez de concatenar el valor directamente en el SQL. Reemplaza algo como stmt.executeQuery("..." + id) por: PreparedStatement ps = conn.prepareStatement("SELECT * FROM tabla WHERE id = ?"); ps.setString(1, id);'))::text
WHERE type = 'PATTERN_REGEX'
  AND pg_temp.payload_json(payload) ->> 'description' = 'Concatenación directa de cadenas en query SQL'
  AND NOT pg_temp.payload_json(payload) ? 'suggestedAction';

UPDATE rules SET payload = (pg_temp.payload_json(payload)
        || jsonb_build_object('suggestedAction', 'Evita SELECT *; especifica explícitamente las columnas que necesitas. Así reduces los datos sensibles expuestos (contraseñas, tokens) si la consulta llegara a ser explotada, y documentas mejor qué usa realmente el código.'))::text
WHERE type = 'PATTERN_REGEX'
  AND pg_temp.payload_json(payload) ->> 'description' = 'Consulta SELECT * sin filtro de columnas sensibles'
  AND NOT pg_temp.payload_json(payload) ? 'suggestedAction';

UPDATE rules SET payload = (pg_temp.payload_json(payload)
        || jsonb_build_object('suggestedAction', 'No uses el valor de request.getParameter(...) directamente dentro de la consulta. Valida y sanitiza el input, y pásalo como parámetro vinculado (?) en una sentencia preparada, nunca concatenado en el texto del SQL.'))::text
WHERE type = 'PATTERN_REGEX'
  AND pg_temp.payload_json(payload) ->> 'description' = 'Parámetro HTTP usado directamente en query sin validar'
  AND NOT pg_temp.payload_json(payload) ? 'suggestedAction';

UPDATE rules SET payload = (pg_temp.payload_json(payload)
        || jsonb_build_object('suggestedAction', 'Reemplaza la asignación directa a innerHTML por textContent si solo necesitas texto plano, o sanitiza el HTML con DOMPurify antes de asignarlo, para evitar que un usuario inyecte <script> u otros elementos ejecutables.'))::text
WHERE type = 'PATTERN_REGEX'
  AND pg_temp.payload_json(payload) ->> 'description' = 'Asignación directa a innerHTML sin escape'
  AND NOT pg_temp.payload_json(payload) ? 'suggestedAction';

UPDATE rules SET payload = (pg_temp.payload_json(payload)
        || jsonb_build_object('suggestedAction', 'Evita insertar HTML sin sanitizar. Si necesitas renderizar HTML dinámico, sanea el contenido primero con una librería como DOMPurify — por ejemplo dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userInput) }} — en vez de pasar el string del usuario directamente.'))::text
WHERE type = 'PATTERN_REGEX'
  AND pg_temp.payload_json(payload) ->> 'description' = 'Renderizado HTML sin sanitización explícita'
  AND NOT pg_temp.payload_json(payload) ? 'suggestedAction';

UPDATE rules SET payload = (pg_temp.payload_json(payload)
        || jsonb_build_object('suggestedAction', 'Exige contraseñas de al menos 12 caracteres, combinando mayúsculas, minúsculas, números y símbolos. Ajusta la validación de longitud actual para reflejar ese mínimo.'))::text
WHERE type = 'PATTERN_REGEX'
  AND pg_temp.payload_json(payload) ->> 'description' = 'Validación de contraseña con longitud menor a 12 caracteres'
  AND NOT pg_temp.payload_json(payload) ? 'suggestedAction';

UPDATE rules SET payload = (pg_temp.payload_json(payload)
        || jsonb_build_object('suggestedAction', 'Agrega limitación de intentos (rate limiting) al endpoint de login — por ejemplo con Bucket4j o un RateLimiter — para frenar ataques de fuerza bruta y credential stuffing.'))::text
WHERE type = 'PATTERN_REGEX'
  AND pg_temp.payload_json(payload) ->> 'description' = 'Endpoint de login sin protección de rate limiting visible'
  AND NOT pg_temp.payload_json(payload) ? 'suggestedAction';

UPDATE rules SET payload = (pg_temp.payload_json(payload)
        || jsonb_build_object('suggestedAction', 'Agrega .withExpiresAt(...) (y opcionalmente .withIssuedAt(...)) al construir el token JWT. Un token sin expiración es válido indefinidamente si es robado.'))::text
WHERE type = 'PATTERN_REGEX'
  AND pg_temp.payload_json(payload) ->> 'description' = 'Token JWT creado sin expiración explícita'
  AND NOT pg_temp.payload_json(payload) ? 'suggestedAction';

UPDATE rules SET payload = (pg_temp.payload_json(payload)
        || jsonb_build_object('suggestedAction', 'No almacenes contraseñas en texto plano. Usa un algoritmo de hash diseñado para contraseñas (Argon2, bcrypt) antes de guardarlas, en vez de mapear el campo password directamente como texto plano.'))::text
WHERE type = 'PATTERN_REGEX'
  AND pg_temp.payload_json(payload) ->> 'description' = 'Campo contraseña almacenado como texto plano sin @Convert ni cifrado'
  AND NOT pg_temp.payload_json(payload) ? 'suggestedAction';

UPDATE rules SET payload = (pg_temp.payload_json(payload)
        || jsonb_build_object('suggestedAction', 'Nunca hardcodees claves, tokens o contraseñas en el código fuente. Muévelos a variables de entorno o a un gestor de secretos (Vault, AWS Secrets Manager, etc.) y cárgalos en tiempo de ejecución.'))::text
WHERE type = 'PATTERN_REGEX'
  AND pg_temp.payload_json(payload) ->> 'description' = 'Secreto hardcodeado detectado en código fuente'
  AND NOT pg_temp.payload_json(payload) ? 'suggestedAction';

UPDATE rules SET payload = (pg_temp.payload_json(payload)
        || jsonb_build_object('suggestedAction', 'Elimina las contraseñas y tokens de los mensajes de log. Si necesitas registrar el evento, enmascara el valor sensible (ej. password=***) o registra solo un identificador no sensible.'))::text
WHERE type = 'PATTERN_REGEX'
  AND pg_temp.payload_json(payload) ->> 'description' = 'Datos sensibles registrados en logs'
  AND NOT pg_temp.payload_json(payload) ? 'suggestedAction';

UPDATE rules SET payload = (pg_temp.payload_json(payload)
        || jsonb_build_object('suggestedAction', 'Habilita server.ssl.enabled=true y configura un certificado válido. Nunca transmitas credenciales o datos sensibles en texto plano sobre HTTP.'))::text
WHERE type = 'CONFIG_CHECK'
  AND pg_temp.payload_json(payload) ->> 'description' = 'TLS debe estar habilitado en produccion'
  AND NOT pg_temp.payload_json(payload) ? 'suggestedAction';

UPDATE rules SET payload = (pg_temp.payload_json(payload)
        || jsonb_build_object('suggestedAction', 'Exige un segundo factor de autenticación (TOTP, WebAuthn, etc.) para los roles privilegiados (ej. SECURITY_ADMIN) antes de otorgar acceso, y configura la clave mfa.required.roles con esos roles.'))::text
WHERE type = 'CONFIG_CHECK'
  AND pg_temp.payload_json(payload) ->> 'description' = 'MFA obligatorio para roles privilegiados'
  AND NOT pg_temp.payload_json(payload) ? 'suggestedAction';

UPDATE rules SET payload = (pg_temp.payload_json(payload)
        || jsonb_build_object('suggestedAction', 'Define una política de actualización periódica de dependencias (por ejemplo, no más de 30 días) y configura la clave dependency.update.maxAgeDays para hacerla cumplir, idealmente automatizada con Dependabot o Renovate.'))::text
WHERE type = 'CONFIG_CHECK'
  AND pg_temp.payload_json(payload) ->> 'description' = 'Politica de actualizacion de dependencias ausente'
  AND NOT pg_temp.payload_json(payload) ? 'suggestedAction';

UPDATE rules SET payload = (pg_temp.payload_json(payload)
        || jsonb_build_object('suggestedAction', 'Verifica la integridad de los artefactos externos con checksums SHA-256 antes de incorporarlos al build, y configura la clave artifact.checksum.verify para exigir esa verificación.'))::text
WHERE type = 'CONFIG_CHECK'
  AND pg_temp.payload_json(payload) ->> 'description' = 'Verificacion de checksum de artefactos ausente'
  AND NOT pg_temp.payload_json(payload) ? 'suggestedAction';

UPDATE rules SET payload = (pg_temp.payload_json(payload)
        || jsonb_build_object('suggestedAction', 'Configura la cabecera Content-Security-Policy en las respuestas HTTP (por ejemplo default-src ''self'') para limitar qué scripts, estilos y recursos puede cargar el navegador, mitigando el impacto de un XSS aunque exista en el código.'))::text
WHERE type = 'CONFIG_CHECK'
  AND pg_temp.payload_json(payload) ->> 'description' = 'Cabecera Content-Security-Policy no configurada'
  AND NOT pg_temp.payload_json(payload) ? 'suggestedAction';

UPDATE rules SET payload = (pg_temp.payload_json(payload)
        || jsonb_build_object('suggestedAction', 'Actualiza la dependencia a una versión igual o superior a la indicada como segura para eliminar el CVE reportado. Agrega un escaneo de dependencias (OWASP Dependency-Check, npm audit, pip-audit) al pipeline de CI/CD para detectarlo automáticamente en cada build.'))::text
WHERE type = 'DEPENDENCY_CHECK'
  AND pg_temp.payload_json(payload) ->> 'description' = 'Dependencias con CVEs conocidos de alta severidad'
  AND NOT pg_temp.payload_json(payload) ? 'suggestedAction';

UPDATE rules SET payload = (pg_temp.payload_json(payload)
        || jsonb_build_object('suggestedAction', 'Actualiza la dependencia afectada antes de desplegar. Configura el pipeline para bloquear el build si se detecta una dependencia con CVE de severidad CRITICAL o HIGH sin una versión corregida disponible.'))::text
WHERE type = 'DEPENDENCY_CHECK'
  AND pg_temp.payload_json(payload) ->> 'description' = 'Bloquear dependencias con CVE CRITICAL o HIGH'
  AND NOT pg_temp.payload_json(payload) ? 'suggestedAction';

-- ── Hallazgos ya guardados sin recomendación: toman la de su regla ──

UPDATE findings f SET suggested_action = pg_temp.payload_json(r.payload) ->> 'suggestedAction'
FROM rules r
WHERE f.rule_id = r.id
  AND f.suggested_action IS NULL
  AND pg_temp.payload_json(r.payload) ->> 'suggestedAction' IS NOT NULL;
