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
-- Aquí cada regla se identifica por su descripción, que es única entre las
-- reglas sembradas. Es idempotente: solo toca reglas que todavía no tienen
-- recomendación (no pisa una editada) y payloads que siguen rotos. Los textos
-- son los de V19 (y V29 para pip-audit).

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

-- La recomendación guardada en el payload de una regla, o NULL.
CREATE OR REPLACE FUNCTION pg_temp.suggested_action(payload TEXT) RETURNS TEXT
LANGUAGE sql IMMUTABLE AS $$
    SELECT pg_temp.payload_json(payload) ->> 'suggestedAction';
$$;

-- ── pip-audit: payload concatenado ({...}{...}) que V29 no alcanzó a reparar ──

UPDATE rules SET payload =
    '{"description":"Escaneo de CVEs en dependencias Python del proyecto","suggestedAction":"Ejecuta pip-audit (o Safety) en el pipeline de CI/CD para bloquear builds con dependencias Python que tengan CVEs conocidos sin parche disponible.","known_vulnerable":[{"ecosystem":"pypi","package":"jinja2","below_version":"2.11.3","cve":"CVE-2020-28493"},{"ecosystem":"pypi","package":"django","below_version":"3.2.13","cve":"CVE-2022-28346"}]}'
WHERE type = 'DEPENDENCY_CHECK'
  AND position('pip-audit' IN payload) > 0
  AND pg_temp.payload_json(payload) IS NULL;

-- ── Recomendación de cada regla sembrada por V14/V17 ──

UPDATE rules r
SET payload = jsonb_set(pg_temp.payload_json(r.payload), '{suggestedAction}', to_jsonb(seed.suggested_action))::text
FROM (VALUES
    ('Concatenación directa de cadenas en query SQL',
     'Usa sentencias parametrizadas (PreparedStatement) en vez de concatenar el valor directamente en el SQL. Reemplaza algo como stmt.executeQuery("..." + id) por: PreparedStatement ps = conn.prepareStatement("SELECT * FROM tabla WHERE id = ?"); ps.setString(1, id);'),
    ('Consulta SELECT * sin filtro de columnas sensibles',
     'Evita SELECT *; especifica explícitamente las columnas que necesitas. Así reduces los datos sensibles expuestos (contraseñas, tokens) si la consulta llegara a ser explotada, y documentas mejor qué usa realmente el código.'),
    ('Parámetro HTTP usado directamente en query sin validar',
     'No uses el valor de request.getParameter(...) directamente dentro de la consulta. Valida y sanitiza el input, y pásalo como parámetro vinculado (?) en una sentencia preparada, nunca concatenado en el texto del SQL.'),
    ('Asignación directa a innerHTML sin escape',
     'Reemplaza la asignación directa a innerHTML por textContent si solo necesitas texto plano, o sanitiza el HTML con DOMPurify antes de asignarlo, para evitar que un usuario inyecte <script> u otros elementos ejecutables.'),
    ('Renderizado HTML sin sanitización explícita',
     'Evita insertar HTML sin sanitizar. Si necesitas renderizar HTML dinámico, sanea el contenido primero con una librería como DOMPurify — por ejemplo dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userInput) }} — en vez de pasar el string del usuario directamente.'),
    ('Validación de contraseña con longitud menor a 12 caracteres',
     'Exige contraseñas de al menos 12 caracteres, combinando mayúsculas, minúsculas, números y símbolos. Ajusta la validación de longitud actual para reflejar ese mínimo.'),
    ('Endpoint de login sin protección de rate limiting visible',
     'Agrega limitación de intentos (rate limiting) al endpoint de login — por ejemplo con Bucket4j o un RateLimiter — para frenar ataques de fuerza bruta y credential stuffing.'),
    ('Token JWT creado sin expiración explícita',
     'Agrega .withExpiresAt(...) (y opcionalmente .withIssuedAt(...)) al construir el token JWT. Un token sin expiración es válido indefinidamente si es robado.'),
    ('Campo contraseña almacenado como texto plano sin @Convert ni cifrado',
     'No almacenes contraseñas en texto plano. Usa un algoritmo de hash diseñado para contraseñas (Argon2, bcrypt) antes de guardarlas, en vez de mapear el campo password directamente como texto plano.'),
    ('Secreto hardcodeado detectado en código fuente',
     'Nunca hardcodees claves, tokens o contraseñas en el código fuente. Muévelos a variables de entorno o a un gestor de secretos (Vault, AWS Secrets Manager, etc.) y cárgalos en tiempo de ejecución.'),
    ('Datos sensibles registrados en logs',
     'Elimina las contraseñas y tokens de los mensajes de log. Si necesitas registrar el evento, enmascara el valor sensible (ej. password=***) o registra solo un identificador no sensible.'),
    ('TLS debe estar habilitado en produccion',
     'Habilita server.ssl.enabled=true y configura un certificado válido. Nunca transmitas credenciales o datos sensibles en texto plano sobre HTTP.'),
    ('MFA obligatorio para roles privilegiados',
     'Exige un segundo factor de autenticación (TOTP, WebAuthn, etc.) para los roles privilegiados (ej. SECURITY_ADMIN) antes de otorgar acceso, y configura la clave mfa.required.roles con esos roles.'),
    ('Politica de actualizacion de dependencias ausente',
     'Define una política de actualización periódica de dependencias (por ejemplo, no más de 30 días) y configura la clave dependency.update.maxAgeDays para hacerla cumplir, idealmente automatizada con Dependabot o Renovate.'),
    ('Verificacion de checksum de artefactos ausente',
     'Verifica la integridad de los artefactos externos con checksums SHA-256 antes de incorporarlos al build, y configura la clave artifact.checksum.verify para exigir esa verificación.'),
    ('Cabecera Content-Security-Policy no configurada',
     'Configura la cabecera Content-Security-Policy en las respuestas HTTP (por ejemplo default-src ''self'') para limitar qué scripts, estilos y recursos puede cargar el navegador, mitigando el impacto de un XSS aunque exista en el código.'),
    ('Dependencias con CVEs conocidos de alta severidad',
     'Actualiza la dependencia a una versión igual o superior a la indicada como segura para eliminar el CVE reportado. Agrega un escaneo de dependencias (OWASP Dependency-Check, npm audit, pip-audit) al pipeline de CI/CD para detectarlo automáticamente en cada build.'),
    ('Bloquear dependencias con CVE CRITICAL o HIGH',
     'Actualiza la dependencia afectada antes de desplegar. Configura el pipeline para bloquear el build si se detecta una dependencia con CVE de severidad CRITICAL o HIGH sin una versión corregida disponible.')
) AS seed(description, suggested_action)
WHERE pg_temp.payload_json(r.payload) ->> 'description' = seed.description
  AND pg_temp.suggested_action(r.payload) IS NULL;

-- ── Hallazgos ya guardados sin recomendación: toman la de su regla ──

UPDATE findings f SET suggested_action = pg_temp.suggested_action(r.payload)
FROM rules r
WHERE f.rule_id = r.id
  AND f.suggested_action IS NULL
  AND pg_temp.suggested_action(r.payload) IS NOT NULL;
