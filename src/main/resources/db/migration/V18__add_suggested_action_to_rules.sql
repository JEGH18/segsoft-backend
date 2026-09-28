-- V18: recomendaciones reales de remediación por regla.
-- Cada regla detecta un patrón muy específico, así que cada una recibe su
-- propio texto de solución (no un mensaje genérico), guardado dentro de su
-- propio payload JSONB bajo la clave "suggestedAction".

-- SQL_INJECTION
UPDATE rules SET payload = payload || jsonb_build_object('suggestedAction',
    'Usa sentencias parametrizadas (PreparedStatement) en vez de concatenar el valor directamente en el SQL. Reemplaza algo como stmt.executeQuery("..." + id) por: PreparedStatement ps = conn.prepareStatement("SELECT * FROM tabla WHERE id = ?"); ps.setString(1, id);')
WHERE id = '77091813-5061-4d92-bc71-da99f577ae4c';

UPDATE rules SET payload = payload || jsonb_build_object('suggestedAction',
    'No uses el valor de request.getParameter(...) directamente dentro de la consulta. Valida y sanitiza el input, y pásalo como parámetro vinculado (?) en una sentencia preparada, nunca concatenado en el texto del SQL.')
WHERE id = 'cc24c7f5-cf71-43ef-aa09-a92611bcb9a5';

UPDATE rules SET payload = payload || jsonb_build_object('suggestedAction',
    'Evita SELECT *; especifica explícitamente las columnas que necesitas. Así reduces los datos sensibles expuestos (contraseñas, tokens) si la consulta llegara a ser explotada, y documentas mejor qué usa realmente el código.')
WHERE id = 'c32419fe-bf48-4176-aa72-cea341e51d89';

-- XSS
UPDATE rules SET payload = payload || jsonb_build_object('suggestedAction',
    'Evita insertar HTML sin sanitizar. Si necesitas renderizar HTML dinámico, sanea el contenido primero con una librería como DOMPurify — por ejemplo dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userInput) }} — en vez de pasar el string del usuario directamente.')
WHERE id = '4de5c3c3-20a4-40a5-aed0-fc3718a7c6d2';

UPDATE rules SET payload = payload || jsonb_build_object('suggestedAction',
    'Reemplaza la asignación directa a innerHTML por textContent si solo necesitas texto plano, o sanitiza el HTML con DOMPurify antes de asignarlo, para evitar que un usuario inyecte <script> u otros elementos ejecutables.')
WHERE id = '0db11bf3-11e7-4d7e-bb4b-a93ade8c45e9';

UPDATE rules SET payload = payload || jsonb_build_object('suggestedAction',
    'Configura la cabecera Content-Security-Policy en las respuestas HTTP (por ejemplo default-src ''self'') para limitar qué scripts, estilos y recursos puede cargar el navegador, mitigando el impacto de un XSS aunque exista en el código.')
WHERE id = 'b67e8a2f-bec6-4425-80da-94af184eebd1';

-- AUTHENTICATION_FAILURE
UPDATE rules SET payload = payload || jsonb_build_object('suggestedAction',
    'Exige un segundo factor de autenticación (TOTP, WebAuthn, etc.) para los roles privilegiados (ej. SECURITY_ADMIN) antes de otorgar acceso, y configura la clave mfa.required.roles con esos roles.')
WHERE id = '4a659b84-f37b-4421-8cad-3d4b347de2b0';

UPDATE rules SET payload = payload || jsonb_build_object('suggestedAction',
    'Agrega .withExpiresAt(...) (y opcionalmente .withIssuedAt(...)) al construir el token JWT. Un token sin expiración es válido indefinidamente si es robado.')
WHERE id = '511a830a-0828-497f-9831-3eb481c84608';

UPDATE rules SET payload = payload || jsonb_build_object('suggestedAction',
    'Exige contraseñas de al menos 12 caracteres, combinando mayúsculas, minúsculas, números y símbolos. Ajusta la validación de longitud actual para reflejar ese mínimo.')
WHERE id = '2bf8c4e6-6683-4361-947c-157e4a9f761d';

UPDATE rules SET payload = payload || jsonb_build_object('suggestedAction',
    'Agrega limitación de intentos (rate limiting) al endpoint de login — por ejemplo con Bucket4j o un RateLimiter — para frenar ataques de fuerza bruta y credential stuffing.')
WHERE id = '5f44e0a7-d94c-44a3-9992-3e4886e013c1';

-- INSECURE_DATA_HANDLING
UPDATE rules SET payload = payload || jsonb_build_object('suggestedAction',
    'Habilita server.ssl.enabled=true y configura un certificado válido. Nunca transmitas credenciales o datos sensibles en texto plano sobre HTTP.')
WHERE id = '2087405f-7898-4774-b905-e2dd7bb61063';

UPDATE rules SET payload = payload || jsonb_build_object('suggestedAction',
    'Revisa la clave de configuración del servidor: no debe contener errores tipográficos y su valor no debe ser false en producción.')
WHERE id = '62445210-4ae5-4ea8-bc4f-9962aae532c7';

UPDATE rules SET payload = payload || jsonb_build_object('suggestedAction',
    'Nunca hardcodees claves, tokens o contraseñas en el código fuente. Muévelos a variables de entorno o a un gestor de secretos (Vault, AWS Secrets Manager, etc.) y cárgalos en tiempo de ejecución.')
WHERE id = 'eb0aa5ec-f941-4e07-bc09-8c43bb886a77';

UPDATE rules SET payload = payload || jsonb_build_object('suggestedAction',
    'No almacenes contraseñas en texto plano. Usa un algoritmo de hash diseñado para contraseñas (Argon2, bcrypt) antes de guardarlas, en vez de mapear el campo password directamente como texto plano.')
WHERE id = 'e7476845-c0f5-4134-b242-ab0bd44560de';

UPDATE rules SET payload = payload || jsonb_build_object('suggestedAction',
    'Elimina las contraseñas y tokens de los mensajes de log. Si necesitas registrar el evento, enmascara el valor sensible (ej. password=***) o registra solo un identificador no sensible.')
WHERE id = 'e99cd722-bae8-48b4-be37-f566d5240d79';

-- DEPENDENCY_VULNERABILITY
UPDATE rules SET payload = payload || jsonb_build_object('suggestedAction',
    'Actualiza la dependencia a una versión igual o superior a la indicada como segura para eliminar el CVE reportado. Agrega un escaneo de dependencias (OWASP Dependency-Check, npm audit, pip-audit) al pipeline de CI/CD para detectarlo automáticamente en cada build.')
WHERE id = 'c9178431-390d-4659-8265-bb929a6cc612';

UPDATE rules SET payload = payload || jsonb_build_object('suggestedAction',
    'Actualiza la dependencia afectada antes de desplegar. Configura el pipeline para bloquear el build si se detecta una dependencia con CVE de severidad CRITICAL o HIGH sin una versión corregida disponible.')
WHERE id = 'd6b986a9-bfa4-4d50-a21c-c881f0e7e060';

UPDATE rules SET payload = payload || jsonb_build_object('suggestedAction',
    'Define una política de actualización periódica de dependencias (por ejemplo, no más de 30 días) y configura la clave dependency.update.maxAgeDays para hacerla cumplir, idealmente automatizada con Dependabot o Renovate.')
WHERE id = '56b639db-8c92-46f7-b7e2-0d01da20d992';

UPDATE rules SET payload = payload || jsonb_build_object('suggestedAction',
    'Verifica la integridad de los artefactos externos con checksums SHA-256 antes de incorporarlos al build, y configura la clave artifact.checksum.verify para exigir esa verificación.')
WHERE id = 'cce45ebc-85b6-45bd-88ae-7e77dacf0b23';
