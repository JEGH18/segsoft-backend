-- V19: repara el daño de V18.
-- V18 usó `payload || jsonb_build_object(...)`, pero la columna `rules.payload`
-- es TEXT (no jsonb nativo), así que el operador `||` resolvió como
-- concatenación de texto: pegó dos objetos JSON uno junto al otro
-- (`{...}{...}`), sin separador, dejando el payload inválido como JSON.
-- Esta migración reconstruye el payload original de cada regla (mismo
-- contenido que V14/V17) con "suggestedAction" correctamente fusionado
-- dentro del mismo objeto JSON, usando la misma forma de asignación con
-- cast a ::jsonb que ya usaban V14/V17 (que sí funciona correctamente
-- para un cast de asignación hacia una columna TEXT).

UPDATE rules SET payload =
    '{"pattern": "(Statement|createStatement|executeQuery)\\s*\\(.*\\+", "description": "Concatenación directa de cadenas en query SQL", "suggestedAction": "Usa sentencias parametrizadas (PreparedStatement) en vez de concatenar el valor directamente en el SQL. Reemplaza algo como stmt.executeQuery(\"...\" + id) por: PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM tabla WHERE id = ?\"); ps.setString(1, id);"}'::jsonb
WHERE id = '77091813-5061-4d92-bc71-da99f577ae4c';

UPDATE rules SET payload =
    '{"pattern": "request\\.(getParameter|getAttribute)\\s*\\([^)]+\\)\\s*[^;]*query", "description": "Parámetro HTTP usado directamente en query sin validar", "suggestedAction": "No uses el valor de request.getParameter(...) directamente dentro de la consulta. Valida y sanitiza el input, y pásalo como parámetro vinculado (?) en una sentencia preparada, nunca concatenado en el texto del SQL."}'::jsonb
WHERE id = 'cc24c7f5-cf71-43ef-aa09-a92611bcb9a5';

UPDATE rules SET payload =
    '{"pattern": "SELECT\\s+\\*\\s+FROM", "description": "Consulta SELECT * sin filtro de columnas sensibles", "suggestedAction": "Evita SELECT *; especifica explícitamente las columnas que necesitas. Así reduces los datos sensibles expuestos (contraseñas, tokens) si la consulta llegara a ser explotada, y documentas mejor qué usa realmente el código."}'::jsonb
WHERE id = 'c32419fe-bf48-4176-aa72-cea341e51d89';

UPDATE rules SET payload =
    '{"pattern": "(dangerouslySetInnerHTML|v-html|\\[innerHTML\\])", "description": "Renderizado HTML sin sanitización explícita", "suggestedAction": "Evita insertar HTML sin sanitizar. Si necesitas renderizar HTML dinámico, sanea el contenido primero con una librería como DOMPurify — por ejemplo dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userInput) }} — en vez de pasar el string del usuario directamente."}'::jsonb
WHERE id = '4de5c3c3-20a4-40a5-aed0-fc3718a7c6d2';

UPDATE rules SET payload =
    '{"pattern": "innerHTML\\s*=\\s*[^\"'']", "description": "Asignación directa a innerHTML sin escape", "suggestedAction": "Reemplaza la asignación directa a innerHTML por textContent si solo necesitas texto plano, o sanitiza el HTML con DOMPurify antes de asignarlo, para evitar que un usuario inyecte <script> u otros elementos ejecutables."}'::jsonb
WHERE id = '0db11bf3-11e7-4d7e-bb4b-a93ade8c45e9';

UPDATE rules SET payload =
    '{"description":"Cabecera Content-Security-Policy no configurada","checks":[{"key":"security.headers.content-security-policy","must_exist":true}], "suggestedAction": "Configura la cabecera Content-Security-Policy en las respuestas HTTP (por ejemplo default-src ''self'') para limitar qué scripts, estilos y recursos puede cargar el navegador, mitigando el impacto de un XSS aunque exista en el código."}'::jsonb
WHERE id = 'b67e8a2f-bec6-4425-80da-94af184eebd1';

UPDATE rules SET payload =
    '{"description":"MFA obligatorio para roles privilegiados","checks":[{"key":"mfa.required.roles","must_exist":true}], "suggestedAction": "Exige un segundo factor de autenticación (TOTP, WebAuthn, etc.) para los roles privilegiados (ej. SECURITY_ADMIN) antes de otorgar acceso, y configura la clave mfa.required.roles con esos roles."}'::jsonb
WHERE id = '4a659b84-f37b-4421-8cad-3d4b347de2b0';

UPDATE rules SET payload =
    '{"pattern": "JWT\\.create\\(\\)(?!.*withExpiresAt|.*withIssuedAt)", "description": "Token JWT creado sin expiración explícita", "suggestedAction": "Agrega .withExpiresAt(...) (y opcionalmente .withIssuedAt(...)) al construir el token JWT. Un token sin expiración es válido indefinidamente si es robado."}'::jsonb
WHERE id = '511a830a-0828-497f-9831-3eb481c84608';

UPDATE rules SET payload =
    '{"pattern": "password.{0,20}(length\\s*[<>]=?\\s*[0-9]|matches\\s*\\(\"[^\"]{0,8}\"\\))", "description": "Validación de contraseña con longitud menor a 12 caracteres", "suggestedAction": "Exige contraseñas de al menos 12 caracteres, combinando mayúsculas, minúsculas, números y símbolos. Ajusta la validación de longitud actual para reflejar ese mínimo."}'::jsonb
WHERE id = '2bf8c4e6-6683-4361-947c-157e4a9f761d';

UPDATE rules SET payload =
    '{"pattern": "@PostMapping.*login(?!.*RateLimiter|.*Bucket4j|.*throttle)", "description": "Endpoint de login sin protección de rate limiting visible", "suggestedAction": "Agrega limitación de intentos (rate limiting) al endpoint de login — por ejemplo con Bucket4j o un RateLimiter — para frenar ataques de fuerza bruta y credential stuffing."}'::jsonb
WHERE id = '5f44e0a7-d94c-44a3-9992-3e4886e013c1';

UPDATE rules SET payload =
    '{"description":"TLS debe estar habilitado en produccion","checks":[{"key":"server.ssl.enabled","not_value":"false"}], "suggestedAction": "Habilita server.ssl.enabled=true y configura un certificado válido. Nunca transmitas credenciales o datos sensibles en texto plano sobre HTTP."}'::jsonb
WHERE id = '2087405f-7898-4774-b905-e2dd7bb61063';

UPDATE rules SET payload =
    '{"checks":[{"key":"server.enaled","not_value":"false"}], "suggestedAction": "Revisa la clave de configuración del servidor: no debe contener errores tipográficos y su valor no debe ser false en producción."}'::jsonb
WHERE id = '62445210-4ae5-4ea8-bc4f-9962aae532c7';

UPDATE rules SET payload =
    '{"pattern": "(apiKey|api_key|secret|password|token)\\s*=\\s*\"[A-Za-z0-9+/]{8,}\"", "description": "Secreto hardcodeado detectado en código fuente", "suggestedAction": "Nunca hardcodees claves, tokens o contraseñas en el código fuente. Muévelos a variables de entorno o a un gestor de secretos (Vault, AWS Secrets Manager, etc.) y cárgalos en tiempo de ejecución."}'::jsonb
WHERE id = 'eb0aa5ec-f941-4e07-bc09-8c43bb886a77';

UPDATE rules SET payload =
    '{"pattern": "@Column.*\\bpassword\\b|String\\s+password\\s*=", "description": "Campo contraseña almacenado como texto plano sin @Convert ni cifrado", "suggestedAction": "No almacenes contraseñas en texto plano. Usa un algoritmo de hash diseñado para contraseñas (Argon2, bcrypt) antes de guardarlas, en vez de mapear el campo password directamente como texto plano."}'::jsonb
WHERE id = 'e7476845-c0f5-4134-b242-ab0bd44560de';

UPDATE rules SET payload =
    '{"pattern": "log\\.(info|debug|warn|error).*password|logger\\.(info|debug).*token", "description": "Datos sensibles registrados en logs", "suggestedAction": "Elimina las contraseñas y tokens de los mensajes de log. Si necesitas registrar el evento, enmascara el valor sensible (ej. password=***) o registra solo un identificador no sensible."}'::jsonb
WHERE id = 'e99cd722-bae8-48b4-be37-f566d5240d79';

UPDATE rules SET payload =
    '{"description":"Dependencias con CVEs conocidos de alta severidad","known_vulnerable":[{"ecosystem":"maven","group":"org.apache.logging.log4j","artifact":"log4j-core","below_version":"2.17.1","cve":"CVE-2021-44228"},{"ecosystem":"maven","group":"org.apache.struts","artifact":"struts2-core","below_version":"2.5.33","cve":"CVE-2021-31805"},{"ecosystem":"npm","package":"lodash","below_version":"4.17.21","cve":"CVE-2021-23337"},{"ecosystem":"npm","package":"minimist","below_version":"1.2.6","cve":"CVE-2021-44906"},{"ecosystem":"pypi","package":"requests","below_version":"2.20.0","cve":"CVE-2018-18074"},{"ecosystem":"pypi","package":"pyyaml","below_version":"5.4","cve":"CVE-2020-14343"}], "suggestedAction": "Actualiza la dependencia a una versión igual o superior a la indicada como segura para eliminar el CVE reportado. Agrega un escaneo de dependencias (OWASP Dependency-Check, npm audit, pip-audit) al pipeline de CI/CD para detectarlo automáticamente en cada build."}'::jsonb
WHERE id = 'c9178431-390d-4659-8265-bb929a6cc612';

UPDATE rules SET payload =
    '{"description":"Bloquear dependencias con CVE CRITICAL o HIGH","known_vulnerable":[{"ecosystem":"maven","group":"org.apache.logging.log4j","artifact":"log4j-core","below_version":"2.17.1","cve":"CVE-2021-44228"},{"ecosystem":"maven","group":"org.springframework","artifact":"spring-core","below_version":"5.3.18","cve":"CVE-2022-22965"}], "suggestedAction": "Actualiza la dependencia afectada antes de desplegar. Configura el pipeline para bloquear el build si se detecta una dependencia con CVE de severidad CRITICAL o HIGH sin una versión corregida disponible."}'::jsonb
WHERE id = 'd6b986a9-bfa4-4d50-a21c-c881f0e7e060';

UPDATE rules SET payload =
    '{"description":"Politica de actualizacion de dependencias ausente","checks":[{"key":"dependency.update.maxAgeDays","must_exist":true}], "suggestedAction": "Define una política de actualización periódica de dependencias (por ejemplo, no más de 30 días) y configura la clave dependency.update.maxAgeDays para hacerla cumplir, idealmente automatizada con Dependabot o Renovate."}'::jsonb
WHERE id = '56b639db-8c92-46f7-b7e2-0d01da20d992';

UPDATE rules SET payload =
    '{"description":"Verificacion de checksum de artefactos ausente","checks":[{"key":"artifact.checksum.verify","must_exist":true}], "suggestedAction": "Verifica la integridad de los artefactos externos con checksums SHA-256 antes de incorporarlos al build, y configura la clave artifact.checksum.verify para exigir esa verificación."}'::jsonb
WHERE id = 'cce45ebc-85b6-45bd-88ae-7e77dacf0b23';
