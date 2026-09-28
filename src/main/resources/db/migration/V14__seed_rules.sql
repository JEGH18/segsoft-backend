-- V14: una regla técnica mínima por cada política seed (V12)
-- Necesario para que PolicySelectionService.validatePolicies() no rechace la selección.

-- SQL_INJECTION
INSERT INTO rules (policy_id, type, payload, severity, cwe_id, category, languages)
SELECT id, 'PATTERN_REGEX',
       '{"pattern":"(Statement|createStatement|executeQuery)\\s*\\(.*\\+","description":"Concatenación directa de cadenas en query SQL"}'::jsonb,
       'CRITICAL', 'CWE-89', 'SQL_INJECTION', '["java","kotlin","groovy"]'::jsonb
FROM policies WHERE name = 'Prevención de SQL Injection con consultas parametrizadas';

INSERT INTO rules (policy_id, type, payload, severity, cwe_id, category, languages)
SELECT id, 'PATTERN_REGEX',
       '{"pattern":"SELECT\\s+\\*\\s+FROM","description":"Consulta SELECT * sin filtro de columnas sensibles"}'::jsonb,
       'MEDIUM', 'CWE-89', 'SQL_INJECTION', '["java","kotlin","sql"]'::jsonb
FROM policies WHERE name = 'Control de acceso a datos por rol';

INSERT INTO rules (policy_id, type, payload, severity, cwe_id, category, languages)
SELECT id, 'PATTERN_REGEX',
       '{"pattern":"request\\.(getParameter|getAttribute)\\s*\\([^)]+\\)\\s*[^;]*query","description":"Parámetro HTTP usado directamente en query sin validar"}'::jsonb,
       'HIGH', 'CWE-20', 'SQL_INJECTION', '["java","kotlin"]'::jsonb
FROM policies WHERE name = 'Validación de entradas en capa de acceso a datos';

-- XSS
INSERT INTO rules (policy_id, type, payload, severity, cwe_id, category, languages)
SELECT id, 'PATTERN_REGEX',
       '{"pattern":"innerHTML\\s*=\\s*[^\"'']","description":"Asignación directa a innerHTML sin escape"}'::jsonb,
       'HIGH', 'CWE-79', 'XSS', '["javascript","typescript"]'::jsonb
FROM policies WHERE name = 'Codificación de salida HTML';

INSERT INTO rules (policy_id, type, payload, severity, cwe_id, category, languages)
SELECT id, 'CONFIG_CHECK',
       '{"header":"Content-Security-Policy","required":true,"description":"Cabecera CSP obligatoria en todas las respuestas HTTP"}'::jsonb,
       'MEDIUM', 'CWE-693', 'XSS', '[]'::jsonb
FROM policies WHERE name = 'Content Security Policy obligatoria';

INSERT INTO rules (policy_id, type, payload, severity, cwe_id, category, languages)
SELECT id, 'PATTERN_REGEX',
       '{"pattern":"(dangerouslySetInnerHTML|v-html|\\[innerHTML\\])","description":"Renderizado HTML sin sanitización explícita"}'::jsonb,
       'HIGH', 'CWE-79', 'XSS', '["javascript","typescript"]'::jsonb
FROM policies WHERE name = 'Sanitización de contenido generado por usuarios';

-- AUTHENTICATION_FAILURE
INSERT INTO rules (policy_id, type, payload, severity, cwe_id, category, languages)
SELECT id, 'PATTERN_REGEX',
       '{"pattern":"password.{0,20}(length\\s*[<>]=?\\s*[0-9]|matches\\s*\\(\"[^\"]{0,8}\"\\))","description":"Validación de contraseña con longitud menor a 12 caracteres"}'::jsonb,
       'HIGH', 'CWE-521', 'AUTHENTICATION_FAILURE', '["java","kotlin"]'::jsonb
FROM policies WHERE name = 'Política de contraseñas seguras';

INSERT INTO rules (policy_id, type, payload, severity, cwe_id, category, languages)
SELECT id, 'PATTERN_REGEX',
       '{"pattern":"@PostMapping.*login(?!.*RateLimiter|.*Bucket4j|.*throttle)","description":"Endpoint de login sin protección de rate limiting visible"}'::jsonb,
       'HIGH', 'CWE-307', 'AUTHENTICATION_FAILURE', '["java","kotlin"]'::jsonb
FROM policies WHERE name = 'Bloqueo de cuenta tras intentos fallidos';

INSERT INTO rules (policy_id, type, payload, severity, cwe_id, category, languages)
SELECT id, 'PATTERN_REGEX',
       '{"pattern":"JWT\\.create\\(\\)(?!.*withExpiresAt|.*withIssuedAt)","description":"Token JWT creado sin expiración explícita"}'::jsonb,
       'CRITICAL', 'CWE-613', 'AUTHENTICATION_FAILURE', '["java","kotlin"]'::jsonb
FROM policies WHERE name = 'Tokens JWT con expiración y rotación';

INSERT INTO rules (policy_id, type, payload, severity, cwe_id, category, languages)
SELECT id, 'CONFIG_CHECK',
       '{"key":"mfa.required.roles","expectedValues":["SECURITY_ADMIN"],"description":"MFA obligatorio para roles privilegiados"}'::jsonb,
       'CRITICAL', 'CWE-308', 'AUTHENTICATION_FAILURE', '[]'::jsonb
FROM policies WHERE name = 'Autenticación multifactor para roles privilegiados';

-- INSECURE_DATA_HANDLING
INSERT INTO rules (policy_id, type, payload, severity, cwe_id, category, languages)
SELECT id, 'PATTERN_REGEX',
       '{"pattern":"@Column.*\\bpassword\\b|String\\s+password\\s*=","description":"Campo contraseña almacenado como texto plano sin @Convert ni cifrado"}'::jsonb,
       'CRITICAL', 'CWE-312', 'INSECURE_DATA_HANDLING', '["java","kotlin"]'::jsonb
FROM policies WHERE name = 'Cifrado de datos sensibles en reposo';

INSERT INTO rules (policy_id, type, payload, severity, cwe_id, category, languages)
SELECT id, 'PATTERN_REGEX',
       '{"pattern":"(apiKey|api_key|secret|password|token)\\s*=\\s*\"[A-Za-z0-9+/]{8,}\"","description":"Secreto hardcodeado detectado en código fuente"}'::jsonb,
       'CRITICAL', 'CWE-798', 'INSECURE_DATA_HANDLING', '["java","kotlin","python","javascript","typescript"]'::jsonb
FROM policies WHERE name = 'No almacenar secretos en código fuente';

INSERT INTO rules (policy_id, type, payload, severity, cwe_id, category, languages)
SELECT id, 'PATTERN_REGEX',
       '{"pattern":"log\\.(info|debug|warn|error).*password|logger\\.(info|debug).*token","description":"Datos sensibles registrados en logs"}'::jsonb,
       'HIGH', 'CWE-532', 'INSECURE_DATA_HANDLING', '["java","kotlin","python"]'::jsonb
FROM policies WHERE name = 'Registro seguro sin datos sensibles';

INSERT INTO rules (policy_id, type, payload, severity, cwe_id, category, languages)
SELECT id, 'CONFIG_CHECK',
       '{"key":"server.ssl.enabled","expectedValue":"true","description":"TLS debe estar habilitado en producción"}'::jsonb,
       'HIGH', 'CWE-319', 'INSECURE_DATA_HANDLING', '[]'::jsonb
FROM policies WHERE name = 'Transmisión cifrada con TLS 1.2+';

-- DEPENDENCY_VULNERABILITY
INSERT INTO rules (policy_id, type, payload, severity, cwe_id, category, languages)
SELECT id, 'DEPENDENCY_CHECK',
       '{"tool":"owasp-dependency-check","failOnSeverity":"HIGH","description":"Escaneo de CVEs en dependencias del proyecto"}'::jsonb,
       'HIGH', 'CWE-1035', 'DEPENDENCY_VULNERABILITY', '[]'::jsonb
FROM policies WHERE name = 'Escaneo de dependencias en CI/CD';

INSERT INTO rules (policy_id, type, payload, severity, cwe_id, category, languages)
SELECT id, 'DEPENDENCY_CHECK',
       '{"minCvssScore":7.0,"blockOnCritical":true,"description":"Bloquear artefactos con dependencias CVE CRITICAL o HIGH"}'::jsonb,
       'CRITICAL', 'CWE-1035', 'DEPENDENCY_VULNERABILITY', '[]'::jsonb
FROM policies WHERE name = 'Prohibición de dependencias con CVE crítico';

INSERT INTO rules (policy_id, type, payload, severity, cwe_id, category, languages)
SELECT id, 'CONFIG_CHECK',
       '{"key":"dependency.update.maxAgeDays","expectedValue":"30","description":"Las dependencias no deben tener más de 30 días sin revisar"}'::jsonb,
       'MEDIUM', 'CWE-1104', 'DEPENDENCY_VULNERABILITY', '[]'::jsonb
FROM policies WHERE name = 'Actualización periódica de dependencias';

INSERT INTO rules (policy_id, type, payload, severity, cwe_id, category, languages)
SELECT id, 'CONFIG_CHECK',
       '{"key":"artifact.checksum.verify","expectedValue":"sha256","description":"Verificación de checksum SHA-256 en artefactos externos"}'::jsonb,
       'HIGH', 'CWE-494', 'DEPENDENCY_VULNERABILITY', '[]'::jsonb
FROM policies WHERE name = 'Verificación de integridad de artefactos';
