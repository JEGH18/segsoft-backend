-- V12: políticas de seguridad iniciales para desarrollo y demostración
-- Cubre las 5 categorías x varios frameworks

INSERT INTO policies (name, description, category, framework, control_id, status, weight)
VALUES

-- SQL_INJECTION
('Prevención de SQL Injection con consultas parametrizadas',
 'Todo acceso a base de datos debe usar PreparedStatement o equivalente ORM. Está prohibida la concatenación de cadenas en queries.',
 'SQL_INJECTION', 'OWASP_TOP_10_2021', 'A03:2021', 'ACTIVE', 90),

('Control de acceso a datos por rol',
 'Las consultas a la base de datos deben estar restringidas al mínimo privilegio necesario según el rol del usuario autenticado.',
 'SQL_INJECTION', 'ISO_27001', 'A.9.4.1', 'ACTIVE', 75),

('Validación de entradas en capa de acceso a datos',
 'Toda entrada de usuario que llegue a una consulta debe validarse con expresiones regulares o listas blancas antes de procesarse.',
 'SQL_INJECTION', 'OWASP_ASVS', 'V5.3.4', 'ACTIVE', 80),

-- XSS
('Codificación de salida HTML',
 'Toda variable renderizada en plantillas HTML debe estar codificada (HTML-escape) para prevenir Cross-Site Scripting reflejado y almacenado.',
 'XSS', 'OWASP_TOP_10_2021', 'A03:2021', 'ACTIVE', 85),

('Content Security Policy obligatoria',
 'Las respuestas HTTP deben incluir la cabecera Content-Security-Policy con directivas que restrinjan fuentes de scripts y estilos.',
 'XSS', 'OWASP_ASVS', 'V14.4.3', 'ACTIVE', 70),

('Sanitización de contenido generado por usuarios',
 'Todo contenido HTML ingresado por el usuario debe pasar por una librería de sanitización aprobada antes de persistirse o mostrarse.',
 'XSS', 'ISO_27001', 'A.14.2.5', 'ACTIVE', 80),

-- AUTHENTICATION_FAILURE
('Política de contraseñas seguras',
 'Las contraseñas deben tener mínimo 12 caracteres, incluir mayúsculas, minúsculas, dígitos y símbolos. No reutilizar las últimas 5.',
 'AUTHENTICATION_FAILURE', 'OWASP_TOP_10_2021', 'A07:2021', 'ACTIVE', 90),

('Bloqueo de cuenta tras intentos fallidos',
 'Después de 5 intentos de autenticación fallidos consecutivos, la cuenta debe bloquearse por al menos 15 minutos.',
 'AUTHENTICATION_FAILURE', 'ISO_27001', 'A.9.4.2', 'ACTIVE', 85),

('Tokens JWT con expiración y rotación',
 'Los tokens de acceso deben expirar en máximo 15 minutos. El refresh token debe rotarse en cada uso y tener revocación activa.',
 'AUTHENTICATION_FAILURE', 'OWASP_ASVS', 'V3.5.1', 'ACTIVE', 88),

('Autenticación multifactor para roles privilegiados',
 'Los usuarios con roles SECURITY_ADMIN o equivalente deben autenticarse con un segundo factor (TOTP o hardware key).',
 'AUTHENTICATION_FAILURE', 'ISO_27001', 'A.9.4.2', 'ACTIVE', 92),

-- INSECURE_DATA_HANDLING
('Cifrado de datos sensibles en reposo',
 'Los campos que contengan PII, credenciales o datos de salud deben estar cifrados en base de datos con AES-256 o superior.',
 'INSECURE_DATA_HANDLING', 'ISO_27001', 'A.10.1.1', 'ACTIVE', 90),

('No almacenar secretos en código fuente',
 'Claves de API, contraseñas y tokens no deben aparecer hardcodeados en el código. Usar variables de entorno o gestores de secretos.',
 'INSECURE_DATA_HANDLING', 'DEVSECOPS', NULL, 'ACTIVE', 95),

('Registro seguro sin datos sensibles',
 'Los logs no deben registrar contraseñas, tokens, números de tarjeta, ni PII. Aplicar enmascaramiento en los appenders de logging.',
 'INSECURE_DATA_HANDLING', 'OWASP_ASVS', 'V7.1.1', 'ACTIVE', 80),

('Transmisión cifrada con TLS 1.2+',
 'Toda comunicación entre cliente-servidor y entre microservicios debe realizarse sobre TLS 1.2 o superior. HTTP plano no permitido en producción.',
 'INSECURE_DATA_HANDLING', 'ISO_27001', 'A.10.1.2', 'ACTIVE', 88),

-- DEPENDENCY_VULNERABILITY
('Escaneo de dependencias en CI/CD',
 'El pipeline de integración continua debe incluir un paso de análisis de vulnerabilidades conocidas (OWASP Dependency-Check o equivalente).',
 'DEPENDENCY_VULNERABILITY', 'DEVSECOPS', NULL, 'ACTIVE', 85),

('Prohibición de dependencias con CVE crítico',
 'No se permite desplegar artefactos que incluyan dependencias con CVE de severidad CRITICAL o HIGH sin mitigación documentada.',
 'DEPENDENCY_VULNERABILITY', 'OWASP_TOP_10_2021', 'A06:2021', 'ACTIVE', 92),

('Actualización periódica de dependencias',
 'Las dependencias de terceros deben revisarse y actualizarse al menos cada 30 días. Las versiones con soporte expirado deben reemplazarse.',
 'DEPENDENCY_VULNERABILITY', 'ISO_27001', 'A.12.6.1', 'ACTIVE', 75),

('Verificación de integridad de artefactos',
 'Los artefactos descargados de repositorios externos deben verificarse con checksums SHA-256 firmados antes de incorporarse al build.',
 'DEPENDENCY_VULNERABILITY', 'DEVSECOPS', NULL, 'ACTIVE', 78);
