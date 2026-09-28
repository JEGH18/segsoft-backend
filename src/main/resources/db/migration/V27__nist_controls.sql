-- V27: incorpora el marco NIST SP 800-53 al catálogo.
--
-- Dos catálogos distintos, con propósitos distintos:
--  1) nist_controls: catálogo de referencia amplio de NIST (por familia:
--     AC, AU, IA, SC, SI), expuesto via GET /api/v1/frameworks/nist/controls
--     para que un SECURITY_ADMIN pueda explorar/elegir controles reales.
--  2) framework_controls: la tabla genérica ya existente que el backend usa
--     para DERIVAR automáticamente el control_id de una política nueva a
--     partir de (framework, category) -- ver PolicyService.create(). NIST
--     necesita sus 5 filas ahí (una por categoría CCS) para que crear una
--     política con framework=NIST_SP_800_53 funcione en absoluto.

CREATE TABLE nist_controls (
    id     VARCHAR(20) PRIMARY KEY,
    title  VARCHAR(200) NOT NULL,
    family VARCHAR(10) NOT NULL
);

CREATE INDEX idx_nist_controls_family ON nist_controls (family);

INSERT INTO nist_controls (id, title, family) VALUES
-- AC: Access Control
('AC-2',  'Account Management', 'AC'),
('AC-3',  'Access Enforcement', 'AC'),
('AC-6',  'Least Privilege', 'AC'),
-- AU: Audit and Accountability
('AU-2',  'Event Logging', 'AU'),
('AU-9',  'Protection of Audit Information', 'AU'),
-- IA: Identification and Authentication
('IA-2',  'Identification and Authentication (Organizational Users)', 'IA'),
('IA-5',  'Authenticator Management', 'IA'),
-- SC: System and Communications Protection
('SC-8',  'Transmission Confidentiality and Integrity', 'SC'),
('SC-13', 'Cryptographic Protection', 'SC'),
('SC-28', 'Protection of Information at Rest', 'SC'),
-- SI: System and Information Integrity
('SI-2',  'Flaw Remediation', 'SI'),
('SI-10', 'Information Input Validation', 'SI'),
('SI-11', 'Error Handling', 'SI');

-- Derivación automática de control_id por categoría CCS para NIST_SP_800_53
-- (mismo esquema (framework, category) -> control_id/control_name que ya
-- usan ISO_27001 / OWASP_TOP_10_2021 / OWASP_ASVS / DEVSECOPS).
INSERT INTO framework_controls (framework, category, control_id, control_name) VALUES
('NIST_SP_800_53', 'SQL_INJECTION',            'SI-10', 'Information Input Validation'),
('NIST_SP_800_53', 'XSS',                      'SI-10', 'Information Input Validation'),
('NIST_SP_800_53', 'AUTHENTICATION_FAILURE',   'IA-5',  'Authenticator Management'),
('NIST_SP_800_53', 'INSECURE_DATA_HANDLING',   'SC-13', 'Cryptographic Protection'),
('NIST_SP_800_53', 'DEPENDENCY_VULNERABILITY', 'SI-2',  'Flaw Remediation');

-- Al menos una política NIST por categoría (subtarea 4), con su regla
-- técnica asociada -- diversificando hacia patrones Python, que el resto
-- del catálogo apenas cubre.
INSERT INTO policies (name, description, category, framework, control_id, status, weight) VALUES
('Validación de entradas antes de construir consultas SQL',
 'Toda entrada externa usada para construir una consulta SQL debe validarse o vincularse como parámetro; queda prohibido interpolarla directamente en el texto de la sentencia.',
 'SQL_INJECTION', 'NIST_SP_800_53', 'SI-10', 'ACTIVE', 85),

('Validación de entradas antes de renderizar contenido dinámico',
 'Todo contenido que provenga de una entrada externa y se incluya en una respuesta renderizada debe pasar por el escape automático del motor de plantillas; queda prohibido forzarlo a "seguro" sin sanitización previa.',
 'XSS', 'NIST_SP_800_53', 'SI-10', 'ACTIVE', 80),

('Gestión segura de credenciales de autenticación',
 'Las contraseñas y demás autenticadores deben protegerse con un algoritmo de hashing diseñado para contraseñas, nunca con funciones hash de propósito general.',
 'AUTHENTICATION_FAILURE', 'NIST_SP_800_53', 'IA-5', 'ACTIVE', 88),

('Uso de algoritmos criptográficos aprobados',
 'La protección criptográfica de datos sensibles debe usar algoritmos y modos de operación vigentes; quedan prohibidos los algoritmos o modos débiles conocidos (DES, ECB).',
 'INSECURE_DATA_HANDLING', 'NIST_SP_800_53', 'SC-13', 'ACTIVE', 90),

('Remediación oportuna de vulnerabilidades en componentes',
 'El pipeline debe verificar automáticamente que las dependencias del proyecto no tengan vulnerabilidades conocidas sin parche disponible.',
 'DEPENDENCY_VULNERABILITY', 'NIST_SP_800_53', 'SI-2', 'ACTIVE', 82);

INSERT INTO rules (policy_id, type, payload, severity, cwe_id, category, languages)
SELECT id, 'PATTERN_REGEX',
       jsonb_build_object(
           'pattern', 'cursor\.execute\s*\(\s*f["'']',
           'description', 'Consulta SQL construida con f-string en vez de parámetros vinculados',
           'suggestedAction', 'Usa parámetros vinculados en vez de f-strings: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,)) en lugar de cursor.execute(f"SELECT * FROM users WHERE id = {user_id}").'
       ),
       'CRITICAL', 'CWE-89', 'SQL_INJECTION', '["python"]'::jsonb
FROM policies WHERE name = 'Validación de entradas antes de construir consultas SQL';

INSERT INTO rules (policy_id, type, payload, severity, cwe_id, category, languages)
SELECT id, 'PATTERN_REGEX',
       jsonb_build_object(
           'pattern', 'mark_safe\s*\(',
           'description', 'Contenido marcado como seguro (mark_safe) sin sanitización previa visible',
           'suggestedAction', 'Evita mark_safe() con contenido que incluya datos de usuario -- Django ya escapa automáticamente por defecto. Si necesitas HTML dinámico, sanea el contenido con bleach.clean(...) antes de marcarlo como seguro.'
       ),
       'HIGH', 'CWE-79', 'XSS', '["python"]'::jsonb
FROM policies WHERE name = 'Validación de entradas antes de renderizar contenido dinámico';

INSERT INTO rules (policy_id, type, payload, severity, cwe_id, category, languages)
SELECT id, 'PATTERN_REGEX',
       jsonb_build_object(
           'pattern', 'hashlib\.(md5|sha1)\s*\([^)]{0,60}password',
           'description', 'Hash de propósito general (MD5/SHA-1) aplicado a una contraseña',
           'suggestedAction', 'No uses MD5/SHA-1 para contraseñas: son demasiado rápidos y vulnerables a fuerza bruta con GPU. Usa un algoritmo diseñado para contraseñas como bcrypt (passlib.hash.bcrypt) o Argon2 (argon2-cffi).'
       ),
       'CRITICAL', 'CWE-916', 'AUTHENTICATION_FAILURE', '["python"]'::jsonb
FROM policies WHERE name = 'Gestión segura de credenciales de autenticación';

INSERT INTO rules (policy_id, type, payload, severity, cwe_id, category, languages)
SELECT id, 'PATTERN_REGEX',
       jsonb_build_object(
           'pattern', 'Cipher\.getInstance\s*\(\s*"(DES|[^"]*\/ECB\/)',
           'description', 'Algoritmo o modo de cifrado débil (DES o ECB)',
           'suggestedAction', 'Reemplaza DES/ECB por AES en modo GCM (AES/GCM/NoPadding), que además ofrece cifrado autenticado. ECB no debe usarse nunca porque no oculta patrones repetidos en los datos.'
       ),
       'CRITICAL', 'CWE-327', 'INSECURE_DATA_HANDLING', '["java","kotlin"]'::jsonb
FROM policies WHERE name = 'Uso de algoritmos criptográficos aprobados';

INSERT INTO rules (policy_id, type, payload, severity, cwe_id, category, languages)
SELECT id, 'DEPENDENCY_CHECK',
       jsonb_build_object(
           'tool', 'pip-audit',
           'failOnSeverity', 'HIGH',
           'description', 'Escaneo de CVEs en dependencias Python del proyecto'
       ),
       'HIGH', 'CWE-1035', 'DEPENDENCY_VULNERABILITY', '[]'::jsonb
FROM policies WHERE name = 'Remediación oportuna de vulnerabilidades en componentes';

UPDATE rules SET payload = payload || jsonb_build_object('suggestedAction',
    'Ejecuta pip-audit (o Safety) en el pipeline de CI/CD para bloquear builds con dependencias Python que tengan CVEs conocidos sin parche disponible.')
WHERE policy_id = (SELECT id FROM policies WHERE name = 'Remediación oportuna de vulnerabilidades en componentes');
