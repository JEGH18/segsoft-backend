-- V29: reproduce en migración 5 reglas que solo existían en la base de datos
-- viva (creadas manualmente vía API, nunca capturadas en una migración -- si
-- el volumen de Docker se recreaba, desaparecían sin dejar rastro), repara el
-- payload roto de la regla "pip-audit" (mismo bug de concatenación de JSON en
-- columna TEXT que V19 ya corrigió para otras filas, pero esta se creó
-- después y quedó fuera de esa reparación), y archiva una regla de prueba sin
-- terminar ("sdfsdf" / payload {"pattern":"dsfsf"}) que no coincide con el
-- schema real que espera ast_executor.py y nunca produjo un hallazgo.

-- ── Reglas Python/Django reales que ya corrían en producción, ahora reproducibles ──

INSERT INTO rules (policy_id, type, payload, severity, cwe_id, category, languages)
SELECT id, 'PATTERN_REGEX',
       '{"pattern":"cursor\\.execute\\s*\\(\\s*f[\"'']","description":"Consulta SQL construida con f-string en vez de parámetros vinculados","suggestedAction":"Usa parámetros vinculados en vez de f-strings: cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,)) en lugar de cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")."}'::jsonb,
       'CRITICAL', 'CWE-89', 'SQL_INJECTION', '["python"]'::jsonb
FROM policies WHERE name = 'Validación de entradas antes de construir consultas SQL'
  AND NOT EXISTS (SELECT 1 FROM rules WHERE payload LIKE '%cursor.execute%');

INSERT INTO rules (policy_id, type, payload, severity, cwe_id, category, languages)
SELECT id, 'PATTERN_REGEX',
       '{"pattern":"mark_safe\\s*\\(","description":"Contenido marcado como seguro (mark_safe) sin sanitización previa visible","suggestedAction":"Evita mark_safe() con contenido que incluya datos de usuario -- Django ya escapa automáticamente por defecto. Si necesitas HTML dinámico, sanea el contenido con bleach.clean(...) antes de marcarlo como seguro."}'::jsonb,
       'HIGH', 'CWE-79', 'XSS', '["python"]'::jsonb
FROM policies WHERE name = 'Validación de entradas antes de renderizar contenido dinámico'
  AND NOT EXISTS (SELECT 1 FROM rules WHERE payload LIKE '%mark_safe%');

INSERT INTO rules (policy_id, type, payload, severity, cwe_id, category, languages)
SELECT id, 'PATTERN_REGEX',
       '{"pattern":"hashlib\\.(md5|sha1)\\s*\\([^)]{0,60}password","description":"Hash de propósito general (MD5/SHA-1) aplicado a una contraseña","suggestedAction":"No uses MD5/SHA-1 para contraseñas: son demasiado rápidos y vulnerables a fuerza bruta con GPU. Usa un algoritmo diseñado para contraseñas como bcrypt (passlib.hash.bcrypt) o Argon2 (argon2-cffi)."}'::jsonb,
       'CRITICAL', 'CWE-916', 'AUTHENTICATION_FAILURE', '["python"]'::jsonb
FROM policies WHERE name = 'Gestión segura de credenciales de autenticación'
  AND NOT EXISTS (SELECT 1 FROM rules WHERE payload LIKE '%hashlib%');

INSERT INTO rules (policy_id, type, payload, severity, cwe_id, category, languages)
SELECT id, 'PATTERN_REGEX',
       '{"pattern":"Cipher\\.getInstance\\s*\\(\\s*\"(DES|[^\"]*\\/ECB\\/)","description":"Algoritmo o modo de cifrado débil (DES o ECB)","suggestedAction":"Reemplaza DES/ECB por AES en modo GCM (AES/GCM/NoPadding), que además ofrece cifrado autenticado. ECB no debe usarse nunca porque no oculta patrones repetidos en los datos."}'::jsonb,
       'CRITICAL', 'CWE-327', 'INSECURE_DATA_HANDLING', '["java","kotlin"]'::jsonb
FROM policies WHERE name = 'Uso de algoritmos criptográficos aprobados'
  AND NOT EXISTS (SELECT 1 FROM rules WHERE payload LIKE '%Cipher.getInstance%');

-- ── Repara el payload roto de la regla pip-audit (JSON concatenado, inválido) ──

UPDATE rules SET payload =
    '{"description":"Escaneo de CVEs en dependencias Python del proyecto","suggestedAction":"Ejecuta pip-audit (o Safety) en el pipeline de CI/CD para bloquear builds con dependencias Python que tengan CVEs conocidos sin parche disponible.","known_vulnerable":[{"ecosystem":"pypi","package":"jinja2","below_version":"2.11.3","cve":"CVE-2020-28493"},{"ecosystem":"pypi","package":"django","below_version":"3.2.13","cve":"CVE-2022-28346"}]}'
WHERE id = '49ebe302-4b3b-4363-b806-b6cf449272be'
  AND payload LIKE '%pip-audit%}{%';

-- ── Archiva la regla de prueba sin terminar (payload no coincide con ningún schema real) ──

UPDATE rules SET status = 'ARCHIVED'
WHERE id = 'd439f597-08ef-4c09-95d1-1b5fc60a16ab' AND payload = '{"pattern":"dsfsf"}';
