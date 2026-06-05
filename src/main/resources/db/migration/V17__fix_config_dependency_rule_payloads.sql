-- V17: corrige el payload de las reglas CONFIG_CHECK y DEPENDENCY_CHECK sembradas
-- para que coincida con el esquema que esperan los executors del motor Python:
--   ConfigExecutor      -> {"checks":[{"key":..., "must_exist":true | "not_value":...}]}
--   DependencyExecutor  -> {"known_vulnerable":[{"ecosystem":..., "below_version":..., "cve":...}]}
-- Se localizan por su contenido actual (los ids son aleatorios).

-- ── CONFIG_CHECK ──────────────────────────────────────────────────────────────

-- TLS debe estar habilitado: marcar si server.ssl.enabled = false
UPDATE rules SET payload =
  '{"description":"TLS debe estar habilitado en produccion","checks":[{"key":"server.ssl.enabled","not_value":"false"}]}'
WHERE type = 'CONFIG_CHECK' AND payload LIKE '%server.ssl.enabled%';

-- MFA obligatorio para roles privilegiados: marcar si la clave no existe
UPDATE rules SET payload =
  '{"description":"MFA obligatorio para roles privilegiados","checks":[{"key":"mfa.required.roles","must_exist":true}]}'
WHERE type = 'CONFIG_CHECK' AND payload LIKE '%mfa.required.roles%';

-- Antiguedad maxima de dependencias: marcar si la clave no existe
UPDATE rules SET payload =
  '{"description":"Politica de actualizacion de dependencias ausente","checks":[{"key":"dependency.update.maxAgeDays","must_exist":true}]}'
WHERE type = 'CONFIG_CHECK' AND payload LIKE '%dependency.update.maxAgeDays%';

-- Verificacion de checksum de artefactos: marcar si la clave no existe
UPDATE rules SET payload =
  '{"description":"Verificacion de checksum de artefactos ausente","checks":[{"key":"artifact.checksum.verify","must_exist":true}]}'
WHERE type = 'CONFIG_CHECK' AND payload LIKE '%artifact.checksum.verify%';

-- CSP obligatoria: marcar si la clave de configuracion CSP no existe
UPDATE rules SET payload =
  '{"description":"Cabecera Content-Security-Policy no configurada","checks":[{"key":"security.headers.content-security-policy","must_exist":true}]}'
WHERE type = 'CONFIG_CHECK' AND payload LIKE '%Content-Security-Policy%';

-- ── DEPENDENCY_CHECK ──────────────────────────────────────────────────────────

-- Escaneo general de CVEs conocidos (maven/npm/pypi)
UPDATE rules SET payload =
  '{"description":"Dependencias con CVEs conocidos de alta severidad","known_vulnerable":[{"ecosystem":"maven","group":"org.apache.logging.log4j","artifact":"log4j-core","below_version":"2.17.1","cve":"CVE-2021-44228"},{"ecosystem":"maven","group":"org.apache.struts","artifact":"struts2-core","below_version":"2.5.33","cve":"CVE-2021-31805"},{"ecosystem":"npm","package":"lodash","below_version":"4.17.21","cve":"CVE-2021-23337"},{"ecosystem":"npm","package":"minimist","below_version":"1.2.6","cve":"CVE-2021-44906"},{"ecosystem":"pypi","package":"requests","below_version":"2.20.0","cve":"CVE-2018-18074"},{"ecosystem":"pypi","package":"pyyaml","below_version":"5.4","cve":"CVE-2020-14343"}]}'
WHERE type = 'DEPENDENCY_CHECK' AND payload LIKE '%owasp-dependency-check%';

-- Bloqueo de dependencias CRITICAL/HIGH (Log4Shell, Spring4Shell)
UPDATE rules SET payload =
  '{"description":"Bloquear dependencias con CVE CRITICAL o HIGH","known_vulnerable":[{"ecosystem":"maven","group":"org.apache.logging.log4j","artifact":"log4j-core","below_version":"2.17.1","cve":"CVE-2021-44228"},{"ecosystem":"maven","group":"org.springframework","artifact":"spring-core","below_version":"5.3.18","cve":"CVE-2022-22965"}]}'
WHERE type = 'DEPENDENCY_CHECK' AND payload LIKE '%blockOnCritical%';
