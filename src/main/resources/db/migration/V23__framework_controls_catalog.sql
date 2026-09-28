-- Catalog of valid (framework, category) -> control_id pairs, so a policy's
-- control_id can be derived from the norm's real control catalog instead of
-- typed freely by the user (who typically doesn't know these codes by heart).
-- CLAUDE_CODE_SECURITY is intentionally absent: it represents team-defined
-- policies with no external standard behind them, so control_id stays free text
-- for that framework only.
CREATE TABLE framework_controls (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    framework     VARCHAR(50) NOT NULL,
    category      VARCHAR(50) NOT NULL,
    control_id    VARCHAR(50) NOT NULL,
    control_name  VARCHAR(200) NOT NULL,
    UNIQUE (framework, category)
);

-- ISO/IEC 27001 Anexo A (numeración 2013), desarrollados en detalle por ISO/IEC 27002.
INSERT INTO framework_controls (framework, category, control_id, control_name) VALUES
('ISO_27001', 'SQL_INJECTION',            'A.9.4.1',  'Restricción de acceso a la información'),
('ISO_27001', 'XSS',                      'A.14.2.5', 'Principios de ingeniería de sistemas seguros'),
('ISO_27001', 'AUTHENTICATION_FAILURE',   'A.9.4.2',  'Procedimientos seguros de inicio de sesión'),
('ISO_27001', 'INSECURE_DATA_HANDLING',   'A.10.1.1', 'Política sobre el uso de controles criptográficos'),
('ISO_27001', 'DEPENDENCY_VULNERABILITY', 'A.12.6.1', 'Gestión de las vulnerabilidades técnicas');

-- OWASP Top 10 2021.
INSERT INTO framework_controls (framework, category, control_id, control_name) VALUES
('OWASP_TOP_10_2021', 'SQL_INJECTION',            'A03:2021', 'Injection'),
('OWASP_TOP_10_2021', 'XSS',                      'A03:2021', 'Injection'),
('OWASP_TOP_10_2021', 'AUTHENTICATION_FAILURE',   'A07:2021', 'Identification and Authentication Failures'),
('OWASP_TOP_10_2021', 'INSECURE_DATA_HANDLING',   'A02:2021', 'Cryptographic Failures'),
('OWASP_TOP_10_2021', 'DEPENDENCY_VULNERABILITY', 'A06:2021', 'Vulnerable and Outdated Components');

-- OWASP Application Security Verification Standard (v4.0.3).
INSERT INTO framework_controls (framework, category, control_id, control_name) VALUES
('OWASP_ASVS', 'SQL_INJECTION',            'V5.3.4',  'Validación de salida y prevención de inyección'),
('OWASP_ASVS', 'XSS',                      'V14.4.3', 'Cabeceras de seguridad HTTP (Content Security Policy)'),
('OWASP_ASVS', 'AUTHENTICATION_FAILURE',   'V3.5.1',  'Gestión de sesiones basada en tokens'),
('OWASP_ASVS', 'INSECURE_DATA_HANDLING',   'V7.1.1',  'Registro seguro sin datos sensibles'),
('OWASP_ASVS', 'DEPENDENCY_VULNERABILITY', 'V14.2.1', 'Verificación de componentes actualizados');

-- DevSecOps: sin norma externa numerada, por eso usa un esquema interno propio
-- (DSO-xx). Cubre solo prácticas de proceso/pipeline -- deliberadamente no
-- ofrece SQL_INJECTION ni XSS, que son hallazgos de código, no de proceso.
INSERT INTO framework_controls (framework, category, control_id, control_name) VALUES
('DEVSECOPS', 'DEPENDENCY_VULNERABILITY', 'DSO-01', 'Escaneo de dependencias en CI/CD'),
('DEVSECOPS', 'INSECURE_DATA_HANDLING',   'DSO-02', 'Gestión de secretos'),
('DEVSECOPS', 'AUTHENTICATION_FAILURE',   'DSO-03', 'Gestión de accesos y credenciales en pipelines');
