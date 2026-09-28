-- V28: "Derivar políticas del catálogo a partir de ISO/IEC 27002".
--
-- Prerrequisito real, no opcional: el Anexo A de ISO/IEC 27001 fue
-- reestructurado por completo en la edición 2022 (93 controles en 4 temas,
-- numeración simple 5.x/6.x/7.x/8.x) y ISO/IEC 27002:2022 comparte esa
-- MISMA numeración 1:1 -- por eso un control_id como "A.9.4.1" (edición
-- 2013, ya retirada) no tiene ninguna correspondencia real con un control
-- de 27002:2022. Sin renumerar primero, el escenario 3 de esta HU (validar
-- que el control 27002 corresponda al control 27001) sería imposible de
-- cumplir honestamente. Este archivo renumera lo existente y luego agrega
-- el catálogo 27002.

-- 1) Renumerar ISO_27001 de la numeración 2013 a la numeración 2022,
--    por categoría CCS (no por control_id exacto, para no depender de qué
--    valor exacto tenía cada fila).
UPDATE policies SET control_id = 'A.8.28'
WHERE framework = 'ISO_27001' AND category = 'SQL_INJECTION';

UPDATE policies SET control_id = 'A.8.26'
WHERE framework = 'ISO_27001' AND category = 'XSS';

UPDATE policies SET control_id = 'A.8.5'
WHERE framework = 'ISO_27001' AND category = 'AUTHENTICATION_FAILURE';

UPDATE policies SET control_id = 'A.8.24'
WHERE framework = 'ISO_27001' AND category = 'INSECURE_DATA_HANDLING';

UPDATE policies SET control_id = 'A.8.8'
WHERE framework = 'ISO_27001' AND category = 'DEPENDENCY_VULNERABILITY';

UPDATE framework_controls SET control_id = 'A.8.28', control_name = 'Codificación segura'
WHERE framework = 'ISO_27001' AND category = 'SQL_INJECTION';

UPDATE framework_controls SET control_id = 'A.8.26', control_name = 'Requisitos de seguridad de aplicaciones'
WHERE framework = 'ISO_27001' AND category = 'XSS';

UPDATE framework_controls SET control_id = 'A.8.5', control_name = 'Autenticación segura'
WHERE framework = 'ISO_27001' AND category = 'AUTHENTICATION_FAILURE';

UPDATE framework_controls SET control_id = 'A.8.24', control_name = 'Uso de criptografía'
WHERE framework = 'ISO_27001' AND category = 'INSECURE_DATA_HANDLING';

UPDATE framework_controls SET control_id = 'A.8.8', control_name = 'Gestión de vulnerabilidades técnicas'
WHERE framework = 'ISO_27001' AND category = 'DEPENDENCY_VULNERABILITY';

-- 2) Catálogo de referencia ISO/IEC 27002:2022, agrupado en las 4
--    categorías temáticas de la norma. id usa la numeración desnuda
--    ("8.24", como la nombra 27002 mismo); corresponding_annex_a_control
--    es siempre "A."+id porque 27001:2022 y 27002:2022 comparten
--    numeración -- es la columna que habilita el escenario 3.
CREATE TABLE iso27002_controls (
    id                            VARCHAR(20) PRIMARY KEY,
    title                         VARCHAR(200) NOT NULL,
    category                      VARCHAR(20) NOT NULL,
    implementation_guidance       TEXT NOT NULL,
    corresponding_annex_a_control VARCHAR(20) NOT NULL
);

CREATE INDEX idx_iso27002_controls_category ON iso27002_controls (category);
CREATE INDEX idx_iso27002_controls_annex_a ON iso27002_controls (corresponding_annex_a_control);

INSERT INTO iso27002_controls (id, title, category, implementation_guidance, corresponding_annex_a_control) VALUES
-- Organizational (5.x)
('5.1', 'Policies for information security', 'ORGANIZATIONAL',
 'Debe existir una política de seguridad de la información aprobada por la dirección, comunicada a todo el personal relevante y revisada periódicamente o ante cambios significativos.',
 'A.5.1'),
('5.9', 'Inventory of information and other associated assets', 'ORGANIZATIONAL',
 'Debe mantenerse un inventario actualizado de activos de información (datos, sistemas, servicios) con un responsable claramente asignado a cada uno.',
 'A.5.9'),
('5.15', 'Access control', 'ORGANIZATIONAL',
 'Las reglas de control de acceso a la información y otros activos deben basarse en requisitos del negocio y de seguridad, aplicando el principio de mínimo privilegio.',
 'A.5.15'),
('5.23', 'Information security for use of cloud services', 'ORGANIZATIONAL',
 'Los procesos de adquisición, uso, gestión y salida de servicios en la nube deben definirse explícitamente, incluyendo los requisitos de seguridad exigidos al proveedor.',
 'A.5.23'),

-- People (6.x)
('6.1', 'Screening', 'PEOPLE',
 'Debe verificarse los antecedentes de los candidatos antes de la contratación, de forma proporcional a la clasificación de la información a la que tendrán acceso.',
 'A.6.1'),
('6.3', 'Information security awareness, education and training', 'PEOPLE',
 'El personal debe recibir formación y actualizaciones periódicas en seguridad de la información relevantes para su función.',
 'A.6.3'),
('6.8', 'Information security event reporting', 'PEOPLE',
 'Debe existir un mecanismo conocido por todo el personal para reportar eventos de seguridad observados o sospechados, de forma oportuna.',
 'A.6.8'),

-- Physical (7.x)
('7.1', 'Physical security perimeters', 'PHYSICAL',
 'Deben definirse y usarse perímetros de seguridad física para proteger las áreas que contienen información y otros activos asociados.',
 'A.7.1'),
('7.9', 'Security of assets off-premises', 'PHYSICAL',
 'Los activos que salen de las instalaciones de la organización deben protegerse, considerando los distintos riesgos de trabajar fuera de ellas.',
 'A.7.9'),
('7.10', 'Storage media', 'PHYSICAL',
 'Los medios de almacenamiento deben gestionarse a lo largo de su ciclo de vida (adquisición, uso, transporte y disposición final) según el esquema de clasificación de la organización.',
 'A.7.10'),

-- Technological (8.x) -- los 6 vinculados a políticas del banco.
('8.5', 'Secure authentication', 'TECHNOLOGICAL',
 'La autenticación debe usar factores fuertes (contraseñas de calidad, MFA para accesos privilegiados o remotos), limitar los intentos fallidos y no revelar si un identificador de usuario existe o no en los mensajes de error.',
 'A.8.5'),
('8.8', 'Management of technical vulnerabilities', 'TECHNOLOGICAL',
 'Debe existir un proceso para identificar vulnerabilidades técnicas conocidas en los componentes y dependencias usados, evaluar la exposición de la organización y aplicar parches o mitigaciones en plazos definidos según la severidad.',
 'A.8.8'),
('8.24', 'Use of cryptography', 'TECHNOLOGICAL',
 'Debe definirse cuándo y cómo usar cifrado (en tránsito y en reposo), seleccionando algoritmos y longitudes de clave vigentes, y gestionando el ciclo de vida de las claves criptográficas (generación, distribución, rotación y revocación).',
 'A.8.24'),
('8.25', 'Secure development life cycle', 'TECHNOLOGICAL',
 'La seguridad debe integrarse en cada fase del ciclo de vida de desarrollo (diseño, codificación, pruebas, despliegue), incluyendo revisiones de seguridad y pruebas antes de pasar a producción.',
 'A.8.25'),
('8.26', 'Application security requirements', 'TECHNOLOGICAL',
 'Los requisitos de seguridad de una aplicación -- incluida la validación y el escape de todas las entradas y salidas -- deben identificarse y especificarse antes o durante el desarrollo, no añadirse después como parche.',
 'A.8.26'),
('8.28', 'Secure coding', 'TECHNOLOGICAL',
 'El desarrollo debe seguir principios de codificación segura: minimizar la superficie de ataque, aplicar el principio de menor privilegio, validar toda entrada no confiable y evitar patrones de código con vulnerabilidades conocidas.',
 'A.8.28');

-- 3) Extensión del modelo de Policy: referencia opcional a la guía de
--    implementación 27002 correspondiente. NULL para políticas que no son
--    ISO_27001, o para ISO_27001 registradas antes de esta funcionalidad
--    (esas últimas son exactamente las que quedan "detailPending" -- ver
--    PolicyService.toResponse, campo calculado, no columna redundante).
ALTER TABLE policies
    ADD COLUMN implementation_guide_id VARCHAR(20) REFERENCES iso27002_controls(id);
