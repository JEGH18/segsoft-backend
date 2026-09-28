-- V30: repara un efecto secundario de V29.
-- El guard `NOT EXISTS (... payload LIKE '%Cipher.getInstance%')` de V29 no
-- encontraba la fila ya existente porque el texto guardado tiene un
-- backslash literal antes del punto (`Cipher\.getInstance`, parte del
-- regex), así que el LIKE sin ese backslash nunca hizo match y V29 insertó
-- un duplicado exacto de la regla en vez de detectar que ya existía.
-- Se borra el duplicado por id explícito (no por contenido, para no
-- arriesgar borrar la fila original si el orden de inserción cambiara).

DELETE FROM rules
WHERE id = '287b8eaa-ff7b-4e4e-98e1-61cf0272d705'
  AND payload::jsonb->>'pattern' = 'Cipher\.getInstance\s*\(\s*"(DES|[^"]*\/ECB\/)';
