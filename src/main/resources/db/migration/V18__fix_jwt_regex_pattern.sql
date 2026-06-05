-- V18: fix JWT lookahead regex so it stops at semicolon instead of end-of-line.
-- The previous pattern (.*withExpiresAt) matched comments like "// JWT sin withExpiresAt"
-- causing false negatives. Replacing .* with [^;]* limits the search to the statement.

UPDATE rules
SET payload = '{"pattern":"JWT\\.create\\(\\)(?![^;]*withExpiresAt|[^;]*withIssuedAt)","description":"Token JWT creado sin expiración explícita"}'
WHERE type = 'PATTERN_REGEX'
  AND payload::text LIKE '%JWT%create%withExpiresAt%';
