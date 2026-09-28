-- CLAUDE_CODE_SECURITY was a leftover placeholder name (it happened to match
-- the tool used to build this project) for what is really just "team-defined
-- policies with no external standard behind them". Renamed to CUSTOM so the
-- name matches its actual meaning.
UPDATE policies SET framework = 'CUSTOM' WHERE framework = 'CLAUDE_CODE_SECURITY';
