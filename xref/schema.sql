PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS symbols (
  id INTEGER PRIMARY KEY,
  usr TEXT,
  name TEXT NOT NULL,
  kind TEXT NOT NULL,
  path TEXT NOT NULL,
  line INTEGER NOT NULL,
  is_definition INTEGER NOT NULL DEFAULT 0,
  type TEXT,
  signature TEXT
);

CREATE INDEX IF NOT EXISTS idx_symbols_usr ON symbols(usr);
CREATE INDEX IF NOT EXISTS idx_symbols_name ON symbols(name);
CREATE INDEX IF NOT EXISTS idx_symbols_path_line ON symbols(path, line);
CREATE UNIQUE INDEX IF NOT EXISTS idx_symbols_unique
  ON symbols(COALESCE(usr, ''), name, kind, path, line, is_definition);

CREATE TABLE IF NOT EXISTS refs (
  id INTEGER PRIMARY KEY,
  referenced_usr TEXT,
  name TEXT NOT NULL,
  kind TEXT NOT NULL,
  path TEXT NOT NULL,
  line INTEGER NOT NULL,
  context TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_refs_usr ON refs(referenced_usr);
CREATE INDEX IF NOT EXISTS idx_refs_name ON refs(name);
CREATE INDEX IF NOT EXISTS idx_refs_path_line ON refs(path, line);
CREATE UNIQUE INDEX IF NOT EXISTS idx_refs_unique
  ON refs(COALESCE(referenced_usr, ''), name, kind, path, line);

CREATE TABLE IF NOT EXISTS commits (
  hash TEXT PRIMARY KEY,
  subject TEXT NOT NULL,
  date TEXT,
  files TEXT NOT NULL,
  diff_hints TEXT NOT NULL DEFAULT '[]',
  audit_signal TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_commits_subject ON commits(subject);
