PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS index_meta (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  workspace TEXT NOT NULL,
  git_head TEXT NOT NULL,
  git_dirty TEXT NOT NULL,
  git_status_count INTEGER,
  compile_commands TEXT NOT NULL,
  compile_command_count INTEGER NOT NULL,
  symbol_count INTEGER NOT NULL,
  ref_count INTEGER NOT NULL,
  commit_count INTEGER NOT NULL,
  jobs INTEGER NOT NULL,
  tu_limit INTEGER,
  batch_size INTEGER NOT NULL,
  detailed_processing_record INTEGER NOT NULL,
  semantic_elapsed_seconds REAL NOT NULL,
  commit_elapsed_seconds REAL NOT NULL,
  total_elapsed_seconds REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS symbols (
  usr TEXT,
  name TEXT NOT NULL,
  kind TEXT NOT NULL,
  path TEXT NOT NULL,
  line INTEGER NOT NULL,
  is_definition INTEGER NOT NULL,
  signature TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_symbols_usr ON symbols(usr);
CREATE INDEX IF NOT EXISTS idx_symbols_name ON symbols(name);
CREATE INDEX IF NOT EXISTS idx_symbols_path_line ON symbols(path, line);
CREATE UNIQUE INDEX IF NOT EXISTS idx_symbols_unique
  ON symbols(COALESCE(usr, ''), name, kind, path, line, is_definition);

CREATE TABLE IF NOT EXISTS refs (
  referenced_usr TEXT NOT NULL,
  path TEXT NOT NULL,
  line INTEGER NOT NULL,
  context TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_refs_usr ON refs(referenced_usr);
CREATE INDEX IF NOT EXISTS idx_refs_path_line ON refs(path, line);
CREATE UNIQUE INDEX IF NOT EXISTS idx_refs_unique
  ON refs(referenced_usr, path, line);

CREATE TABLE IF NOT EXISTS commits (
  hash TEXT PRIMARY KEY,
  subject TEXT NOT NULL,
  files TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_commits_subject ON commits(subject);
CREATE INDEX IF NOT EXISTS idx_commits_files ON commits(files);
