use anyhow::{Context, Result, anyhow, bail};
use rusqlite::{Connection, OptionalExtension, params};
use std::fs;
use std::path::Path;

pub struct XrefDb {
    conn: Connection,
}

#[derive(Debug)]
pub struct SymbolInsertRow {
    pub usr: String,
    pub name: String,
    pub kind: String,
    pub path: String,
    pub line: u32,
    pub is_definition: bool,
    pub signature: String,
}

#[derive(Debug)]
pub struct RefInsertRow {
    pub referenced_usr: String,
    pub path: String,
    pub line: u32,
    pub context: String,
}

#[derive(Debug)]
pub struct CommitInsertRow {
    pub hash: String,
    pub subject: String,
    pub files: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct IndexMeta {
    pub workspace: String,
    pub git_head: String,
    pub git_dirty: String,
    pub git_status_count: Option<usize>,
    pub compile_commands: String,
    pub compile_command_count: usize,
    pub symbol_count: usize,
    pub ref_count: usize,
    pub commit_count: usize,
    pub jobs: usize,
    pub tu_limit: Option<usize>,
    pub batch_size: usize,
    pub detailed_processing_record: bool,
    pub semantic_elapsed_seconds: f64,
    pub commit_elapsed_seconds: f64,
    pub total_elapsed_seconds: f64,
}

#[derive(Clone, Debug)]
pub struct SymbolRow {
    pub usr: String,
    pub name: String,
    pub kind: String,
    pub path: String,
    pub line: i64,
    pub is_definition: i64,
    pub signature: String,
}

#[derive(Debug)]
pub struct RefRow {
    pub path: String,
    pub line: i64,
    pub context: String,
}

#[derive(Debug)]
pub struct CommitRow {
    pub hash: String,
    pub subject: String,
    pub files: Vec<String>,
}

impl XrefDb {
    pub fn open_existing(db: &Path) -> Result<Self> {
        if !db.exists() {
            bail!(
                "找不到索引: {}\n请先运行 xref --workspace <目标工作区> index",
                db.display()
            );
        }
        Self::open(db)
    }

    pub fn create_for_index(db: &Path) -> Result<Self> {
        Self::open(db)
    }

    fn open(db: &Path) -> Result<Self> {
        let conn =
            Connection::open(db).with_context(|| format!("无法打开数据库: {}", db.display()))?;
        Ok(Self { conn })
    }

    pub fn reset_schema(&mut self, schema_path: &Path) -> Result<()> {
        let schema = fs::read_to_string(&schema_path)
            .with_context(|| format!("无法读取 schema: {}", schema_path.display()))?;
        for table in [
            "tests",
            "routes",
            "diagnostics",
            "commit_files",
            "symbols",
            "refs",
            "commits",
            "files",
            "meta",
            "index_meta",
        ] {
            self.conn
                .execute(&format!("DROP TABLE IF EXISTS {table}"), [])?;
        }
        self.conn.execute_batch(&schema)?;
        Ok(())
    }

    pub fn checkpoint(&self) -> Result<()> {
        self.conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
        Ok(())
    }

    pub fn replace_index_meta(&self, meta: &IndexMeta) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT OR REPLACE INTO index_meta(
              id, workspace, git_head, git_dirty, git_status_count,
              compile_commands, compile_command_count, symbol_count, ref_count,
              commit_count, jobs, tu_limit, batch_size, detailed_processing_record,
              semantic_elapsed_seconds, commit_elapsed_seconds, total_elapsed_seconds
            )
            VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
            params![
                &meta.workspace,
                &meta.git_head,
                &meta.git_dirty,
                meta.git_status_count.map(i64::try_from).transpose()?,
                &meta.compile_commands,
                i64::try_from(meta.compile_command_count)?,
                i64::try_from(meta.symbol_count)?,
                i64::try_from(meta.ref_count)?,
                i64::try_from(meta.commit_count)?,
                i64::try_from(meta.jobs)?,
                meta.tu_limit.map(i64::try_from).transpose()?,
                i64::try_from(meta.batch_size)?,
                i32::from(meta.detailed_processing_record),
                meta.semantic_elapsed_seconds,
                meta.commit_elapsed_seconds,
                meta.total_elapsed_seconds,
            ],
        )?;
        Ok(())
    }

    pub fn index_meta(&self) -> Result<Option<IndexMeta>> {
        self.conn
            .query_row(
                r#"
                SELECT
                  workspace, git_head, git_dirty, git_status_count,
                  compile_commands, compile_command_count, symbol_count, ref_count,
                  commit_count, jobs, tu_limit, batch_size, detailed_processing_record,
                  semantic_elapsed_seconds, commit_elapsed_seconds, total_elapsed_seconds
                FROM index_meta
                WHERE id = 1
                "#,
                [],
                |row| {
                    Ok(IndexMeta {
                        workspace: row.get(0)?,
                        git_head: row.get(1)?,
                        git_dirty: row.get(2)?,
                        git_status_count: optional_usize(row.get::<_, Option<i64>>(3)?)?,
                        compile_commands: row.get(4)?,
                        compile_command_count: row_usize(row.get(5)?)?,
                        symbol_count: row_usize(row.get(6)?)?,
                        ref_count: row_usize(row.get(7)?)?,
                        commit_count: row_usize(row.get(8)?)?,
                        jobs: row_usize(row.get(9)?)?,
                        tu_limit: optional_usize(row.get::<_, Option<i64>>(10)?)?,
                        batch_size: row_usize(row.get(11)?)?,
                        detailed_processing_record: row.get::<_, i64>(12)? != 0,
                        semantic_elapsed_seconds: row.get(13)?,
                        commit_elapsed_seconds: row.get(14)?,
                        total_elapsed_seconds: row.get(15)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn count_symbols_refs(&self) -> Result<(usize, usize)> {
        Ok((self.count_symbols()?, self.count_refs()?))
    }

    pub fn count_symbols(&self) -> Result<usize> {
        self.count_sql("SELECT COUNT(*) FROM symbols")
    }

    pub fn count_refs(&self) -> Result<usize> {
        self.count_sql("SELECT COUNT(*) FROM refs")
    }

    #[cfg(test)]
    pub fn count_commits(&self) -> Result<usize> {
        self.count_sql("SELECT COUNT(*) FROM commits")
    }

    fn count_sql(&self, sql: &str) -> Result<usize> {
        let count: i64 = self.conn.query_row(sql, [], |row| row.get(0))?;
        usize::try_from(count).context("SQLite COUNT(*) 返回了无法表示为 usize 的值")
    }

    pub fn insert_semantic_rows(
        &self,
        symbol_rows: &mut Vec<SymbolInsertRow>,
        ref_rows: &mut Vec<RefInsertRow>,
        force: bool,
        batch_size: usize,
    ) -> Result<()> {
        while (!symbol_rows.is_empty() && (force || symbol_rows.len() >= batch_size))
            || (!ref_rows.is_empty() && (force || ref_rows.len() >= batch_size))
        {
            let tx = self.conn.unchecked_transaction()?;
            if !symbol_rows.is_empty() && (force || symbol_rows.len() >= batch_size) {
                let chunk_size = if force { symbol_rows.len() } else { batch_size };
                let mut stmt = tx.prepare(
                    r#"
                    INSERT OR IGNORE INTO symbols(
                      usr, name, kind, path, line, is_definition, signature
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    "#,
                )?;
                for row in symbol_rows.drain(..chunk_size) {
                    stmt.execute(params![
                        row.usr,
                        row.name,
                        row.kind,
                        row.path,
                        row.line,
                        i32::from(row.is_definition),
                        row.signature,
                    ])?;
                }
            }
            if !ref_rows.is_empty() && (force || ref_rows.len() >= batch_size) {
                let chunk_size = if force { ref_rows.len() } else { batch_size };
                let mut stmt = tx.prepare(
                    "INSERT OR IGNORE INTO refs(referenced_usr, path, line, context) VALUES (?, ?, ?, ?)",
                )?;
                for row in ref_rows.drain(..chunk_size) {
                    stmt.execute(params![row.referenced_usr, row.path, row.line, row.context])?;
                }
            }
            tx.commit()?;
        }
        Ok(())
    }

    pub fn insert_commits(&self, commits: Vec<CommitInsertRow>) -> Result<usize> {
        let count = commits.len();
        let tx = self.conn.unchecked_transaction()?;
        {
            let mut stmt = tx
                .prepare("INSERT OR REPLACE INTO commits(hash, subject, files) VALUES (?, ?, ?)")?;
            for item in commits {
                stmt.execute(params![
                    item.hash,
                    item.subject,
                    serde_json::to_string(&item.files)?,
                ])?;
            }
        }
        tx.commit()?;
        Ok(count)
    }

    pub fn fetch_symbols(
        &self,
        term: &str,
        limit: usize,
        definitions_only: bool,
    ) -> Result<Vec<SymbolRow>> {
        let like = format!("%{term}%");
        if definitions_only {
            let mut stmt = self.conn.prepare(
                r#"
                SELECT
                  COALESCE(usr, '') AS usr, name, kind, path, line,
                  is_definition, signature
                FROM symbols
                WHERE (usr = ? OR name = ? OR name LIKE ?) AND is_definition = 1
                ORDER BY
                  CASE WHEN usr = ? THEN 0 WHEN name = ? THEN 1 ELSE 2 END,
                  is_definition DESC, path, line
                LIMIT ?
                "#,
            )?;
            let rows = stmt.query_map(
                params![term, term, like, term, term, limit_i64(limit)?],
                symbol_from_row,
            )?;
            return collect_rows(rows);
        }
        let mut stmt = self.conn.prepare(
            r#"
            SELECT
              COALESCE(usr, '') AS usr, name, kind, path, line,
              is_definition, signature
            FROM symbols
            WHERE usr = ? OR name = ? OR name LIKE ?
            ORDER BY
              CASE WHEN usr = ? THEN 0 WHEN name = ? THEN 1 ELSE 2 END,
              is_definition DESC, path, line
            LIMIT ?
            "#,
        )?;
        let rows = stmt.query_map(
            params![term, term, like, term, term, limit_i64(limit)?],
            symbol_from_row,
        )?;
        collect_rows(rows)
    }

    pub fn exact_symbol_candidates(&self, term: &str, limit: usize) -> Result<Vec<SymbolRow>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT
              COALESCE(usr, '') AS usr, name, kind, path, line, is_definition,
              signature
            FROM symbols
            WHERE usr = ? OR name = ?
            ORDER BY CASE WHEN usr = ? THEN 0 ELSE 1 END, is_definition DESC, path, line
            LIMIT ?
            "#,
        )?;
        let rows = stmt.query_map(
            params![term, term, term, limit_i64(limit)?],
            symbol_from_row,
        )?;
        collect_rows(rows)
    }

    pub fn usr_exists(&self, usr: &str) -> Result<bool> {
        Ok(self
            .conn
            .query_row("SELECT 1 FROM symbols WHERE usr = ? LIMIT 1", [usr], |_| {
                Ok(())
            })
            .optional()?
            .is_some())
    }

    pub fn symbol_usrs_for_name(&self, name: &str, limit: usize) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT DISTINCT usr
            FROM symbols
            WHERE name = ? AND usr IS NOT NULL AND usr != ''
            ORDER BY usr
            LIMIT ?
            "#,
        )?;
        let rows = stmt.query_map(params![name, limit_i64(limit)?], |row| {
            row.get::<_, String>(0)
        })?;
        collect_rows(rows)
    }

    pub fn ref_rows_by_usr(&self, usr: &str, limit: usize) -> Result<Vec<RefRow>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT path, line, context
            FROM refs
            WHERE referenced_usr = ?
            ORDER BY path, line
            LIMIT ?
            "#,
        )?;
        let rows = stmt.query_map(params![usr, limit_i64(limit)?], ref_from_row)?;
        collect_rows(rows)
    }

    pub fn nearby_symbols(
        &self,
        path: &str,
        start: usize,
        end: usize,
        limit: usize,
    ) -> Result<Vec<SymbolRow>> {
        let margin_start = start.saturating_sub(19).max(1);
        let margin_end = end.saturating_add(20);
        let mut stmt = self.conn.prepare(
            r#"
            SELECT
              COALESCE(usr, '') AS usr, name, kind, path, line,
              is_definition, signature
            FROM symbols
            WHERE path = ? AND line BETWEEN ? AND ?
            ORDER BY
              ABS(line - ?), is_definition DESC, line
            LIMIT ?
            "#,
        )?;
        let rows = stmt.query_map(
            params![
                path,
                i64::try_from(margin_start)?,
                i64::try_from(margin_end)?,
                i64::try_from(start)?,
                limit_i64(limit)?
            ],
            symbol_from_row,
        )?;
        collect_rows(rows)
    }

    pub fn commit_rows(&self, term: &str, limit: usize) -> Result<Vec<CommitRow>> {
        let like = format!("%{term}%");
        let mut stmt = self.conn.prepare(
            r#"
            SELECT hash, subject, files
            FROM commits
            WHERE subject LIKE ? OR files LIKE ?
            ORDER BY hash
            LIMIT ?
            "#,
        )?;
        let rows = stmt.query_map(params![like, like, limit_i64(limit)?], |row| {
            let files = row.get::<_, String>(2)?;
            Ok(CommitRow {
                hash: row.get(0)?,
                subject: row.get(1)?,
                files: json_list(&files),
            })
        })?;
        collect_rows(rows)
    }
}

fn symbol_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SymbolRow> {
    Ok(SymbolRow {
        usr: row.get("usr")?,
        name: row.get("name")?,
        kind: row.get("kind")?,
        path: row.get("path")?,
        line: row.get("line")?,
        is_definition: row.get("is_definition")?,
        signature: row.get("signature")?,
    })
}

fn ref_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RefRow> {
    Ok(RefRow {
        path: row.get("path")?,
        line: row.get("line")?,
        context: row.get("context")?,
    })
}

fn collect_rows<T>(
    rows: rusqlite::MappedRows<'_, impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>>,
) -> Result<Vec<T>> {
    let mut values = Vec::new();
    for row in rows {
        values.push(row?);
    }
    Ok(values)
}

fn json_list(value: &str) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(value).unwrap_or_default()
}

fn row_usize(value: i64) -> rusqlite::Result<usize> {
    usize::try_from(value).map_err(|exc| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Integer, Box::new(exc))
    })
}

fn optional_usize(value: Option<i64>) -> rusqlite::Result<Option<usize>> {
    value.map(row_usize).transpose()
}

fn limit_i64(limit: usize) -> Result<i64> {
    i64::try_from(limit).map_err(|_| anyhow!("limit 过大: {limit}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestDb {
        path: std::path::PathBuf,
    }

    impl Drop for TestDb {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
            let _ = std::fs::remove_file(self.path.with_extension("db-wal"));
            let _ = std::fs::remove_file(self.path.with_extension("db-shm"));
        }
    }

    fn temp_db(name: &str) -> (TestDb, XrefDb) {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "xref_db_{name}_{}_{}.db",
            std::process::id(),
            unique
        ));
        let guard = TestDb { path: path.clone() };
        let mut db = XrefDb::create_for_index(&path).unwrap();
        db.reset_schema(&test_schema_path()).unwrap();
        (guard, db)
    }

    fn test_schema_path() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("schema.sql")
    }

    fn sample_symbol(name: &str) -> SymbolInsertRow {
        SymbolInsertRow {
            usr: format!("usr:{name}"),
            name: name.to_owned(),
            kind: "FUNCTION_DECL".to_owned(),
            path: "src/main.c".to_owned(),
            line: 7,
            is_definition: true,
            signature: format!("{name}()"),
        }
    }

    fn sample_meta() -> IndexMeta {
        IndexMeta {
            workspace: "/tmp/project".to_owned(),
            git_head: "abcdef".to_owned(),
            git_dirty: "no".to_owned(),
            git_status_count: Some(0),
            compile_commands: "/tmp/project/compile_commands.json".to_owned(),
            compile_command_count: 1,
            symbol_count: 1,
            ref_count: 1,
            commit_count: 2,
            jobs: 1,
            tu_limit: None,
            batch_size: 500,
            detailed_processing_record: false,
            semantic_elapsed_seconds: 1.25,
            commit_elapsed_seconds: 0.5,
            total_elapsed_seconds: 1.75,
        }
    }

    #[test]
    fn inserts_semantic_rows_and_queries_them() {
        let (_guard, db) = temp_db("semantic");
        let mut symbols = vec![sample_symbol("alpha")];
        let mut refs = vec![RefInsertRow {
            referenced_usr: "usr:alpha".to_owned(),
            path: "src/main.c".to_owned(),
            line: 9,
            context: "return alpha();".to_owned(),
        }];

        db.insert_semantic_rows(&mut symbols, &mut refs, true, 5000)
            .unwrap();

        assert!(symbols.is_empty());
        assert!(refs.is_empty());
        assert_eq!(db.count_symbols_refs().unwrap(), (1, 1));
        assert!(db.usr_exists("usr:alpha").unwrap());
        assert_eq!(db.fetch_symbols("alpha", 20, true).unwrap().len(), 1);
        assert_eq!(db.ref_rows_by_usr("usr:alpha", 20).unwrap().len(), 1);
    }

    #[test]
    fn replaces_typed_meta_and_inserts_commit_batches() {
        let (_guard, db) = temp_db("meta_commits");
        db.replace_index_meta(&sample_meta()).unwrap();
        db.insert_commits(vec![CommitInsertRow {
            hash: "abcdef123456".to_owned(),
            subject: "fix overflow".to_owned(),
            files: vec!["src/main.c".to_owned()],
        }])
        .unwrap();
        db.insert_commits(vec![CommitInsertRow {
            hash: "123456abcdef".to_owned(),
            subject: "sanitize bounds".to_owned(),
            files: vec!["src/bounds.c".to_owned()],
        }])
        .unwrap();

        let meta = db.index_meta().unwrap().unwrap();
        assert_eq!(meta.commit_count, 2);
        assert_eq!(db.count_commits().unwrap(), 2);
        let commits = db.commit_rows("overflow", 20).unwrap();
        assert_eq!(commits.len(), 1);
        assert_eq!(commits[0].files, vec!["src/main.c"]);
    }

    #[test]
    fn schema_contains_only_v0_tables_and_columns() {
        let (_guard, db) = temp_db("schema");
        let tables = db
            .conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<std::result::Result<std::collections::HashSet<_>, _>>()
            .unwrap();
        assert!(
            ["index_meta", "symbols", "refs", "commits"]
                .iter()
                .all(|table| tables.contains(*table))
        );
        assert!(!tables.contains("meta"));
        assert!(!tables.contains("commit_files"));

        let symbol_columns = table_columns(&db, "symbols");
        assert_eq!(
            symbol_columns,
            std::collections::HashSet::from([
                "usr".to_owned(),
                "name".to_owned(),
                "kind".to_owned(),
                "path".to_owned(),
                "line".to_owned(),
                "is_definition".to_owned(),
                "signature".to_owned(),
            ])
        );
        let ref_columns = table_columns(&db, "refs");
        assert_eq!(
            ref_columns,
            std::collections::HashSet::from([
                "referenced_usr".to_owned(),
                "path".to_owned(),
                "line".to_owned(),
                "context".to_owned(),
            ])
        );
        let commit_columns = table_columns(&db, "commits");
        assert_eq!(
            commit_columns,
            std::collections::HashSet::from([
                "hash".to_owned(),
                "subject".to_owned(),
                "files".to_owned(),
            ])
        );
    }

    fn table_columns(db: &XrefDb, table: &str) -> std::collections::HashSet<String> {
        db.conn
            .prepare(&format!("PRAGMA table_info({table})"))
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap()
    }
}
