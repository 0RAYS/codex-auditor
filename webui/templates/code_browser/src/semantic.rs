use anyhow::Result;
use clang_sys::*;
use rusqlite::{Connection, params};
use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, CString};
use std::fs;
use std::os::raw::{c_uint, c_void};
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

use crate::compile_db::CompileCommand;
use crate::db::count_table;
use crate::path_util::{ext, is_c_family, rel};

#[derive(Default, Debug)]
struct TuRows {
    symbols: Vec<SymbolRow>,
    refs: Vec<RefRow>,
}

#[derive(Debug)]
struct SymbolRow {
    usr: String,
    name: String,
    kind: String,
    path: String,
    line: u32,
    is_definition: bool,
    type_text: String,
    signature: String,
}

#[derive(Debug)]
struct RefRow {
    referenced_usr: String,
    name: String,
    kind: String,
    path: String,
    line: u32,
    context: String,
}

struct VisitState<'a> {
    workspace: &'a Path,
    rows: &'a mut TuRows,
    source_cache: HashMap<PathBuf, Vec<String>>,
    path_cache: HashMap<PathBuf, PathInfo>,
    main_source: PathBuf,
    header_claims: Arc<Mutex<HashSet<PathBuf>>>,
    claimed_headers: HashSet<PathBuf>,
}

#[derive(Clone, Debug)]
struct PathInfo {
    canonical: PathBuf,
    relative: Option<String>,
    is_c_family: bool,
    is_header: bool,
}

pub fn index_translation_units(
    conn: &Connection,
    workspace: &Path,
    commands: &[CompileCommand],
    jobs: usize,
    batch_size: usize,
    detailed_processing_record: bool,
) -> Result<(usize, usize)> {
    if commands.is_empty() {
        return Ok((0, 0));
    }
    let header_claims = Arc::new(Mutex::new(HashSet::new()));
    let worker_count = jobs.min(commands.len()).max(1);
    let (result_tx, result_rx) = mpsc::channel::<(PathBuf, TuRows)>();
    let commands = Arc::new(commands.to_vec());
    let next_index = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    for _ in 0..worker_count {
        let commands = Arc::clone(&commands);
        let next_index = Arc::clone(&next_index);
        let result_tx = result_tx.clone();
        let workspace = workspace.to_path_buf();
        let header_claims = Arc::clone(&header_claims);
        handles.push(thread::spawn(move || {
            loop {
                let index = next_index.fetch_add(1, Ordering::Relaxed);
                if index >= commands.len() {
                    break;
                }
                let command = &commands[index];
                let rows = extract_translation_unit_rows(
                    &workspace,
                    command,
                    detailed_processing_record,
                    Arc::clone(&header_claims),
                );
                let _ = result_tx.send((command.source.clone(), rows));
            }
        }));
    }
    drop(result_tx);

    let mut symbol_rows = Vec::new();
    let mut ref_rows = Vec::new();
    for (source, rows) in result_rx {
        symbol_rows.extend(rows.symbols);
        ref_rows.extend(rows.refs);
        flush_semantic_rows(conn, &mut symbol_rows, &mut ref_rows, false, batch_size)?;
        if handles.iter().any(thread::JoinHandle::is_finished) {
            // Finished handles are joined below; this branch keeps clippy from suggesting no-op progress logic.
            let _ = &source;
        }
    }
    for handle in handles {
        if handle.join().is_err() {
            eprintln!("libclang diagnostic: <unknown>:0:0: fatal: index worker panicked");
        }
    }
    flush_semantic_rows(conn, &mut symbol_rows, &mut ref_rows, true, batch_size)?;
    Ok((count_table(conn, "symbols")?, count_table(conn, "refs")?))
}

fn extract_translation_unit_rows(
    workspace: &Path,
    command: &CompileCommand,
    detailed_processing_record: bool,
    header_claims: Arc<Mutex<HashSet<PathBuf>>>,
) -> TuRows {
    let mut rows = TuRows::default();
    let source_c = match path_to_cstring(&command.source) {
        Ok(value) => value,
        Err(exc) => {
            emit_parse_error(
                workspace,
                &command.source,
                &format!("invalid source path: {exc}"),
            );
            return rows;
        }
    };
    let c_args = match command
        .args
        .iter()
        .map(|arg| CString::new(arg.as_str()))
        .collect::<std::result::Result<Vec<_>, _>>()
    {
        Ok(value) => value,
        Err(exc) => {
            emit_parse_error(
                workspace,
                &command.source,
                &format!("invalid compiler argument: {exc}"),
            );
            return rows;
        }
    };
    let arg_ptrs = c_args.iter().map(|arg| arg.as_ptr()).collect::<Vec<_>>();
    let options = if detailed_processing_record {
        CXTranslationUnit_DetailedPreprocessingRecord
    } else {
        CXTranslationUnit_None
    };
    unsafe {
        let index = clang_createIndex(0, 0);
        if index.is_null() {
            emit_parse_error(workspace, &command.source, "libclang create index failed");
            return rows;
        }
        let mut tu: CXTranslationUnit = ptr::null_mut();
        let error = clang_parseTranslationUnit2(
            index,
            source_c.as_ptr(),
            arg_ptrs.as_ptr(),
            arg_ptrs.len() as i32,
            ptr::null_mut(),
            0,
            options,
            &mut tu,
        );
        if error != CXError_Success || tu.is_null() {
            emit_parse_error(
                workspace,
                &command.source,
                &format!("libclang parse failed: CXErrorCode={error}"),
            );
            clang_disposeIndex(index);
            return rows;
        }
        emit_diagnostics(workspace, tu);
        let cursor = clang_getTranslationUnitCursor(tu);
        let mut state = VisitState {
            workspace,
            rows: &mut rows,
            source_cache: HashMap::new(),
            path_cache: HashMap::new(),
            main_source: command.source.clone(),
            header_claims,
            claimed_headers: HashSet::new(),
        };
        clang_visitChildren(cursor, visit_child, &mut state as *mut _ as *mut c_void);
        clang_disposeTranslationUnit(tu);
        clang_disposeIndex(index);
    }
    rows
}

extern "C" fn visit_child(
    cursor: CXCursor,
    _parent: CXCursor,
    client_data: CXClientData,
) -> CXChildVisitResult {
    let state = unsafe { &mut *(client_data as *mut VisitState<'_>) };
    let kind = unsafe { clang_getCursorKind(cursor) };
    let is_declaration = is_declaration_kind(kind);
    let is_reference = is_reference_kind(kind);
    if !is_declaration && !is_reference {
        return CXChildVisit_Recurse;
    }
    let Some((path, line)) = cursor_location(cursor) else {
        return CXChildVisit_Recurse;
    };
    let info = cached_path_info(state, &path).clone();
    let Some(rpath) = info.relative.clone() else {
        return CXChildVisit_Continue;
    };
    if !should_visit_file(state, &info) {
        return CXChildVisit_Continue;
    }
    if is_declaration {
        let spelling = cursor_spelling(cursor);
        let display_name = if spelling.is_empty() || cursor_needs_signature(kind) {
            cursor_display_name(cursor)
        } else {
            String::new()
        };
        let name = if spelling.is_empty() {
            display_name.clone()
        } else {
            spelling.clone()
        };
        if name.is_empty() {
            return CXChildVisit_Recurse;
        }
        state.rows.symbols.push(SymbolRow {
            usr: cursor_usr(cursor),
            name: name.clone(),
            kind: kind_spelling(kind),
            path: rpath.clone(),
            line,
            is_definition: unsafe { clang_isCursorDefinition(cursor) != 0 },
            type_text: cursor_type_spelling(cursor),
            signature: cursor_signature(cursor, &display_name, &spelling),
        });
    }
    if is_reference {
        let referenced = unsafe { clang_getCursorReferenced(cursor) };
        if unsafe { clang_Cursor_isNull(referenced) } == 0 {
            let ref_usr = cursor_usr(referenced);
            let ref_name = {
                let referenced_spelling = cursor_spelling(referenced);
                if !referenced_spelling.is_empty() {
                    referenced_spelling
                } else {
                    let spelling = cursor_spelling(cursor);
                    if !spelling.is_empty() {
                        spelling
                    } else {
                        cursor_display_name(cursor)
                    }
                }
            };
            if !ref_usr.is_empty() && !ref_name.is_empty() {
                let context = line_context(&info.canonical, line, &mut state.source_cache);
                state.rows.refs.push(RefRow {
                    referenced_usr: ref_usr,
                    name: ref_name,
                    kind: kind_spelling(kind),
                    path: rpath,
                    line,
                    context,
                });
            }
        }
    }
    CXChildVisit_Recurse
}

fn cached_path_info<'a>(state: &'a mut VisitState<'_>, path: &Path) -> &'a PathInfo {
    state
        .path_cache
        .entry(path.to_path_buf())
        .or_insert_with(|| build_path_info(state.workspace, path))
}

fn build_path_info(workspace: &Path, path: &Path) -> PathInfo {
    let Ok(canonical) = fs::canonicalize(path) else {
        return PathInfo {
            canonical: path.to_path_buf(),
            relative: None,
            is_c_family: false,
            is_header: false,
        };
    };
    let relative = canonical
        .strip_prefix(workspace)
        .ok()
        .map(|value| value.to_string_lossy().replace('\\', "/"));
    let is_c_family = is_c_family(&canonical);
    let is_header = matches!(ext(&canonical).as_str(), "h" | "hh" | "hpp" | "hxx");
    PathInfo {
        canonical,
        relative,
        is_c_family,
        is_header,
    }
}

fn should_visit_file(state: &mut VisitState<'_>, info: &PathInfo) -> bool {
    let canonical = &info.canonical;
    if *canonical == state.main_source {
        return true;
    }
    if !info.is_c_family {
        return false;
    }
    if !info.is_header {
        return false;
    }
    if state.claimed_headers.contains(canonical) {
        return true;
    }
    let mut claims = state
        .header_claims
        .lock()
        .expect("header claim mutex poisoned");
    if claims.insert(canonical.clone()) {
        state.claimed_headers.insert(canonical.clone());
        true
    } else {
        false
    }
}

fn path_to_cstring(path: &Path) -> std::result::Result<CString, std::ffi::NulError> {
    CString::new(path.to_string_lossy().as_bytes())
}

fn emit_parse_error(workspace: &Path, source: &Path, message: &str) {
    let path = rel(workspace, source).unwrap_or_else(|_| source.display().to_string());
    eprintln!("libclang diagnostic: {path}:0:0: fatal: {message}");
}

fn emit_diagnostics(workspace: &Path, tu: CXTranslationUnit) {
    unsafe {
        let count = clang_getNumDiagnostics(tu);
        for i in 0..count {
            let diagnostic = clang_getDiagnostic(tu, i);
            let loc = clang_getDiagnosticLocation(diagnostic);
            let (path, line, column) = source_location(workspace, loc);
            let severity = clang_getDiagnosticSeverity(diagnostic) as u32;
            let spelling = cx_string(clang_getDiagnosticSpelling(diagnostic));
            eprintln!(
                "libclang diagnostic: {}:{line}:{column}: {}: {spelling}",
                path.unwrap_or_else(|| "<unknown>".to_owned()),
                severity_name(severity),
            );
            clang_disposeDiagnostic(diagnostic);
        }
    }
}

fn cursor_location(cursor: CXCursor) -> Option<(PathBuf, u32)> {
    unsafe {
        let loc = clang_getCursorLocation(cursor);
        let mut file: CXFile = ptr::null_mut();
        let mut line = 0;
        let mut column = 0;
        let mut offset = 0;
        clang_getExpansionLocation(loc, &mut file, &mut line, &mut column, &mut offset);
        if file.is_null() {
            return None;
        }
        let name = cx_string(clang_getFileName(file));
        if name.is_empty() {
            None
        } else {
            Some((PathBuf::from(name), line))
        }
    }
}

fn source_location(workspace: &Path, loc: CXSourceLocation) -> (Option<String>, u32, u32) {
    unsafe {
        let mut file: CXFile = ptr::null_mut();
        let mut line = 0;
        let mut column = 0;
        let mut offset = 0;
        clang_getExpansionLocation(loc, &mut file, &mut line, &mut column, &mut offset);
        if file.is_null() {
            return (None, line, column);
        }
        let name = cx_string(clang_getFileName(file));
        if name.is_empty() {
            (None, line, column)
        } else {
            let path = PathBuf::from(name);
            let display = rel(workspace, &path).unwrap_or_else(|_| path.display().to_string());
            (Some(display), line, column)
        }
    }
}

fn cursor_spelling(cursor: CXCursor) -> String {
    unsafe { cx_string(clang_getCursorSpelling(cursor)) }
}

fn cursor_display_name(cursor: CXCursor) -> String {
    unsafe { cx_string(clang_getCursorDisplayName(cursor)) }
}

fn cursor_usr(cursor: CXCursor) -> String {
    unsafe { cx_string(clang_getCursorUSR(cursor)) }
}

fn cursor_type_spelling(cursor: CXCursor) -> String {
    unsafe { cx_string(clang_getTypeSpelling(clang_getCursorType(cursor))) }
}

fn cursor_signature(cursor: CXCursor, display_name: &str, spelling: &str) -> String {
    unsafe {
        let n_args = clang_Cursor_getNumArguments(cursor);
        if n_args > 0 {
            let mut args = Vec::new();
            for i in 0..n_args {
                args.push(cursor_spelling(clang_Cursor_getArgument(
                    cursor,
                    i as c_uint,
                )));
            }
            return format!("{spelling}({})", args.join(", "));
        }
    }
    if !display_name.is_empty() {
        display_name.to_owned()
    } else {
        spelling.to_owned()
    }
}

unsafe fn cx_string(value: CXString) -> String {
    let ptr = unsafe { clang_getCString(value) };
    let out = if ptr.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned()
    };
    unsafe { clang_disposeString(value) };
    out
}

fn kind_spelling(kind: CXCursorKind) -> String {
    if let Some(value) = legacy_kind_name(kind) {
        return value.to_owned();
    }
    camel_to_upper_snake(&unsafe { cx_string(clang_getCursorKindSpelling(kind)) })
}

fn legacy_kind_name(kind: CXCursorKind) -> Option<&'static str> {
    [
        (CXCursor_FunctionDecl, "FUNCTION_DECL"),
        (CXCursor_CXXMethod, "CXX_METHOD"),
        (CXCursor_Constructor, "CONSTRUCTOR"),
        (CXCursor_Destructor, "DESTRUCTOR"),
        (CXCursor_FunctionTemplate, "FUNCTION_TEMPLATE"),
        (CXCursor_ClassDecl, "CLASS_DECL"),
        (CXCursor_ClassTemplate, "CLASS_TEMPLATE"),
        (CXCursor_StructDecl, "STRUCT_DECL"),
        (CXCursor_UnionDecl, "UNION_DECL"),
        (CXCursor_EnumDecl, "ENUM_DECL"),
        (CXCursor_TypedefDecl, "TYPEDEF_DECL"),
        (CXCursor_TypeAliasDecl, "TYPE_ALIAS_DECL"),
        (CXCursor_VarDecl, "VAR_DECL"),
        (CXCursor_FieldDecl, "FIELD_DECL"),
        (CXCursor_EnumConstantDecl, "ENUM_CONSTANT_DECL"),
        (CXCursor_Namespace, "NAMESPACE"),
        (CXCursor_DeclRefExpr, "DECL_REF_EXPR"),
        (CXCursor_MemberRefExpr, "MEMBER_REF_EXPR"),
        (CXCursor_CallExpr, "CALL_EXPR"),
        (CXCursor_TypeRef, "TYPE_REF"),
        (CXCursor_TemplateRef, "TEMPLATE_REF"),
        (CXCursor_NamespaceRef, "NAMESPACE_REF"),
        (CXCursor_MemberRef, "MEMBER_REF"),
    ]
    .into_iter()
    .find_map(|(candidate, name)| (candidate == kind).then_some(name))
}

fn camel_to_upper_snake(value: &str) -> String {
    let mut out = String::new();
    let chars = value.chars().collect::<Vec<_>>();
    for (index, ch) in chars.iter().copied().enumerate() {
        if index > 0 {
            let prev = chars[index - 1];
            let next = chars.get(index + 1).copied();
            if ch.is_ascii_uppercase()
                && (prev.is_ascii_lowercase()
                    || prev.is_ascii_digit()
                    || next.is_some_and(|n| n.is_ascii_lowercase()))
            {
                out.push('_');
            }
        }
        if ch.is_ascii_whitespace() || ch == '-' {
            out.push('_');
        } else {
            out.push(ch.to_ascii_uppercase());
        }
    }
    out
}

fn is_declaration_kind(kind: CXCursorKind) -> bool {
    [
        CXCursor_FunctionDecl,
        CXCursor_CXXMethod,
        CXCursor_Constructor,
        CXCursor_Destructor,
        CXCursor_FunctionTemplate,
        CXCursor_ClassDecl,
        CXCursor_ClassTemplate,
        CXCursor_StructDecl,
        CXCursor_UnionDecl,
        CXCursor_EnumDecl,
        CXCursor_TypedefDecl,
        CXCursor_TypeAliasDecl,
        CXCursor_VarDecl,
        CXCursor_FieldDecl,
        CXCursor_EnumConstantDecl,
        CXCursor_Namespace,
    ]
    .contains(&kind)
}

fn cursor_needs_signature(kind: CXCursorKind) -> bool {
    [
        CXCursor_FunctionDecl,
        CXCursor_CXXMethod,
        CXCursor_Constructor,
        CXCursor_Destructor,
        CXCursor_FunctionTemplate,
    ]
    .contains(&kind)
}

fn is_reference_kind(kind: CXCursorKind) -> bool {
    [
        CXCursor_DeclRefExpr,
        CXCursor_MemberRefExpr,
        CXCursor_CallExpr,
        CXCursor_TypeRef,
        CXCursor_TemplateRef,
        CXCursor_NamespaceRef,
        CXCursor_MemberRef,
    ]
    .contains(&kind)
}

fn line_context(path: &Path, line: u32, cache: &mut HashMap<PathBuf, Vec<String>>) -> String {
    let lines = cache.entry(path.to_path_buf()).or_insert_with(|| {
        fs::read_to_string(path)
            .map(|text| text.lines().map(ToOwned::to_owned).collect())
            .unwrap_or_default()
    });
    lines
        .get(line.saturating_sub(1) as usize)
        .map_or_else(String::new, |value| {
            value.trim().chars().take(300).collect()
        })
}

fn severity_name(value: u32) -> &'static str {
    match value {
        0 => "ignored",
        1 => "note",
        2 => "warning",
        3 => "error",
        4 => "fatal",
        _ => "unknown",
    }
}

fn flush_semantic_rows(
    conn: &Connection,
    symbol_rows: &mut Vec<SymbolRow>,
    ref_rows: &mut Vec<RefRow>,
    force: bool,
    batch_size: usize,
) -> Result<()> {
    while (!symbol_rows.is_empty() && (force || symbol_rows.len() >= batch_size))
        || (!ref_rows.is_empty() && (force || ref_rows.len() >= batch_size))
    {
        let tx = conn.unchecked_transaction()?;
        if !symbol_rows.is_empty() && (force || symbol_rows.len() >= batch_size) {
            let chunk_size = if force { symbol_rows.len() } else { batch_size };
            let mut stmt = tx.prepare(
                r#"
                INSERT OR IGNORE INTO symbols(
                  usr, name, kind, path, line, is_definition, type, signature
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
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
                    row.type_text,
                    row.signature,
                ])?;
            }
        }
        if !ref_rows.is_empty() && (force || ref_rows.len() >= batch_size) {
            let chunk_size = if force { ref_rows.len() } else { batch_size };
            let mut stmt = tx.prepare(
                "INSERT OR IGNORE INTO refs(referenced_usr, name, kind, path, line, context) VALUES (?, ?, ?, ?, ?, ?)",
            )?;
            for row in ref_rows.drain(..chunk_size) {
                stmt.execute(params![
                    row.referenced_usr,
                    row.name,
                    row.kind,
                    row.path,
                    row.line,
                    row.context,
                ])?;
            }
        }
        tx.commit()?;
    }
    Ok(())
}
