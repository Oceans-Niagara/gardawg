use crate::physics::{evaluate_payload, LinkProfile};
use crate::sarif::{Finding, Severity};
use globset::{Glob, GlobSet, GlobSetBuilder};
use ignore::WalkBuilder;
use std::collections::{HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use tree_sitter::{Node, Parser};

pub const TOTAL_RULES_COUNT: usize = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    Python,
    Rust,
    Cpp,
    TypeScript,
    JavaScript,
}

impl Lang {
    pub fn from_path(path: &Path) -> Option<Self> {
        match path
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| s.to_ascii_lowercase())
            .as_deref()
        {
            Some("py") => Some(Self::Python),
            Some("rs") => Some(Self::Rust),
            Some("c" | "cc" | "cpp" | "cxx" | "h" | "hh" | "hpp" | "hxx" | "ino") => {
                Some(Self::Cpp)
            }
            Some("ts" | "tsx" | "mts" | "cts") => Some(Self::TypeScript),
            Some("js" | "jsx" | "mjs" | "cjs") => Some(Self::JavaScript),
            _ => None,
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "py" | "python" => Some(Self::Python),
            "rs" | "rust" => Some(Self::Rust),
            "c" | "cc" | "cpp" | "c++" | "h" | "hpp" | "ino" => Some(Self::Cpp),
            "ts" | "tsx" | "typescript" => Some(Self::TypeScript),
            "js" | "jsx" | "javascript" => Some(Self::JavaScript),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::Rust => "rust",
            Self::Cpp => "cpp",
            Self::TypeScript => "typescript",
            Self::JavaScript => "javascript",
        }
    }

    pub fn suffix(self) -> &'static str {
        match self {
            Self::Python => "PY",
            Self::Rust => "RUST",
            Self::Cpp => "CPP",
            Self::TypeScript => "TS",
            Self::JavaScript => "JS",
        }
    }

    fn comment_prefix(self) -> &'static str {
        match self {
            Self::Python => "#",
            _ => "//",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ScanOptions<'a> {
    pub exclude: &'a [String],
    pub link_profile: Option<&'a LinkProfile>,
    pub assumed_hz: f64,
    pub pedantic: bool,
}

#[derive(Debug, Clone)]
pub struct UnifiedScanResult {
    pub files_scanned: usize,
    pub rules_evaluated: usize,
    pub findings: Vec<Finding>,
}

#[derive(Clone, Default)]
struct WalkContext {
    in_loop: bool,
    in_async: bool,
    in_batch_guard: bool,
    in_rust_test_mod: bool,
    loop_hz_inferred: Option<f64>,
    has_timeout_in_file: bool,
    has_http_timeout_in_file: bool,
    has_atomic_replace_in_file: bool,
    has_c_socket_timeout_in_file: bool,
    has_framing_in_file: bool,
    local_sink_vars: HashSet<String>,
}

const MONEY_KEYWORDS: &[&str] = &[
    "price", "amount", "total", "subtotal", "tax", "fee", "balance", "qty", "quantity", "cents",
];

fn is_money_name(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    MONEY_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

fn build_exclude_set(patterns: &[String]) -> anyhow::Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for p in patterns {
        builder.add(Glob::new(p)?);
    }
    Ok(builder.build()?)
}

fn is_test_or_example_path(rel: &str) -> bool {
    let norm = rel.replace('\\', "/");
    norm.starts_with("tests/")
        || norm.contains("/tests/")
        || norm.starts_with("examples/")
        || norm.contains("/examples/")
        || norm.ends_with("_test.rs")
        || norm.ends_with("_test.cpp")
        || norm.ends_with("_test.c")
        || norm.contains("test_")
}

fn line_suppressed(src: &str, line_idx: usize, rule_id: &str) -> bool {
    let line = src.lines().nth(line_idx).unwrap_or("");
    for marker in ["gardawg-ignore", "linkguard-ignore"] {
        if let Some(pos) = line.find(marker) {
            let after = line[pos + marker.len()..].trim_start();
            if after.starts_with('(') {
                if let Some(end) = after.find(')') {
                    let spec = after[1..end].trim().to_ascii_uppercase();
                    let upper_rule = rule_id.to_ascii_uppercase();
                    if upper_rule == spec || upper_rule.starts_with(&format!("{spec}-")) || spec.is_empty() {
                        return true;
                    }
                    continue;
                }
            }
            return true;
        }
    }
    false
}

fn make_hint(lang: Lang, rule_id: &str) -> String {
    format!("{} gardawg-ignore({rule_id})", lang.comment_prefix())
}

#[allow(clippy::too_many_arguments)]
fn push_finding(
    out: &mut Vec<Finding>,
    src: &str,
    lang: Lang,
    rule_id: &str,
    tool: &str,
    severity: Severity,
    tier: &str,
    file: &str,
    line: usize,
    col: usize,
    snippet: Option<String>,
    message: String,
    physics_law: Option<String>,
    remediation: Option<String>,
    budget: Option<crate::physics::PayloadBudgetReport>,
) {
    if line_suppressed(src, line.saturating_sub(1), rule_id) {
        return;
    }
    out.push(Finding {
        rule_id: rule_id.to_string(),
        tool: tool.to_string(),
        severity,
        tier: Some(tier.to_string()),
        message,
        file: file.to_string(),
        start_line: line.max(1),
        start_col: col.max(1),
        snippet,
        physics_law,
        remediation,
        suppression_hint: Some(make_hint(lang, rule_id)),
        budget,
    });
}

pub fn scan_workspace(root: &Path, opts: &ScanOptions<'_>) -> anyhow::Result<UnifiedScanResult> {
    let excludes = build_exclude_set(opts.exclude)?;
    let mut files: Vec<(PathBuf, String, Lang)> = Vec::new();

    if root.is_file() {
        if let Some(lang) = Lang::from_path(root) {
            let rel = root.file_name().and_then(|n| n.to_str()).unwrap_or("file").to_string();
            files.push((root.to_path_buf(), rel, lang));
        }
    } else {
        for entry in WalkBuilder::new(root).hidden(true).git_ignore(true).build().flatten() {
            if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                continue;
            }
            let path = entry.path();
            let rel = path
                .strip_prefix(root)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");
            if excludes.is_match(&rel) {
                continue;
            }
            if let Some(lang) = Lang::from_path(path) {
                files.push((path.to_path_buf(), rel, lang));
            }
        }
    }

    let mut findings = Vec::new();
    for (path, rel, lang) in &files {
        let Ok(src) = fs::read_to_string(path) else { continue };
        let file_findings = analyze_source(
            &src,
            *lang,
            rel,
            opts.link_profile,
            if opts.assumed_hz > 0.0 { opts.assumed_hz } else { 10.0 },
            opts.pedantic,
        )?;
        findings.extend(file_findings);
    }

    Ok(UnifiedScanResult {
        files_scanned: files.len(),
        rules_evaluated: TOTAL_RULES_COUNT,
        findings,
    })
}

pub fn analyze_source(
    source: &str,
    lang: Lang,
    file_label: &str,
    profile: Option<&LinkProfile>,
    assumed_hz: f64,
    pedantic: bool,
) -> anyhow::Result<Vec<Finding>> {
    let mut parser = Parser::new();
    match lang {
        Lang::Python => parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .map_err(|e| anyhow::anyhow!("Python grammar error: {e}"))?,
        Lang::Rust => parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .map_err(|e| anyhow::anyhow!("Rust grammar error: {e}"))?,
        Lang::Cpp => parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .map_err(|e| anyhow::anyhow!("C/C++ grammar error: {e}"))?,
        Lang::TypeScript => {
            let ts_lang = if file_label.to_ascii_lowercase().ends_with(".tsx") {
                tree_sitter_typescript::LANGUAGE_TSX.into()
            } else {
                tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()
            };
            parser
                .set_language(&ts_lang)
                .map_err(|e| anyhow::anyhow!("TypeScript grammar error: {e}"))?;
        }
        Lang::JavaScript => parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .map_err(|e| anyhow::anyhow!("JavaScript grammar error: {e}"))?,
    }

    let tree = parser
        .parse(source, None)
        .ok_or_else(|| anyhow::anyhow!("Tree-sitter failed to parse {file_label}"))?;

    let mut findings = Vec::new();

    // 0. Syntax / parse errors (GR000)
    let mut error_locs = Vec::new();
    collect_error_nodes(tree.root_node(), &mut error_locs);
    let mut seen_err_lines = HashSet::new();
    for (line, col) in error_locs {
        if !seen_err_lines.insert(line) {
            continue;
        }
        push_finding(
            &mut findings,
            source,
            lang,
            &format!("GR000-SYNTAX-ERROR-{}", lang.suffix()),
            "gardawg-ast",
            Severity::Error,
            "critical",
            file_label,
            line,
            col,
            source.lines().nth(line.saturating_sub(1)).map(|s| s.trim().to_string()),
            "Syntax/parse error detected; file may contain invalid syntax or stray markdown fences (```).".into(),
            None,
            Some("Fix the syntax error or remove stray markdown code fences before continuing.".into()),
            None,
        );
    }

    let has_timeout_in_file = source.contains(".settimeout(")
        || source.contains("set_read_timeout")
        || source.contains("set_write_timeout")
        || source.contains("tokio::time::timeout")
        || source.contains("AbortController")
        || source.contains("AbortSignal.timeout")
        || source.contains("SO_RCVTIMEO")
        || source.contains("SO_SNDTIMEO")
        || source.contains("Serial.setTimeout");

    let has_http_timeout_in_file = source.contains(".timeout =")
        || source.contains("settimeout(")
        || source.contains("daemon_threads = True")
        || source.contains("daemon_threads=True");

    let has_atomic_replace_in_file = source.contains("os.replace(")
        || source.contains("os.rename(")
        || source.contains("NamedTemporaryFile");

    let has_c_socket_timeout_in_file = source.contains("SO_RCVTIMEO")
        || source.contains("SO_SNDTIMEO")
        || source.contains("select(")
        || source.contains("poll(")
        || source.contains("epoll_wait(");

    let lower_src = source.to_ascii_lowercase();
    let has_framing_in_file = lower_src.contains("crc")
        || lower_src.contains("checksum")
        || lower_src.contains("hmac")
        || lower_src.contains("sha256")
        || lower_src.contains("cobs")
        || lower_src.contains("slip")
        || lower_src.contains("seq")
        || lower_src.contains("frame_id")
        || lower_src.contains("fec")
        || lower_src.contains("reed_solomon");

    let local_sink_vars = collect_local_sink_vars(source);

    let ctx = WalkContext {
        in_loop: false,
        in_async: false,
        in_batch_guard: false,
        in_rust_test_mod: false,
        loop_hz_inferred: None,
        has_timeout_in_file,
        has_http_timeout_in_file,
        has_atomic_replace_in_file,
        has_c_socket_timeout_in_file,
        has_framing_in_file,
        local_sink_vars,
    };

    walk_node(
        tree.root_node(),
        source,
        lang,
        file_label,
        profile,
        assumed_hz,
        pedantic,
        ctx,
        &mut findings,
    );

    // Line-level secrets + AI comment checks
    let skip_secret_self_scan = file_label.ends_with("analyzer.rs") || file_label.ends_with("ast_rules.rs");
    for (idx, line) in source.lines().enumerate() {
        let line_no = idx + 1;
        if !skip_secret_self_scan && contains_hardcoded_secret(line) {
            push_finding(
                &mut findings,
                source,
                lang,
                "GR006-HARDCODED-SECRET",
                "gardawg-ast",
                Severity::Error,
                "critical",
                file_label,
                line_no,
                1,
                Some(line.trim().to_string()),
                "Hardcoded secret or private key material detected in source.".into(),
                None,
                Some("Load credentials from environment variables (`std::env::var` / `os.environ` / `process.env`).".into()),
                None,
            );
        }
        let trimmed = line.trim();
        let is_comment = trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with("/*");
        if is_comment {
            if trimmed.contains("PLACEHOLDER") {
                push_finding(
                    &mut findings,
                    source,
                    lang,
                    "GR005-AI-COMMENT-PLACEHOLDER",
                    "gardawg-ast",
                    Severity::Warning,
                    "high",
                    file_label,
                    line_no,
                    1,
                    Some(trimmed.to_string()),
                    "Unresolved PLACEHOLDER comment left in code.".into(),
                    None,
                    Some("Replace placeholder with complete implementation.".into()),
                    None,
                );
            } else if pedantic && (trimmed.contains("TODO:") || trimmed.contains("FIXME:")) {
                push_finding(
                    &mut findings,
                    source,
                    lang,
                    "GR005-AI-COMMENT-TODO",
                    "gardawg-ast",
                    Severity::Note,
                    "pedantic",
                    file_label,
                    line_no,
                    1,
                    Some(trimmed.to_string()),
                    "Unresolved TODO/FIXME comment left in code.".into(),
                    None,
                    Some("Resolve TODO/FIXME or convert into a tracked issue.".into()),
                    None,
                );
            }
        }
    }

    Ok(findings)
}

fn collect_error_nodes(node: Node, out: &mut Vec<(usize, usize)>) {
    if node.is_error() {
        let pos = node.start_position();
        out.push((pos.row + 1, pos.column + 1));
        return;
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            collect_error_nodes(child, out);
        }
    }
}

/// Identifies variable names bound to local disk writers or in-memory channels (mpsc, BufWriter, File).
fn collect_local_sink_vars(source: &str) -> HashSet<String> {
    let mut vars = HashSet::new();
    for line in source.lines() {
        let t = line.trim();
        let is_local_sink = t.contains("mpsc::")
            || t.contains("oneshot::")
            || t.contains("crossbeam")
            || t.contains("BufWriter")
            || t.contains("File::create")
            || t.contains("File::open")
            || t.contains("OpenOptions")
            || t.contains("queue.Queue(")
            || t.contains("asyncio.Queue(")
            || t.contains("open(");

        if is_local_sink {
            if let Some(lhs) = t.split('=').next() {
                for tok in lhs.split(|c: char| !c.is_alphanumeric() && c != '_') {
                    if !tok.is_empty() && !matches!(tok, "let" | "mut" | "const" | "var" | "with" | "as") {
                        vars.insert(tok.to_string());
                    }
                }
            }
        }
    }
    vars
}

fn is_loop_kind(kind: &str) -> bool {
    matches!(
        kind,
        "for_statement"
            | "for_in_statement"
            | "for_range_loop"
            | "while_statement"
            | "do_statement"
            | "for_expression"
            | "while_expression"
            | "loop_expression"
    )
}

fn is_function_boundary(kind: &str, lang: Lang) -> bool {
    match lang {
        Lang::Python => matches!(kind, "function_definition" | "lambda"),
        Lang::Rust => matches!(kind, "function_item" | "closure_expression"),
        Lang::Cpp => matches!(kind, "function_definition" | "lambda_expression"),
        Lang::TypeScript | Lang::JavaScript => matches!(
            kind,
            "function_declaration" | "function_expression" | "arrow_function" | "method_definition"
        ),
    }
}

fn is_batch_if_guard(node: Node, source: &str) -> bool {
    let kind = node.kind();
    if kind != "if_statement" && kind != "if_expression" {
        return false;
    }
    if let Some(cond) = node.child_by_field_name("condition") {
        let cond_txt = cond.utf8_text(source.as_bytes()).unwrap_or("");
        let has_len = cond_txt.contains("len(")
            || cond_txt.contains(".len()")
            || cond_txt.contains(".length")
            || cond_txt.contains(".byteLength")
            || cond_txt.contains(".size()");
        let has_cmp = cond_txt.contains(">=") || cond_txt.contains("==") || cond_txt.contains('>');
        return has_len && has_cmp;
    }
    false
}

fn cpp_function_name<'a>(node: Node<'a>, source: &'a str) -> Option<&'a str> {
    if node.kind() != "function_definition" {
        return None;
    }
    let decl = node.child_by_field_name("declarator")?;
    let inner = decl.child_by_field_name("declarator").unwrap_or(decl);
    inner.utf8_text(source.as_bytes()).ok()
}

fn is_cpp_loop_fn(node: Node, source: &str) -> bool {
    cpp_function_name(node, source) == Some("loop")
}

fn is_cpp_rtos_or_async_fn(node: Node, source: &str) -> bool {
    if node.kind() != "function_definition" {
        return false;
    }
    let text = node.utf8_text(source.as_bytes()).unwrap_or("");
    let header = text.split('{').next().unwrap_or("");
    if header.contains("pvParameters") || text.contains("co_await") || text.contains("co_return") {
        return true;
    }
    if let Some(name) = cpp_function_name(node, source) {
        let lower = name.to_ascii_lowercase();
        return lower.contains("task")
            || lower.contains("worker")
            || lower.contains("thread")
            || lower.contains("async");
    }
    false
}

fn extract_setinterval_hz(node: Node, source: &str) -> Option<f64> {
    if node.kind() != "call_expression" {
        return None;
    }
    let callee = node
        .child_by_field_name("function")
        .and_then(|n| n.utf8_text(source.as_bytes()).ok())
        .unwrap_or("");
    if callee != "setInterval" && !callee.ends_with(".setInterval") {
        return None;
    }
    let args = node.child_by_field_name("arguments")?;
    let ms_node = args.named_child(1)?;
    let ms_text = ms_node.utf8_text(source.as_bytes()).ok()?.trim();
    let ms = ms_text.replace('_', "").parse::<f64>().ok()?;
    if ms > 0.0 {
        Some((1000.0 / ms).clamp(0.001, 100_000.0))
    } else {
        None
    }
}

fn infer_loop_hz(loop_node: Node, source: &str, lang: Lang) -> Option<f64> {
    fn scan(node: Node, source: &str, lang: Lang, is_root: bool) -> Option<f64> {
        let kind = node.kind();
        if !is_root && (is_loop_kind(kind) || is_function_boundary(kind, lang)) {
            return None;
        }
        if matches!(kind, "call" | "call_expression") {
            let text = node.utf8_text(source.as_bytes()).unwrap_or("");
            let callee = node
                .child_by_field_name("function")
                .and_then(|n| n.utf8_text(source.as_bytes()).ok())
                .unwrap_or("");

            match lang {
                Lang::Python => {
                    if callee.ends_with("time.sleep") || callee.ends_with("asyncio.sleep") {
                        if let Some(secs) = extract_single_float_in_parens(text) {
                            if secs > 0.0 {
                                return Some((1.0 / secs).clamp(0.001, 100_000.0));
                            }
                        }
                    }
                }
                Lang::Rust => {
                    if callee.ends_with("thread::sleep") || callee.ends_with("time::sleep") {
                        if let Some(secs) = extract_rust_duration_secs(text) {
                            if secs > 0.0 {
                                return Some((1.0 / secs).clamp(0.001, 100_000.0));
                            }
                        }
                    }
                }
                Lang::Cpp => {
                    if callee == "delay" || callee == "HAL_Delay" || callee == "pdMS_TO_TICKS" {
                        if let Some(ms) = extract_single_float_in_parens(text) {
                            if ms > 0.0 {
                                return Some((1000.0 / ms).clamp(0.001, 100_000.0));
                            }
                        }
                    } else if callee == "usleep" || callee == "delayMicroseconds" {
                        if let Some(us) = extract_single_float_in_parens(text) {
                            if us > 0.0 {
                                return Some((1_000_000.0 / us).clamp(0.001, 100_000.0));
                            }
                        }
                    } else if callee == "sleep" {
                        if let Some(secs) = extract_single_float_in_parens(text) {
                            if secs > 0.0 {
                                return Some((1.0 / secs).clamp(0.001, 100_000.0));
                            }
                        }
                    }
                }
                Lang::TypeScript | Lang::JavaScript => {
                    if callee == "sleep" || callee.ends_with(".sleep") {
                        if let Some(ms) = extract_single_float_in_parens(text) {
                            if ms > 0.0 {
                                return Some((1000.0 / ms).clamp(0.001, 100_000.0));
                            }
                        }
                    }
                }
            }
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(hz) = scan(child, source, lang, false) {
                    return Some(hz);
                }
            }
        }
        None
    }

    scan(loop_node, source, lang, true)
}

fn extract_single_float_in_parens(call_text: &str) -> Option<f64> {
    let open = call_text.rfind('(')?;
    let close = call_text[open + 1..].find(')')?;
    let inner = call_text[open + 1..open + 1 + close].trim();
    inner.parse::<f64>().ok()
}

fn extract_rust_duration_secs(text: &str) -> Option<f64> {
    if let Some(pos) = text.find("from_millis(") {
        let rest = &text[pos + "from_millis(".len()..];
        let end = rest.find(')')?;
        let ms = rest[..end].trim().replace('_', "").parse::<f64>().ok()?;
        return Some(ms / 1000.0);
    }
    if let Some(pos) = text.find("from_micros(") {
        let rest = &text[pos + "from_micros(".len()..];
        let end = rest.find(')')?;
        let us = rest[..end].trim().replace('_', "").parse::<f64>().ok()?;
        return Some(us / 1_000_000.0);
    }
    for prefix in ["from_secs_f64(", "from_secs_f32(", "from_secs("] {
        if let Some(pos) = text.find(prefix) {
            let rest = &text[pos + prefix.len()..];
            let end = rest.find(')')?;
            return rest[..end].trim().replace('_', "").parse::<f64>().ok();
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn walk_node(
    node: Node,
    source: &str,
    lang: Lang,
    file_label: &str,
    profile: Option<&LinkProfile>,
    assumed_hz: f64,
    pedantic: bool,
    ctx: WalkContext,
    findings: &mut Vec<Finding>,
) {
    let kind = node.kind();
    let text = node.utf8_text(source.as_bytes()).unwrap_or("");

    // Detect #[cfg(test)] mod tests in Rust
    let enters_rust_test = lang == Lang::Rust
        && kind == "mod_item"
        && node
            .prev_named_sibling()
            .and_then(|s| s.utf8_text(source.as_bytes()).ok())
            .map(|t| t.contains("cfg(test)"))
            .unwrap_or(false);

    let setinterval_hz = match lang {
        Lang::TypeScript | Lang::JavaScript => extract_setinterval_hz(node, source),
        _ => None,
    };

    let is_loop = is_loop_kind(kind)
        || (lang == Lang::Cpp && is_cpp_loop_fn(node, source))
        || setinterval_hz.is_some();

    let is_fn_boundary = is_function_boundary(kind, lang) && !(lang == Lang::Cpp && is_cpp_loop_fn(node, source));

    // Only stop loop propagation at nested function/closure boundaries (NOT try/except/if/match)
    let inherited_in_loop = if is_fn_boundary { false } else { ctx.in_loop };
    let inherited_batch_guard = if is_fn_boundary { false } else { ctx.in_batch_guard };
    let inherited_hz = if is_fn_boundary { None } else { ctx.loop_hz_inferred };

    let inferred_hz = if setinterval_hz.is_some() {
        setinterval_hz.or(inherited_hz)
    } else if is_loop {
        infer_loop_hz(node, source, lang).or(inherited_hz)
    } else {
        inherited_hz
    };

    let is_async_fn = match lang {
        Lang::Python => kind == "function_definition" && text.trim_start().starts_with("async "),
        Lang::Rust => {
            kind == "function_item"
                && text
                    .split('{')
                    .next()
                    .unwrap_or("")
                    .split_whitespace()
                    .any(|w| w == "async")
        }
        Lang::Cpp => is_cpp_rtos_or_async_fn(node, source),
        Lang::TypeScript | Lang::JavaScript => {
            matches!(
                kind,
                "function_declaration" | "function_expression" | "arrow_function" | "method_definition"
            ) && text
                .split('{')
                .next()
                .unwrap_or("")
                .split_whitespace()
                .any(|w| w == "async")
        }
    };

    let next_ctx = WalkContext {
        in_loop: inherited_in_loop || is_loop,
        in_async: if is_fn_boundary { is_async_fn } else { ctx.in_async || is_async_fn },
        in_batch_guard: inherited_batch_guard || is_batch_if_guard(node, source),
        in_rust_test_mod: ctx.in_rust_test_mod || enters_rust_test,
        loop_hz_inferred: inferred_hz,
        has_timeout_in_file: ctx.has_timeout_in_file,
        has_http_timeout_in_file: ctx.has_http_timeout_in_file,
        has_atomic_replace_in_file: ctx.has_atomic_replace_in_file,
        has_c_socket_timeout_in_file: ctx.has_c_socket_timeout_in_file,
        has_framing_in_file: ctx.has_framing_in_file,
        local_sink_vars: ctx.local_sink_vars.clone(),
    };

    inspect_gardawg_node(
        node,
        source,
        text,
        lang,
        file_label,
        pedantic,
        &next_ctx,
        findings,
    );

    if let Some(prof) = profile {
        let is_call = matches!(kind, "call" | "call_expression" | "macro_invocation");
        if is_call {
            inspect_link_call(
                node,
                source,
                text,
                lang,
                file_label,
                prof,
                assumed_hz,
                &next_ctx,
                findings,
            );
        }
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            walk_node(
                child,
                source,
                lang,
                file_label,
                profile,
                assumed_hz,
                pedantic,
                next_ctx.clone(),
                findings,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn inspect_gardawg_node(
    node: Node,
    source: &str,
    text: &str,
    lang: Lang,
    file_label: &str,
    pedantic: bool,
    ctx: &WalkContext,
    findings: &mut Vec<Finding>,
) {
    let kind = node.kind();
    let pos = node.start_position();
    let line = pos.row + 1;
    let col = pos.column + 1;
    let snippet = Some(text.lines().next().unwrap_or(text).trim().to_string());

    match lang {
        Lang::Rust => {
            // GR001: f64 / f32 on money/quantity identifiers
            if matches!(kind, "parameter" | "let_declaration" | "field_declaration") {
                if let Some(ty_node) = node.child_by_field_name("type") {
                    let ty = ty_node.utf8_text(source.as_bytes()).unwrap_or("").trim();
                    if matches!(ty, "f64" | "f32") {
                        let ident = node
                            .child_by_field_name("pattern")
                            .or_else(|| node.child_by_field_name("name"))
                            .and_then(|n| n.utf8_text(source.as_bytes()).ok())
                            .unwrap_or("");
                        if is_money_name(ident) {
                            let rule_id = if ty == "f32" {
                                "GR001-FLOAT-MONEY-RUST-F32"
                            } else {
                                "GR001-FLOAT-MONEY-RUST"
                            };
                            push_finding(
                                findings, source, lang, rule_id, "gardawg-ast",
                                Severity::Error, "high", file_label, line, col, snippet.clone(),
                                format!("Floating-point type `{ty}` used for monetary or quantity identifier `{ident}`."),
                                None,
                                Some("Use integer minor units or `rust_decimal::Decimal`:\n```rust\nlet amount_cents: i64 = 1999;\n```".into()),
                                None,
                            );
                        }
                    }
                }
            }

            // GR004: let _ = <expr>; with smart exemptions
            if kind == "let_declaration" {
                let pat = node
                    .child_by_field_name("pattern")
                    .and_then(|n| n.utf8_text(source.as_bytes()).ok())
                    .unwrap_or("")
                    .trim();
                if pat == "_" {
                    let val_txt = node
                        .child_by_field_name("value")
                        .and_then(|n| n.utf8_text(source.as_bytes()).ok())
                        .unwrap_or("");
                    if !is_rust_let_underscore_exempt(val_txt) {
                        let is_io_risk = is_rust_critical_io_expr(val_txt);
                        if is_io_risk || pedantic {
                            push_finding(
                                findings, source, lang, "GR004-SWALLOWED-ERR-RUST", "gardawg-ast",
                                if is_io_risk { Severity::Warning } else { Severity::Note },
                                if is_io_risk { "high" } else { "pedantic" },
                                file_label, line, col, snippet.clone(),
                                "Swallowed Result/Option via `let _ = ...` on I/O or state operation.".into(),
                                None,
                                Some("Propagate with `?` or log the failure:\n```rust\nif let Err(e) = op() { tracing::warn!(\"op failed: {e}\"); }\n```".into()),
                                None,
                            );
                        }
                    }
                }
            }

            // GR005: todo!() / unimplemented!()
            if kind == "macro_invocation" {
                let mac = node
                    .child_by_field_name("macro")
                    .and_then(|n| n.utf8_text(source.as_bytes()).ok())
                    .unwrap_or("");
                if mac == "todo" {
                    push_finding(
                        findings, source, lang, "GR005-AI-STUB-RUST-TODO", "gardawg-ast",
                        Severity::Error, "critical", file_label, line, col, snippet.clone(),
                        "Unfinished `todo!()` macro left in code.".into(),
                        None,
                        Some("Implement the function body or return a typed `Err` before merge.".into()),
                        None,
                    );
                } else if mac == "unimplemented" {
                    push_finding(
                        findings, source, lang, "GR005-AI-STUB-RUST-UNIMPL", "gardawg-ast",
                        Severity::Error, "critical", file_label, line, col, snippet.clone(),
                        "Unfinished `unimplemented!()` macro left in code.".into(),
                        None,
                        Some("Implement the function body or return a typed `Err` before merge.".into()),
                        None,
                    );
                }
            }

            // GR002 & GR007: reqwest::Client::new(), .unwrap()
            if kind == "call_expression" {
                let callee = node
                    .child_by_field_name("function")
                    .and_then(|n| n.utf8_text(source.as_bytes()).ok())
                    .unwrap_or("");
                if callee == "reqwest::Client::new" {
                    push_finding(
                        findings, source, lang, "GR002-MISSING-TIMEOUT-RUST", "gardawg-ast",
                        Severity::Error, "high", file_label, line, col, snippet.clone(),
                        "`reqwest::Client::new()` has no default request timeout.".into(),
                        None,
                        Some("Configure an explicit timeout:\n```rust\nlet client = reqwest::Client::builder().timeout(Duration::from_secs(10)).build()?;\n```".into()),
                        None,
                    );
                }
                if callee.ends_with(".unwrap")
                    && !ctx.in_rust_test_mod
                    && !is_test_or_example_path(file_label)
                    && !source[..node.start_byte()].contains("#[cfg(test)]")
                {
                    push_finding(
                        findings, source, lang, "GR007-PANIC-UNWRAP-RUST", "gardawg-ast",
                        Severity::Warning, "high", file_label, line, col, snippet,
                        "`.unwrap()` in production Rust code can panic at runtime.".into(),
                        None,
                        Some("Propagate errors with `?` or `.ok_or_else(...)`:\n```rust\nlet val = expr.context(\"missing value\")?;\n```".into()),
                        None,
                    );
                }
            }
        }

        Lang::Python => {
            // GR001: typed float annotation on money identifier
            if kind == "typed_parameter" || kind == "assignment" {
                if let Some(ty_node) = node.child_by_field_name("type") {
                    let ty = ty_node.utf8_text(source.as_bytes()).unwrap_or("").trim();
                    if ty == "float" {
                        let lhs = node
                            .child_by_field_name("left")
                            .or_else(|| node.named_child(0))
                            .and_then(|n| n.utf8_text(source.as_bytes()).ok())
                            .unwrap_or("");
                        if is_money_name(lhs) {
                            push_finding(
                                findings, source, lang, "GR001-FLOAT-MONEY-PY", "gardawg-ast",
                                Severity::Error, "high", file_label, line, col, snippet.clone(),
                                format!("Python `float` annotation used on monetary/quantity identifier `{lhs}`."),
                                None,
                                Some("Use `decimal.Decimal` or integer cents:\n```python\nfrom decimal import Decimal\namount: Decimal = Decimal(\"19.99\")\n```".into()),
                                None,
                            );
                        }
                    }
                }
            }

            // GR004: except ...: pass
            if kind == "except_clause" {
                let body_txt = node
                    .children(&mut node.walk())
                    .find(|c| c.kind() == "block")
                    .and_then(|b| b.utf8_text(source.as_bytes()).ok())
                    .unwrap_or("")
                    .trim();
                if body_txt == "pass" {
                    push_finding(
                        findings, source, lang, "GR004-SWALLOWED-ERR-PY", "gardawg-ast",
                        Severity::Error, "high", file_label, line, col, snippet.clone(),
                        "`except ...: pass` silently swallows failures.".into(),
                        None,
                        Some("Log and handle or re-raise the exception:\n```python\nexcept OSError as exc:\n    logging.warning(\"I/O error: %s\", exc)\n```".into()),
                        None,
                    );
                }
            }

            // GR005: raise NotImplementedError(...)
            if kind == "raise_statement" && text.contains("NotImplementedError") {
                push_finding(
                    findings, source, lang, "GR005-AI-STUB-PY", "gardawg-ast",
                    Severity::Error, "critical", file_label, line, col, snippet.clone(),
                    "Unfinished `NotImplementedError` placeholder left in code.".into(),
                    None,
                    Some("Implement the behavior before finishing.".into()),
                    None,
                );
            }

            if kind == "call" {
                let callee = node
                    .child_by_field_name("function")
                    .and_then(|n| n.utf8_text(source.as_bytes()).ok())
                    .unwrap_or("");

                // GR002 HTTP clients
                if matches!(callee, "requests.post" | "requests.get" | "requests.put" | "requests.request")
                    && !text.contains("timeout")
                {
                    push_finding(
                        findings, source, lang, "GR002-MISSING-TIMEOUT-PY", "gardawg-ast",
                        Severity::Error, "high", file_label, line, col, snippet.clone(),
                        format!("`{callee}()` called without `timeout=` (can hang indefinitely)."),
                        None,
                        Some("Always pass an explicit timeout:\n```python\nresp = requests.post(url, json=payload, timeout=(3.05, 10))\n```".into()),
                        None,
                    );
                }
                if matches!(callee, "httpx.post" | "httpx.get" | "httpx.put") && !text.contains("timeout") {
                    push_finding(
                        findings, source, lang, "GR002-MISSING-TIMEOUT-HTTPX", "gardawg-ast",
                        Severity::Error, "high", file_label, line, col, snippet.clone(),
                        format!("`{callee}()` called without explicit `timeout=`."),
                        None,
                        Some("Pass `timeout=10.0` or use `httpx.Client(timeout=10.0)`.".into()),
                        None,
                    );
                }

                // GR002 Python stdlib socket.socket() & HTTPServer / ThreadingHTTPServer
                if (callee == "socket.socket" || callee == "socket") && !ctx.has_timeout_in_file {
                    push_finding(
                        findings, source, lang, "GR002-MISSING-TIMEOUT-PY-SOCKET", "gardawg-ast",
                        Severity::Error, "high", file_label, line, col, snippet.clone(),
                        "`socket.socket()` created without `.settimeout(...)` — blocking recv/connect can hang forever.".into(),
                        None,
                        Some("Set an explicit socket timeout immediately after creation:\n```python\nsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\nsock.settimeout(2.0)\n```".into()),
                        None,
                    );
                }
                if (callee.ends_with("HTTPServer") || callee.ends_with("ThreadingHTTPServer"))
                    && !ctx.has_http_timeout_in_file
                {
                    push_finding(
                        findings, source, lang, "GR002-MISSING-TIMEOUT-PY-HTTPSERVER", "gardawg-ast",
                        Severity::Error, "high", file_label, line, col, snippet.clone(),
                        "`HTTPServer`/`ThreadingHTTPServer` created without `.timeout` / `daemon_threads = True`.".into(),
                        None,
                        Some("Set socket/server timeout and daemon threads:\n```python\nserver = ThreadingHTTPServer(addr, Handler)\nserver.daemon_threads = True\nserver.timeout = 5.0\n```".into()),
                        None,
                    );
                }

                // Non-atomic JSON/state overwrites: open(..., "w") without os.replace()
                if callee == "open" && (text.contains("\"w\"") || text.contains("'w'")) {
                    let lower_t = text.to_ascii_lowercase();
                    if (lower_t.contains(".json") || lower_t.contains("state") || lower_t.contains("config"))
                        && !ctx.has_atomic_replace_in_file
                    {
                        push_finding(
                            findings, source, lang, "GR004-NON-ATOMIC-WRITE-PY", "gardawg-ast",
                            Severity::Warning, "high", file_label, line, col, snippet.clone(),
                            "Direct `open(..., \"w\")` overwrite of JSON/state file risks corruption on crash.".into(),
                            None,
                            Some("Write to a temp file and atomically swap with `os.replace()`:\n```python\nwith open(path + \".tmp\", \"w\") as f:\n    json.dump(data, f)\nos.replace(path + \".tmp\", path)\n```".into()),
                            None,
                        );
                    }
                }

                // GR003 idempotency
                if callee == "requests.post" && missing_idempotency_nearby(source, node.start_byte()) {
                    push_finding(
                        findings, source, lang, "GR003-IDEMPOTENCY-PY", "gardawg-ast",
                        Severity::Warning, "medium", file_label, line, col, snippet.clone(),
                        "POST request missing visible idempotency key header.".into(),
                        None,
                        Some("Include `headers={\"Idempotency-Key\": str(uuid.uuid4())}`.".into()),
                        None,
                    );
                }

                // GR006 security
                if callee == "eval" {
                    push_finding(
                        findings, source, lang, "GR006-UNSAFE-EVAL-PY", "gardawg-ast",
                        Severity::Error, "critical", file_label, line, col, snippet.clone(),
                        "Dynamic `eval()` risks arbitrary code execution.".into(),
                        None,
                        Some("Use `ast.literal_eval()` for literals or `json.loads()` for JSON.".into()),
                        None,
                    );
                } else if callee == "exec" {
                    push_finding(
                        findings, source, lang, "GR006-UNSAFE-EXEC-PY", "gardawg-ast",
                        Severity::Error, "critical", file_label, line, col, snippet.clone(),
                        "Dynamic `exec()` risks arbitrary code execution.".into(),
                        None,
                        Some("Avoid `exec()` and use explicit functions or dispatch tables.".into()),
                        None,
                    );
                } else if matches!(callee, "subprocess.run" | "subprocess.Popen")
                    && (text.contains("shell=True") || text.contains("shell = True"))
                {
                    let rule_id = if callee.ends_with("Popen") {
                        "GR006-SHELL-POPEN-PY"
                    } else {
                        "GR006-SHELL-INJECTION-PY"
                    };
                    push_finding(
                        findings, source, lang, rule_id, "gardawg-ast",
                        Severity::Error, "critical", file_label, line, col, snippet,
                        format!("`{callee}(..., shell=True)` risks command injection."),
                        None,
                        Some("Pass an argument list with `shell=False`:\n```python\nsubprocess.run([\"cmd\", arg], shell=False, check=True, timeout=10)\n```".into()),
                        None,
                    );
                }
            }
        }

        Lang::TypeScript | Lang::JavaScript => {
            let sfx = lang.suffix();

            // GR001: multiplication on money identifier
            if kind == "binary_expression" && text.contains('*') && is_money_name(text) {
                push_finding(
                    findings, source, lang, &format!("GR001-FLOAT-MONEY-{sfx}"), "gardawg-ast",
                    Severity::Warning, "medium", file_label, line, col, snippet.clone(),
                    "Floating-point multiplication on monetary/quantity identifier.".into(),
                    None,
                    Some("Compute in integer minor units (cents) or `decimal.js`.".into()),
                    None,
                );
            }

            // GR004: empty catch block
            if kind == "catch_clause" {
                let body_txt = node
                    .child_by_field_name("body")
                    .and_then(|b| b.utf8_text(source.as_bytes()).ok())
                    .unwrap_or("")
                    .trim();
                let inner = body_txt.trim_start_matches('{').trim_end_matches('}').trim();
                if inner.is_empty() {
                    push_finding(
                        findings, source, lang, &format!("GR004-SWALLOWED-ERR-{sfx}"), "gardawg-ast",
                        Severity::Error, "high", file_label, line, col, snippet.clone(),
                        "Empty `catch` block silently swallows exception.".into(),
                        None,
                        Some("Log, rethrow, or return a typed error inside `catch`.".into()),
                        None,
                    );
                }
            }

            // GR005: throw new Error("not implemented")
            if kind == "throw_statement" && text.to_ascii_lowercase().contains("not implemented") {
                push_finding(
                    findings, source, lang, &format!("GR005-AI-STUB-{sfx}"), "gardawg-ast",
                    Severity::Error, "critical", file_label, line, col, snippet.clone(),
                    "Placeholder `Error(\"not implemented\")` left in code.".into(),
                    None,
                    Some("Implement behavior before merge.".into()),
                    None,
                );
            }

            // GR006: new Function(...)
            if kind == "new_expression" {
                let ctor = node
                    .child_by_field_name("constructor")
                    .and_then(|n| n.utf8_text(source.as_bytes()).ok())
                    .unwrap_or("");
                if ctor == "Function" {
                    push_finding(
                        findings, source, lang, &format!("GR006-UNSAFE-FUNC-{sfx}"), "gardawg-ast",
                        Severity::Error, "critical", file_label, line, col, snippet.clone(),
                        "`new Function()` compiles arbitrary strings as executable code.".into(),
                        None,
                        Some("Replace dynamic code construction with static functions or lookup tables.".into()),
                        None,
                    );
                }
            }

            if kind == "call_expression" {
                let callee = node
                    .child_by_field_name("function")
                    .and_then(|n| n.utf8_text(source.as_bytes()).ok())
                    .unwrap_or("");
                if callee == "fetch" && !text.contains("signal") && !text.contains("timeout") {
                    push_finding(
                        findings, source, lang, &format!("GR002-MISSING-TIMEOUT-{sfx}"), "gardawg-ast",
                        Severity::Error, "high", file_label, line, col, snippet.clone(),
                        "`fetch()` called without an `AbortSignal` / timeout.".into(),
                        None,
                        Some("Pass an AbortSignal timeout:\n```js\nconst res = await fetch(url, { signal: AbortSignal.timeout(10_000) });\n```".into()),
                        None,
                    );
                }
                if callee.starts_with("axios.") && !text.contains("timeout") {
                    push_finding(
                        findings, source, lang, &format!("GR002-MISSING-TIMEOUT-AXIOS-{sfx}"), "gardawg-ast",
                        Severity::Error, "high", file_label, line, col, snippet.clone(),
                        format!("`{callee}()` called without explicit `timeout`."),
                        None,
                        Some("Pass `{ timeout: 10000 }` in Axios request config.".into()),
                        None,
                    );
                }
                if callee == "fetch"
                    && text.to_ascii_uppercase().contains("POST")
                    && missing_idempotency_nearby(source, node.start_byte())
                {
                    push_finding(
                        findings, source, lang, &format!("GR003-IDEMPOTENCY-{sfx}"), "gardawg-ast",
                        Severity::Warning, "medium", file_label, line, col, snippet.clone(),
                        "POST request missing visible idempotency key header.".into(),
                        None,
                        Some("Include an `Idempotency-Key` header in `fetch` headers.".into()),
                        None,
                    );
                }
                if callee == "eval" {
                    push_finding(
                        findings, source, lang, &format!("GR006-UNSAFE-EVAL-{sfx}"), "gardawg-ast",
                        Severity::Error, "critical", file_label, line, col, snippet,
                        "Dynamic `eval()` execution enables code injection.".into(),
                        None,
                        Some("Parse structured data with `JSON.parse()` instead of `eval()`.".into()),
                        None,
                    );
                }
            }
        }

        Lang::Cpp => {
            if kind == "call_expression" {
                let callee = node
                    .child_by_field_name("function")
                    .and_then(|n| n.utf8_text(source.as_bytes()).ok())
                    .unwrap_or("");
                let base_name = callee.rsplit("::").next().unwrap_or(callee);

                // GR002: Blocking recv/read/connect without socket timeouts / select / poll
                if matches!(base_name, "recv" | "recvfrom" | "connect") && !ctx.has_c_socket_timeout_in_file {
                    push_finding(
                        findings, source, lang, "GR002-MISSING-TIMEOUT-CPP", "gardawg-ast",
                        Severity::Error, "high", file_label, line, col, snippet.clone(),
                        format!("Blocking `{base_name}()` call without `SO_RCVTIMEO`/`SO_SNDTIMEO` or `select`/`poll` timeout."),
                        None,
                        Some("Configure socket timeout before I/O:\n```c\nstruct timeval tv = { .tv_sec = 5, .tv_usec = 0 };\nsetsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));\n```".into()),
                        None,
                    );
                }

                // GR004: Ignored return codes on critical I/O/system calls without (void) cast
                if matches!(
                    base_name,
                    "write" | "fwrite" | "fflush" | "fsync" | "sendto" | "pthread_mutex_lock"
                ) {
                    let is_bare_stmt = node
                        .parent()
                        .map(|p| p.kind() == "expression_statement")
                        .unwrap_or(false);
                    if is_bare_stmt {
                        push_finding(
                            findings, source, lang, "GR004-IGNORED-RETURN-CPP", "gardawg-ast",
                            Severity::Warning, "high", file_label, line, col, snippet.clone(),
                            format!("Return value of `{base_name}()` is silently ignored."),
                            None,
                            Some("Check the return code or cast `(void)` if intentionally ignored:\n```c\nif (fsync(fd) < 0) { perror(\"fsync\"); }\n```".into()),
                            None,
                        );
                    }
                }

                // GR006: Unsafe unbounded buffer/command calls
                if matches!(base_name, "strcpy" | "strcat" | "sprintf" | "gets" | "system" | "popen") {
                    push_finding(
                        findings, source, lang, "GR006-UNSAFE-C-CALL", "gardawg-ast",
                        Severity::Error, "critical", file_label, line, col, snippet.clone(),
                        format!("Unsafe unbounded C call `{base_name}()` risks buffer overflow or command injection."),
                        None,
                        Some("Use bounded equivalents (`snprintf`, `strncpy` with null-termination, or `execvp`) instead.".into()),
                        None,
                    );
                }

                // GR007: assert() in non-test paths or unchecked malloc/calloc/realloc
                if base_name == "assert" && !is_test_or_example_path(file_label) {
                    push_finding(
                        findings, source, lang, "GR007-ASSERT-IN-PROD-CPP", "gardawg-ast",
                        Severity::Warning, "medium", file_label, line, col, snippet.clone(),
                        "`assert()` in non-test C/C++ code aborts the process in debug builds and vanishes under `-DNDEBUG`.".into(),
                        None,
                        Some("Return an explicit error code instead of `assert()`.".into()),
                        None,
                    );
                }
                if matches!(base_name, "malloc" | "calloc" | "realloc") {
                    let window_end = (node.end_byte() + 200).min(source.len());
                    let after = &source[node.end_byte()..window_end];
                    if !after.contains("NULL") && !after.contains("nullptr") && !after.contains("if (!") && !after.contains("if(!") {
                        push_finding(
                            findings, source, lang, "GR007-UNCHECKED-ALLOC-CPP", "gardawg-ast",
                            Severity::Warning, "high", file_label, line, col, snippet,
                            format!("Allocation `{base_name}()` has no visible NULL check."),
                            None,
                            Some("Check allocation result before use:\n```c\nvoid *p = malloc(n);\nif (!p) { return -ENOMEM; }\n```".into()),
                            None,
                        );
                    }
                }
            }
        }
    }
}

fn is_rust_let_underscore_exempt(val: &str) -> bool {
    let lower = val.to_ascii_lowercase();
    // Non-blocking channel teardown / send (mpsc, oneshot, crossbeam, etc.)
    if (lower.contains(".send(") || lower.contains(".try_send("))
        && (lower.contains("tx") || lower.contains("sender") || lower.contains("chan") || lower.contains("notify") || lower.contains("metrics"))
    {
        return true;
    }
    if lower.contains("mpsc") || lower.contains("oneshot") || lower.contains("tx.") || lower.contains("sender.") {
        return true;
    }
    // Best-effort temp file / cleanup
    if lower.contains("remove_file") || lower.contains("remove_dir") || lower.contains("fs::remove") {
        return true;
    }
    // Graceful shutdown / close / timeout close / join / abort
    if lower.contains("shutdown") || lower.contains("close(") || lower.contains("abort(") || lower.contains("kill(") {
        return true;
    }
    if lower.contains("timeout(") && (lower.contains("close") || lower.contains("shutdown")) {
        return true;
    }
    false
}

fn is_rust_critical_io_expr(val: &str) -> bool {
    let lower = val.to_ascii_lowercase();
    lower.contains("write")
        || lower.contains("flush")
        || lower.contains("sync")
        || lower.contains("fs::")
        || lower.contains("file")
        || lower.contains("socket")
        || lower.contains("stream")
        || lower.contains("send")
        || lower.contains("recv")
        || lower.contains("connect")
        || lower.contains("bind")
        || lower.contains("persist")
        || lower.contains("save")
        || lower.contains("commit")
        || lower.contains("db")
        || lower.contains("sql")
        || lower.contains("http")
}

fn missing_idempotency_nearby(src: &str, offset: usize) -> bool {
    let start = offset.saturating_sub(300);
    let end = (offset + 400).min(src.len());
    let window = &src[start..end].to_ascii_lowercase();
    !(window.contains("idempotency") || window.contains("idempotent"))
}

fn is_non_network_sink_call(callee: &str, text: &str, ctx: &WalkContext) -> bool {
    let lower = callee.to_ascii_lowercase();
    // Explicit in-memory channel or local disk writer keywords
    if lower.contains("mpsc")
        || lower.contains("oneshot")
        || lower.contains("channel")
        || lower.contains("bufwriter")
        || lower.contains("stderr")
        || lower.contains("stdout")
        || lower.contains("file")
        || lower.contains("logger")
        || lower.contains("log.")
        || text.contains("BufWriter")
        || text.contains("mpsc::")
    {
        return true;
    }
    if let Some(recv) = callee.split('.').next() {
        let recv_trimmed = recv.trim();
        if ctx.local_sink_vars.contains(recv_trimmed) {
            return true;
        }
        let rlow = recv_trimmed.to_ascii_lowercase();
        if rlow == "f" || rlow == "fp" || rlow == "file" || rlow == "out_file" || rlow == "log_file" || rlow == "buf" {
            return true;
        }
    }
    false
}

#[allow(clippy::too_many_arguments)]
fn inspect_link_call(
    node: Node,
    source: &str,
    text: &str,
    lang: Lang,
    file_label: &str,
    profile: &LinkProfile,
    assumed_hz: f64,
    ctx: &WalkContext,
    findings: &mut Vec<Finding>,
) {
    let pos = node.start_position();
    let line = pos.row + 1;
    let col = pos.column + 1;
    let snippet = text.lines().next().unwrap_or(text).trim().to_string();

    let callee = node
        .child_by_field_name("function")
        .and_then(|n| n.utf8_text(source.as_bytes()).ok())
        .unwrap_or("");

    let effective_hz = ctx.loop_hz_inferred.unwrap_or(assumed_hz);
    let hz_source = if let Some(h) = ctx.loop_hz_inferred {
        format!("{:.2} Hz (inferred from loop period)", (h * 100.0).round() / 100.0)
    } else {
        format!("{assumed_hz} Hz")
    };
    let safe_bytes = profile.recommended_app_payload_bytes();

    // Rule 1: JSON / text serialization inside a loop
    let is_json_ser = match lang {
        Lang::Python | Lang::Rust => {
            callee.ends_with("json.dumps")
                || callee.ends_with("serde_json::to_string")
                || callee.ends_with("serde_json::to_vec")
        }
        Lang::Cpp => {
            callee == "serializeJson"
                || callee == "serializeJsonPretty"
                || callee == "snprintf"
                || callee == "sprintf"
                || callee == "vsnprintf"
                || callee.ends_with("::to_string")
                || callee.ends_with("::format")
        }
        Lang::TypeScript | Lang::JavaScript => callee == "JSON.stringify",
    };

    if is_json_ser && ctx.in_loop {
        let estimated_json_bytes = 96;
        let budget = evaluate_payload(profile, estimated_json_bytes, effective_hz);
        let sev = if budget.exceeds_effective_capacity { Severity::Error } else { Severity::Warning };
        let tier = if budget.exceeds_effective_capacity { "critical" } else { "high" };

        let fix = match lang {
            Lang::Python => format!(
                "Pack binary frames (<= {safe_bytes} B for {}) with `struct.pack` + sequence/CRC:\n```python\nframe = struct.pack('<BHH', seq & 0xFF, temp_x10, volt_mv)\nframe += struct.pack('<H', zlib.crc32(frame) & 0xFFFF)\n```",
                profile.id
            ),
            Lang::Rust => format!(
                "Serialize compact binary (<= {safe_bytes} B for {}) into a reusable buffer:\n```rust\nlet mut buf = [0u8; {safe_bytes}];\nlet n = postcard::to_slice(&sample, &mut buf)?.len();\n```",
                profile.id
            ),
            Lang::Cpp => format!(
                "Use a packed binary struct (<= {safe_bytes} B for {}) with CRC instead of text formatting:\n```c\nstruct __attribute__((packed)) Frame {{ uint8_t seq; int16_t temp_x10; uint16_t crc; }};\n```",
                profile.id
            ),
            Lang::TypeScript | Lang::JavaScript => format!(
                "Pack into a binary `DataView` (<= {safe_bytes} B for {}) instead of `JSON.stringify()`:\n```js\nconst buf = new ArrayBuffer(8); const dv = new DataView(buf);\ndv.setUint8(0, seq); dv.setInt16(1, tempX10, true); dv.setUint16(3, crc16, true);\n```",
                profile.id
            ),
        };

        push_finding(
            findings, source, lang, "JSON_IN_LOOP", "linkguard-ast",
            sev, tier, file_label, line, col, Some(snippet.clone()),
            format!(
                "Text/JSON serialization inside a loop at {hz_source}. Needs ~{:.0} bps ({:.1}% of {}'s {:.0} bps goodput; max app payload <= {safe_bytes} B).",
                budget.required_wire_bps, budget.utilization_pct, profile.id, profile.effective_goodput_bps
            ),
            Some(format!(
                "Information Theory & Framing Tax (Shannon: {:.0} bps, Goodput: {:.0} bps, MTU: {} B)",
                budget.shannon_ceiling_bps, budget.effective_goodput_bps, profile.max_payload_bytes
            )),
            Some(fix),
            Some(budget),
        );
    }

    // Rule 2: Unframed binary packing on lossy RF profiles (UNFRAMED_LOSSY_PAYLOAD)
    let is_binary_pack = match lang {
        Lang::Python => callee.ends_with("struct.pack") || callee.ends_with("struct.pack_into"),
        Lang::Rust => callee.ends_with("bincode::serialize") || callee.ends_with("postcard::to_vec"),
        Lang::TypeScript | Lang::JavaScript => text.contains("DataView") || callee.ends_with("Buffer.alloc"),
        Lang::Cpp => false,
    };

    if is_binary_pack && profile.is_lossy_rf() && !ctx.has_framing_in_file {
        push_finding(
            findings, source, lang, "UNFRAMED_LOSSY_PAYLOAD", "linkguard-ast",
            Severity::Warning, "high", file_label, line, col, Some(snippet.clone()),
            format!(
                "Raw binary payload packed for lossy RF profile '{}' without sequence counter, length prefix, CRC/hash, or FEC.",
                profile.id
            ),
            Some("Lossy RF Channel Integrity: silent bit flips & dropped frames corrupt unframed structs.".into()),
            Some(format!(
                "Add a 1B sequence counter + 2B CRC16 (keep total <= {safe_bytes} B for {}):\n```python\npkt = struct.pack('<Bhh', seq & 0xFF, temp_x10, volt_mv)\npkt += struct.pack('<H', zlib.crc32(pkt) & 0xFFFF)\n```",
                profile.id
            )),
            None,
        );
    }

    // Rule 3: Transport send/write inside a loop (excluding local disk writers & in-memory channels)
    let is_send = match lang {
        Lang::Python | Lang::Rust => {
            callee.ends_with(".send")
                || callee.ends_with(".sendall")
                || callee.ends_with(".sendto")
                || callee.ends_with(".write")
                || callee.ends_with(".write_all")
                || callee.ends_with(".send_to")
        }
        Lang::Cpp => {
            callee == "send"
                || callee == "sendto"
                || callee.ends_with("::send")
                || callee.ends_with("::sendto")
                || callee.ends_with(".send")
                || callee.ends_with(".write")
                || callee.ends_with(".print")
                || callee.ends_with(".println")
        }
        Lang::TypeScript | Lang::JavaScript => {
            callee.ends_with(".send")
                || callee.ends_with(".write")
                || callee == "fetch"
                || callee.ends_with(".fetch")
        }
    };

    if is_send && ctx.in_loop && !is_non_network_sink_call(callee, text, ctx) {
        let mut emitted_mtu = false;
        if let Some(lit_len) = extract_string_literal_len(text) {
            if lit_len > profile.max_payload_bytes {
                emitted_mtu = true;
                let budget = evaluate_payload(profile, lit_len, effective_hz);
                push_finding(
                    findings, source, lang, "MTU_EXCEEDED_LITERAL", "linkguard-ast",
                    Severity::Error, "high", file_label, line, col, Some(snippet.clone()),
                    format!(
                        "Literal payload ({} B) exceeds {} MTU ({} B), splitting into {} fragments (loss={:.2}%).",
                        lit_len, profile.id, profile.max_payload_bytes, budget.fragments_per_message, budget.packet_loss_prob_pct
                    ),
                    Some("Fragmentation & BER Amplification: P(loss) = 1 - (1 - BER)^(wire_bits)".into()),
                    Some(format!("Shrink or pack binary payload to <= {safe_bytes} B for {} single-MTU delivery.", profile.id)),
                    Some(budget),
                );
            }
        }
        if !emitted_mtu && !ctx.in_batch_guard {
            let budget = evaluate_payload(profile, 16, effective_hz);
            let sev = if budget.exceeds_effective_capacity { Severity::Error } else { Severity::Warning };
            let tier = if budget.exceeds_effective_capacity { "high" } else { "medium" };
            push_finding(
                findings, source, lang, "UNBATCHED_SEND_IN_LOOP", "linkguard-ast",
                sev, tier, file_label, line, col, Some(snippet.clone()),
                format!(
                    "Unbatched network send `{callee}()` inside a loop at {hz_source} (header tax {:.1}% on {}, max single-MTU <= {safe_bytes} B).",
                    budget.header_overhead_pct, profile.id
                ),
                Some("Framing Efficiency = payload / (payload + header_overhead)".into()),
                Some(format!(
                    "Batch readings up to <= {safe_bytes} B before transmitting:\n```python\nbuf.append(sample)\nif len(buf) >= 4:\n    sock.sendto(b\"\".join(buf), addr); buf.clear()\n```"
                )),
                Some(budget),
            );
        }
    }

    // Rule 4: Blocking I/O in async / RTOS task
    let is_blocking_call = match lang {
        Lang::Python | Lang::Rust => {
            callee.ends_with("time.sleep")
                || callee.ends_with("thread::sleep")
                || callee.ends_with("requests.get")
                || callee.ends_with("requests.post")
        }
        Lang::Cpp => {
            callee == "delay"
                || callee == "HAL_Delay"
                || callee == "sleep"
                || callee == "usleep"
                || callee.ends_with("sleep_for")
                || callee.ends_with("sleep_until")
        }
        Lang::TypeScript | Lang::JavaScript => callee.ends_with("Sync") && callee.contains('.'),
    };

    if is_blocking_call && ctx.in_async {
        push_finding(
            findings, source, lang, "BLOCKING_IO_IN_ASYNC", "linkguard-ast",
            Severity::Error, "high", file_label, line, col, Some(snippet.clone()),
            "Blocking sleep or synchronous I/O inside an async/RTOS task stalls sibling handlers.".into(),
            Some("Queueing Delay & Executor Starvation".into()),
            Some(match lang {
                Lang::Python => "Replace with `await asyncio.sleep(...)` or an async HTTP client (`httpx.AsyncClient`).".into(),
                Lang::Rust => "Replace with `tokio::time::sleep(...).await` or `tokio::task::spawn_blocking`.".into(),
                Lang::Cpp => "Replace blocking delay with `vTaskDelay(pdMS_TO_TICKS(...))` or `co_await`.".into(),
                Lang::TypeScript | Lang::JavaScript => "Replace `*Sync` calls with `await fs.promises.*`.".into(),
            }),
            None,
        );
    }

    // Rule 5: Timeout shorter than physical link latency
    let timeout_ms = if callee.ends_with(".settimeout") {
        extract_single_float_in_parens(text).map(|s| s * 1000.0)
    } else if callee.ends_with(".set_read_timeout") || callee.ends_with(".set_write_timeout") {
        extract_rust_duration_secs(text).map(|s| s * 1000.0)
    } else if lang == Lang::Cpp && callee.ends_with(".setTimeout") {
        extract_single_float_in_parens(text)
    } else {
        None
    };

    if let Some(t_ms) = timeout_ms {
        if t_ms > 0.0 && t_ms < profile.base_latency_ms {
            push_finding(
                findings, source, lang, "TIMEOUT_BELOW_LINK_LATENCY", "linkguard-ast",
                Severity::Error, "high", file_label, line, col, Some(snippet.clone()),
                format!(
                    "Socket timeout ({t_ms:.1} ms) is shorter than '{}' base latency ({:.0} ms).",
                    profile.id, profile.base_latency_ms
                ),
                Some("Timeout Floor > Physical Base RTT + Serialization Airtime".into()),
                Some(format!(
                    "Set timeout >= {:.1} s for {} (3x base latency).",
                    (profile.base_latency_ms * 3.0) / 1000.0,
                    profile.id
                )),
                None,
            );
        }
    }

    // Rule 6: JS/TS fetch() without AbortSignal on high-latency link
    if matches!(lang, Lang::TypeScript | Lang::JavaScript)
        && (callee == "fetch" || callee.ends_with(".fetch"))
        && !text.contains("signal")
        && !ctx.has_timeout_in_file
    {
        push_finding(
            findings, source, lang, "MISSING_ABORT_TIMEOUT", "linkguard-ast",
            if profile.base_latency_ms >= 20.0 { Severity::Error } else { Severity::Warning },
            "high", file_label, line, col, Some(snippet.clone()),
            format!("`fetch()` without `AbortSignal.timeout` on '{}' ({:.0} ms latency).", profile.id, profile.base_latency_ms),
            Some("Head-of-Line Blocking & Unbounded Stall on Lossy RF Channels".into()),
            Some(format!("Pass `signal: AbortSignal.timeout({:.0})`.", (profile.base_latency_ms * 4.0).max(2000.0))),
            None,
        );
    }

    // Rule 7: Socket creation without timeout on lossy/high-latency link
    let is_socket_init = callee.ends_with("socket.socket")
        || callee.ends_with("TcpStream::connect")
        || callee.ends_with("UdpSocket::bind")
        || (lang == Lang::Cpp && (callee == "socket" || callee.ends_with("::socket")));

    if is_socket_init && !ctx.has_timeout_in_file && profile.base_latency_ms >= 20.0 {
        push_finding(
            findings, source, lang, "NO_TIMEOUT_ON_LOSSY_LINK", "linkguard-ast",
            Severity::Warning, "medium", file_label, line, col, Some(snippet),
            format!("Socket initialized without timeout on lossy/high-latency profile '{}'.", profile.id),
            Some("Head-of-Line Blocking & Unbounded Stall on Lossy RF Channels".into()),
            Some("Configure explicit read/write timeouts (e.g. `.settimeout(2.0)` / `SO_RCVTIMEO`).".into()),
            None,
        );
    }
}

fn extract_string_literal_len(call_text: &str) -> Option<usize> {
    let start = call_text.find('"')?;
    let rest = &call_text[start + 1..];
    let end = rest.find('"')?;
    Some(end)
}

fn has_token_with_prefix(line: &str, prefix: &str, min_tail_len: usize, upper_only: bool) -> bool {
    let mut search_from = 0;
    while let Some(idx) = line[search_from..].find(prefix) {
        let start = search_from + idx + prefix.len();
        let tail_len = line[start..]
            .chars()
            .take_while(|c| {
                if upper_only {
                    c.is_ascii_uppercase() || c.is_ascii_digit()
                } else {
                    c.is_ascii_alphanumeric() || *c == '_' || *c == '-'
                }
            })
            .count();
        if tail_len >= min_tail_len {
            return true;
        }
        search_from = start;
    }
    false
}

fn contains_hardcoded_secret(line: &str) -> bool {
    has_token_with_prefix(line, "sk_live_", 12, false)
        || has_token_with_prefix(line, "rk_live_", 12, false)
        || has_token_with_prefix(line, "ghp_", 20, false)
        || has_token_with_prefix(line, "github_pat_", 20, false)
        || has_token_with_prefix(line, "xoxb-", 12, false)
        || has_token_with_prefix(line, "AKIA", 16, true)
        || line.contains("-----BEGIN PRIVATE KEY-----")
        || line.contains("-----BEGIN RSA PRIVATE KEY-----")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::physics::get_profile;

    #[test]
    fn valid_rust_raw_identifier_borrow_emits_no_syntax_error() {
        let src = r#"
pub fn f(raw: &[u8]) -> &[u8] { &raw[0..4] }

pub fn parse_frame(raw: &[u8]) -> Option<usize> {
    if raw.len() < 40 || &raw[0..4] != b"MAGI" {
        return None;
    }
    let cid_bytes = &raw[8..40];
    let _val: usize = serde_json::from_slice(&raw).ok()?;
    Some(cid_bytes.len())
}
"#;
        let findings = analyze_source(src, Lang::Rust, "src/frame.rs", None, 1.0, false).unwrap();
        assert!(
            !findings.iter().any(|f| f.rule_id.starts_with("GR000-SYNTAX-ERROR")),
            "Unexpected syntax error on valid Rust `&raw`: {findings:?}"
        );
    }

    #[test]
    fn recurses_into_try_except_inside_loop_for_unbatched_send() {
        let src = r#"
import socket, time
sock = socket.socket()
sock.settimeout(2.0)
while True:
    try:
        sock.sendto(b"abc", ("127.0.0.1", 9000))
    except OSError as exc:
        print(exc)
    time.sleep(0.1)
"#;
        let lora = get_profile("lora-sf12").unwrap();
        let findings = analyze_source(src, Lang::Python, "bad_test.py", Some(&lora), 1.0, false).unwrap();
        assert!(
            findings.iter().any(|f| f.rule_id == "UNBATCHED_SEND_IN_LOOP"),
            "Expected UNBATCHED_SEND_IN_LOOP inside try/except, got: {findings:?}"
        );
    }

    #[test]
    fn filters_mpsc_and_bufwriter_from_unbatched_send_and_gr004_exempts() {
        let src = r#"
use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::mpsc;

pub fn pump(tx: mpsc::Sender<Vec<u8>>, path: &str) -> std::io::Result<()> {
    let f = File::create(path)?;
    let mut writer = BufWriter::new(f);
    for i in 0..10 {
        let _ = tx.send(vec![i as u8]);
        writer.write_all(&[i as u8])?;
    }
    let _ = std::fs::remove_file("/tmp/old.tmp");
    Ok(())
}
"#;
        let lora = get_profile("lora-sf12").unwrap();
        let findings = analyze_source(src, Lang::Rust, "src/fabric.rs", Some(&lora), 10.0, false).unwrap();
        assert!(
            !findings.iter().any(|f| f.rule_id == "UNBATCHED_SEND_IN_LOOP"),
            "False positive UNBATCHED_SEND_IN_LOOP on mpsc/BufWriter: {findings:?}"
        );
        assert!(
            !findings.iter().any(|f| f.rule_id == "GR004-SWALLOWED-ERR-RUST"),
            "False positive GR004 on mpsc/remove_file: {findings:?}"
        );
    }

    #[test]
    fn flags_unframed_lossy_payload_and_clears_with_crc_seq() {
        let bad = r#"
import struct
pkt = struct.pack("<ff", 23.4, 3.3)
"#;
        let lora = get_profile("lora-sf12").unwrap();
        let f_bad = analyze_source(bad, Lang::Python, "tx.py", Some(&lora), 1.0, false).unwrap();
        assert!(f_bad.iter().any(|f| f.rule_id == "UNFRAMED_LOSSY_PAYLOAD"));

        let good = r#"
import struct, zlib
seq = 1
body = struct.pack("<Bff", seq, 23.4, 3.3)
crc = zlib.crc32(body) & 0xFFFF
pkt = body + struct.pack("<H", crc)
"#;
        let f_good = analyze_source(good, Lang::Python, "tx_ok.py", Some(&lora), 1.0, false).unwrap();
        assert!(!f_good.iter().any(|f| f.rule_id == "UNFRAMED_LOSSY_PAYLOAD"));
    }

    #[test]
    fn flags_python_socket_httpserver_timeout_and_non_atomic_write() {
        let src = r#"
import json, socket
from http.server import HTTPServer
s = socket.socket()
srv = HTTPServer(("127.0.0.1", 8080), object)
with open("state.json", "w") as f:
    json.dump({"ok": True}, f)
"#;
        let findings = analyze_source(src, Lang::Python, "srv.py", None, 1.0, false).unwrap();
        assert!(findings.iter().any(|f| f.rule_id == "GR002-MISSING-TIMEOUT-PY-SOCKET"));
        assert!(findings.iter().any(|f| f.rule_id == "GR002-MISSING-TIMEOUT-PY-HTTPSERVER"));
        assert!(findings.iter().any(|f| f.rule_id == "GR004-NON-ATOMIC-WRITE-PY"));
    }

    #[test]
    fn cpp_and_js_gardawg_parity() {
        let c_src = r#"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
void bad(int sock, int fd, const char *in) {
    char buf[16];
    strcpy(buf, in);
    recv(sock, buf, sizeof(buf), 0);
    write(fd, buf, 4);
    char *p = (char *)malloc(64);
    p[0] = 'x';
}
"#;
        let c_findings = analyze_source(c_src, Lang::Cpp, "bad.c", None, 1.0, false).unwrap();
        assert!(c_findings.iter().any(|f| f.rule_id == "GR006-UNSAFE-C-CALL"));
        assert!(c_findings.iter().any(|f| f.rule_id == "GR002-MISSING-TIMEOUT-CPP"));
        assert!(c_findings.iter().any(|f| f.rule_id == "GR004-IGNORED-RETURN-CPP"));
        assert!(c_findings.iter().any(|f| f.rule_id == "GR007-UNCHECKED-ALLOC-CPP"));

        let js_src = r#"
async function go(u, x) {
    try {
        await fetch(u);
    } catch (e) {}
    return eval(x);
}
"#;
        let js_findings = analyze_source(js_src, Lang::JavaScript, "app.mjs", None, 1.0, false).unwrap();
        assert!(js_findings.iter().any(|f| f.rule_id == "GR002-MISSING-TIMEOUT-JS"));
        assert!(js_findings.iter().any(|f| f.rule_id == "GR004-SWALLOWED-ERR-JS"));
        assert!(js_findings.iter().any(|f| f.rule_id == "GR006-UNSAFE-EVAL-JS"));
    }

    #[test]
    fn inline_ignore_and_scoped_rule_ignore_work() {
        let src = r#"
fn a() -> usize { "1".parse::<usize>().unwrap() } // gardawg-ignore(GR007-PANIC-UNWRAP-RUST)
fn b() -> usize { "2".parse::<usize>().unwrap() }
"#;
        let findings = analyze_source(src, Lang::Rust, "src/lib.rs", None, 1.0, false).unwrap();
        let lines: Vec<usize> = findings.iter().map(|f| f.start_line).collect();
        assert_eq!(lines, vec![3]);
    }
}

