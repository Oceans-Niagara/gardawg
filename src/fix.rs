use crate::analyzer::{analyze_source, scan_workspace, Lang, ScanOptions};
use crate::config::GardawgConfig;
use crate::physics::LinkProfile;
use crate::sarif::Finding;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::net::TcpStream;

pub struct FixOptions<'a> {
    pub model: &'a str,
    pub ollama_url: &'a str,
    pub target_file: Option<&'a Path>,
    pub link_profile: Option<&'a LinkProfile>,
    pub assumed_hz: f64,
    pub max_files: usize,
    pub dry_run: bool,
}

fn strip_ollama_prefix(model: &str) -> anyhow::Result<&str> {
    let trimmed = model.trim();
    if let Some(rest) = trimmed.strip_prefix("ollama/") {
        if rest.is_empty() {
            anyhow::bail!("--model ollama/<tag> requires a model tag (e.g. ollama/qwen2.5-coder:3b)");
        }
        return Ok(rest);
    }
    if trimmed.contains('/') {
        anyhow::bail!(
            "Unsupported model provider '{trimmed}'. `gardawg fix` runs offline against local Ollama (`--model ollama/<tag>`); for other providers use `gardawg mcp` inside your host CLI."
        );
    }
    if trimmed.is_empty() {
        anyhow::bail!("--model cannot be empty (example: --model ollama/qwen2.5-coder:3b)");
    }
    Ok(trimmed)
}

fn lang_from_path(path: &Path) -> Option<Lang> {
    match path.extension().and_then(|e| e.to_str())?.to_ascii_lowercase().as_str() {
        "py" => Some(Lang::Python),
        "rs" => Some(Lang::Rust),
        "ts" | "tsx" => Some(Lang::TypeScript),
        "js" | "jsx" | "mjs" | "cjs" => Some(Lang::JavaScript),
        "c" | "cc" | "cpp" | "cxx" | "h" | "hpp" | "ino" => Some(Lang::Cpp),
        _ => None,
    }
}

fn extract_code_block(reply: &str) -> String {
    let trimmed = reply.trim();
    if let Some(start_fence) = trimmed.find("```") {
        let after = &trimmed[start_fence + 3..];
        let body_start = after.find('\n').map(|i| i + 1).unwrap_or(0);
        let body = &after[body_start..];
        if let Some(end_fence) = body.rfind("```") {
            return format!("{}\n", body[..end_fence].trim_end());
        }
    }
    format!("{trimmed}\n")
}

async fn call_ollama_chat(ollama_url: &str, model_tag: &str, prompt: &str) -> anyhow::Result<String> {
    let clean = ollama_url
        .trim()
        .trim_end_matches('/')
        .strip_prefix("http://")
        .ok_or_else(|| anyhow::anyhow!("--ollama-url must start with http:// (got '{ollama_url}')"))?;
    let (host_port, base_path) = match clean.find('/') {
        Some(idx) => (&clean[..idx], &clean[idx..]),
        None => (clean, ""),
    };
    let endpoint = format!("{base_path}/api/chat");

    let payload = serde_json::to_vec(&json!({
        "model": model_tag,
        "stream": false,
        "options": { "temperature": 0.1 },
        "messages": [
            {
                "role": "system",
                "content": "You are a precise code repair assistant. Return ONLY the complete updated source file inside one fenced code block. Fix the reported findings minimally without changing unrelated behavior."
            },
            {
                "role": "user",
                "content": prompt
            }
        ]
    }))?;

    let stream = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(host_port))
        .await
        .map_err(|_| anyhow::anyhow!("Timed out connecting to Ollama at {host_port}"))?
        .map_err(|e| anyhow::anyhow!("Failed to connect to Ollama at {host_port} (is `ollama serve` running?): {e}"))?;

    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .method("POST")
        .uri(endpoint)
        .header("Host", host_port)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(payload)))?;

    let resp = tokio::time::timeout(Duration::from_secs(180), sender.send_request(req))
        .await
        .map_err(|_| anyhow::anyhow!("Timed out waiting for Ollama response from model '{model_tag}'"))??;

    let status = resp.status();
    let body_bytes = resp.into_body().collect().await?.to_bytes();
    if !status.is_success() {
        let text = String::from_utf8_lossy(&body_bytes);
        anyhow::bail!("Ollama returned HTTP {status}: {text}");
    }

    let parsed: Value = serde_json::from_slice(&body_bytes)?;
    let content = parsed["message"]["content"]
        .as_str()
        .or_else(|| parsed["response"].as_str())
        .ok_or_else(|| anyhow::anyhow!("Unexpected Ollama JSON response (missing message.content)"))?;
    Ok(content.to_string())
}

pub async fn run_fix(
    workspace: &Path,
    cfg: &GardawgConfig,
    opts: FixOptions<'_>,
) -> anyhow::Result<bool> {
    let tag = strip_ollama_prefix(opts.model)?;

    let mut by_file: BTreeMap<String, Vec<Finding>> = BTreeMap::new();
    if let Some(rel) = opts.target_file {
        let abs = if rel.is_absolute() { rel.to_path_buf() } else { workspace.join(rel) };
        let lang = lang_from_path(&abs)
            .ok_or_else(|| anyhow::anyhow!("Unsupported file extension for {}", abs.display()))?;
        let src = fs::read_to_string(&abs)?;
        let label = abs
            .strip_prefix(workspace)
            .unwrap_or(&abs)
            .to_string_lossy()
            .replace('\\', "/");
        let mut findings = analyze_source(&src, lang, &label, opts.link_profile, opts.assumed_hz, false)?;
        findings.retain(|f| cfg.is_rule_enabled(&f.rule_id));
        if !findings.is_empty() {
            by_file.insert(label, findings);
        }
    } else {
        let scan = scan_workspace(
            workspace,
            &ScanOptions {
                exclude: &cfg.ast.exclude,
                link_profile: opts.link_profile,
                assumed_hz: opts.assumed_hz,
                pedantic: false,
            },
        )?;
        for f in scan.findings {
            if cfg.is_rule_enabled(&f.rule_id) {
                by_file.entry(f.file.clone()).or_default().push(f);
            }
        }
    }

    if by_file.is_empty() {
        println!("gardawg fix: no AST findings to repair.");
        return Ok(true);
    }

    let mut all_clean = true;
    for (rel_file, findings) in by_file.into_iter().take(opts.max_files.max(1)) {
        let abs_path: PathBuf = workspace.join(&rel_file);
        let Some(lang) = lang_from_path(&abs_path) else { continue };
        let orig_src = fs::read_to_string(&abs_path)?;
        let before_count = findings.len();

        let findings_json = serde_json::to_string_pretty(&findings)?;
        let prompt = format!(
            "File: {rel_file}\n\nFindings & Remedies (JSON):\n{findings_json}\n\nCurrent Source:\n```\n{orig_src}\n```\n\nOutput ONLY the complete corrected file in one fenced code block."
        );

        eprintln!("gardawg fix: repairing {rel_file} ({before_count} finding(s)) via ollama/{tag}...");
        let reply = call_ollama_chat(opts.ollama_url, tag, &prompt).await?;
        let candidate = extract_code_block(&reply);

        let mut after_findings = analyze_source(
            &candidate,
            lang,
            &rel_file,
            opts.link_profile,
            opts.assumed_hz,
            false,
        )?;
        after_findings.retain(|f| cfg.is_rule_enabled(&f.rule_id));

        let has_syntax_err = after_findings.iter().any(|f| f.rule_id.starts_with("GR000"));
        let after_count = after_findings.len();
        if has_syntax_err {
            eprintln!("  [skipped] model output introduced GR000 syntax error(s); keeping original {rel_file}.");
            all_clean = false;
            continue;
        }
        if after_count >= before_count {
            eprintln!("  [skipped] findings did not decrease ({before_count} -> {after_count}); keeping original {rel_file}.");
            all_clean = false;
            continue;
        }

        if opts.dry_run {
            println!("[dry-run] {rel_file}: {before_count} -> {after_count} finding(s)");
        } else {
            fs::write(&abs_path, candidate)?;
            println!("[fixed] {rel_file}: {before_count} -> {after_count} finding(s)");
        }
        if after_count > 0 {
            all_clean = false;
        }
    }

    Ok(all_clean)
}