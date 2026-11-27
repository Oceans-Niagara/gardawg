use crate::config::GateConfig;
use crate::sarif::{Finding, Severity};
use std::path::Path;
use tokio::process::Command;

const PEDANTIC_CLIPPY_CODES: &[&str] = &[
    "clippy::io_other_error",
    "clippy::needless_return",
    "clippy::redundant_closure",
    "clippy::module_name_repetitions",
    "clippy::too_many_arguments",
    "clippy::uninlined_format_args",
    "clippy::len_zero",
    "clippy::single_match",
    "clippy::manual_map",
    "clippy::collapsible_if",
    "clippy::new_without_default",
];

fn is_pedantic_clippy_code(code: &str) -> bool {
    PEDANTIC_CLIPPY_CODES.iter().any(|c| code.eq_ignore_ascii_case(c))
}

pub async fn run_unified_gate(
    root: &Path,
    gate_cfg: &GateConfig,
    pedantic: bool,
) -> anyhow::Result<Vec<Finding>> {
    let mut all = Vec::new();

    if gate_cfg.rust && root.join("Cargo.toml").exists() {
        all.extend(run_clippy(root, pedantic).await?);
    }
    if gate_cfg.typescript && root.join("package.json").exists() && root.join("tsconfig.json").exists() {
        all.extend(run_tsc(root).await?);
    }
    if gate_cfg.python && (root.join("pyproject.toml").exists() || root.join("requirements.txt").exists()) {
        all.extend(run_ruff(root, pedantic).await?);
        all.extend(run_mypy(root).await?);
    }

    Ok(all)
}

async fn run_clippy(root: &Path, pedantic: bool) -> anyhow::Result<Vec<Finding>> {
    let Ok(out) = Command::new("cargo")
        .args(["clippy", "--all-targets", "--message-format=json"])
        .current_dir(root)
        .output()
        .await
    else {
        return Ok(vec![]);
    };

    let mut findings = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
        if v["reason"] != "compiler-message" {
            continue;
        }
        let msg = &v["message"];
        let Some(span) = msg["spans"].as_array().and_then(|s| s.first()) else { continue };
        let level = msg["level"].as_str().unwrap_or("warning");
        if level == "help" {
            continue;
        }

        let code = msg["code"]["code"].as_str().unwrap_or("clippy").to_string();
        let is_style_lint = level == "note" || is_pedantic_clippy_code(&code);
        if is_style_lint && !pedantic {
            continue;
        }

        let severity = match level {
            "error" => Severity::Error,
            "note" => Severity::Note,
            _ => Severity::Warning,
        };

        findings.push(Finding {
            rule_id: code,
            tool: "clippy".to_string(),
            severity,
            tier: Some(if is_style_lint { "pedantic" } else if level == "error" { "critical" } else { "high" }.to_string()),
            message: msg["message"].as_str().unwrap_or("").to_string(),
            file: span["file_name"].as_str().unwrap_or("").replace('\\', "/"),
            start_line: span["line_start"].as_u64().unwrap_or(1) as usize,
            start_col: span["column_start"].as_u64().unwrap_or(1) as usize,
            snippet: None,
            physics_law: None,
            remediation: None,
            suppression_hint: None,
            budget: None,
        });
    }
    Ok(findings)
}

async fn run_tsc(root: &Path) -> anyhow::Result<Vec<Finding>> {
    let npx = if cfg!(windows) { "npx.cmd" } else { "npx" };
    let Ok(out) = Command::new(npx)
        .args(["--no-install", "tsc", "--noEmit", "--pretty", "false"])
        .current_dir(root)
        .output()
        .await
    else {
        return Ok(vec![]);
    };

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let mut findings = Vec::new();
    for line in combined.lines() {
        if let Some(f) = parse_tsc_line(line) {
            findings.push(f);
        }
    }
    Ok(findings)
}

pub fn parse_tsc_line(line: &str) -> Option<Finding> {
    let (loc_part, rest) = line.split_once("): ")?;
    let (file_part, coords) = loc_part.rsplit_once('(')?;
    let (line_s, col_s) = coords.split_once(',')?;
    let start_line: usize = line_s.trim().parse().ok()?;
    let start_col: usize = col_s.trim().parse().ok()?;

    let (kind_and_code, message) = rest.split_once(": ")?;
    let (kind, code) = kind_and_code.split_once(' ')?;

    let severity = match kind {
        "error" => Severity::Error,
        "warning" => Severity::Warning,
        _ => Severity::Note,
    };

    Some(Finding {
        rule_id: code.to_string(),
        tool: "tsc".to_string(),
        severity,
        tier: Some(if matches!(severity, Severity::Error) { "high" } else { "medium" }.to_string()),
        message: message.trim().to_string(),
        file: file_part.trim().replace('\\', "/"),
        start_line,
        start_col,
        snippet: None,
        physics_law: None,
        remediation: None,
        suppression_hint: None,
        budget: None,
    })
}

async fn run_ruff(root: &Path, pedantic: bool) -> anyhow::Result<Vec<Finding>> {
    let Ok(out) = Command::new("ruff")
        .args(["check", "--output-format=json", "."])
        .current_dir(root)
        .output()
        .await
    else {
        return Ok(vec![]);
    };

    let mut findings = Vec::new();
    if let Ok(items) = serde_json::from_slice::<Vec<serde_json::Value>>(&out.stdout) {
        for item in items {
            let code = item["code"].as_str().unwrap_or("ruff").to_string();
            let is_style = code.starts_with('I') || code.starts_with("D") || code.starts_with("UP");
            if is_style && !pedantic {
                continue;
            }
            findings.push(Finding {
                rule_id: code,
                tool: "ruff".to_string(),
                severity: if is_style { Severity::Note } else { Severity::Error },
                tier: Some(if is_style { "pedantic" } else { "high" }.to_string()),
                message: item["message"].as_str().unwrap_or("").to_string(),
                file: item["filename"].as_str().unwrap_or("").replace('\\', "/"),
                start_line: item["location"]["row"].as_u64().unwrap_or(1) as usize,
                start_col: item["location"]["column"].as_u64().unwrap_or(1) as usize,
                snippet: None,
                physics_law: None,
                remediation: None,
                suppression_hint: None,
                budget: None,
            });
        }
    }
    Ok(findings)
}

async fn run_mypy(root: &Path) -> anyhow::Result<Vec<Finding>> {
    let Ok(out) = Command::new("mypy")
        .args(["--output=json", "."])
        .current_dir(root)
        .output()
        .await
    else {
        return Ok(vec![]);
    };

    let mut findings = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
        let sev_str = v["severity"].as_str().unwrap_or("error");
        let severity = match sev_str {
            "error" => Severity::Error,
            "warning" => Severity::Warning,
            _ => Severity::Note,
        };

        findings.push(Finding {
            rule_id: v["code"].as_str().unwrap_or("mypy").to_string(),
            tool: "mypy".to_string(),
            severity,
            tier: Some(if matches!(severity, Severity::Error) { "high" } else { "medium" }.to_string()),
            message: v["message"].as_str().unwrap_or("").to_string(),
            file: v["file"].as_str().unwrap_or("").replace('\\', "/"),
            start_line: v["line"].as_u64().unwrap_or(1) as usize,
            start_col: v["column"].as_u64().unwrap_or(1) as usize,
            snippet: None,
            physics_law: None,
            remediation: None,
            suppression_hint: None,
            budget: None,
        });
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tsc_and_filters_pedantic_clippy() {
        let err = parse_tsc_line(
            "src/index.ts(12,5): error TS2322: Type 'string' is not assignable to type 'number'.",
        )
        .unwrap();
        assert_eq!(err.rule_id, "TS2322");
        assert!(is_pedantic_clippy_code("clippy::io_other_error"));
        assert!(!is_pedantic_clippy_code("clippy::unwrap_used"));
    }
}
