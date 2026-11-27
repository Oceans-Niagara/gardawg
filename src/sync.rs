use crate::config::GardawgConfig;
use serde_json::{json, Map, Value};
use std::fs;
use std::path::Path;

const START_MARKER: &str = "<!-- GARDAWG:START -->";
const END_MARKER: &str = "<!-- GARDAWG:END -->";

pub fn sync_all(workspace: &Path, cfg: &GardawgConfig, force: bool) -> anyhow::Result<()> {
    if cfg.sync.mcp_json {
        sync_mcp_json(&workspace.join(".mcp.json"), force)?;
    }
    if cfg.sync.opencode_json {
        sync_opencode_json(&workspace.join("opencode.json"), force)?;
    }
    if cfg.sync.agents_md {
        sync_agents_md(&workspace.join("AGENTS.md"), cfg)?;
    }
    Ok(())
}

fn is_on_path(bin_name: &str) -> bool {
    let Some(path_var) = std::env::var_os("PATH") else {
        return false;
    };
    #[cfg(windows)]
    let candidates = [
        format!("{bin_name}.exe"),
        format!("{bin_name}.cmd"),
        bin_name.to_string(),
    ];
    #[cfg(not(windows))]
    let candidates = [bin_name.to_string()];

    std::env::split_paths(&path_var).any(|dir| candidates.iter().any(|name| dir.join(name).is_file()))
}

pub fn resolve_mcp_command() -> String {
    if is_on_path("gardawg") {
        return "gardawg".to_string();
    }
    if let Ok(exe) = std::env::current_exe() {
        let s = exe.to_string_lossy();
        #[cfg(windows)]
        let s = s.strip_prefix(r"\\?\").unwrap_or(&s);
        return s.to_string();
    }
    "gardawg".to_string()
}

fn sync_mcp_json(path: &Path, force: bool) -> anyhow::Result<()> {
    let mut root: Value = if path.exists() {
        let raw = fs::read_to_string(path)?;
        if raw.trim().is_empty() { json!({}) } else { serde_json::from_str(&raw)? }
    } else {
        json!({})
    };

    let obj = root
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!(".mcp.json root must be a JSON object"))?;

    let servers = obj
        .entry("mcpServers")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("`mcpServers` must be a JSON object"))?;

    let resolved_cmd = resolve_mcp_command();
    match servers.get_mut("gardawg").and_then(|v| v.as_object_mut()) {
        Some(existing) if !force => {
            let missing_cmd = existing
                .get("command")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().is_empty())
                .unwrap_or(true);
            if missing_cmd {
                existing.insert("command".to_string(), Value::String(resolved_cmd));
            }
            existing
                .entry("args")
                .or_insert_with(|| json!(["mcp", "--workspace", "."]));
        }
        _ => {
            servers.insert(
                "gardawg".to_string(),
                json!({
                    "command": resolved_cmd,
                    "args": ["mcp", "--workspace", "."]
                }),
            );
        }
    }

    let pretty = serde_json::to_string_pretty(&root)?;
    fs::write(path, format!("{pretty}\n"))?;
    Ok(())
}

fn sync_opencode_json(path: &Path, force: bool) -> anyhow::Result<()> {
    let mut root: Value = if path.exists() {
        let raw = fs::read_to_string(path)?;
        if raw.trim().is_empty() { json!({}) } else { serde_json::from_str(&raw)? }
    } else {
        json!({ "$schema": "https://opencode.ai/config.json" })
    };

    let obj = root
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("opencode.json root must be a JSON object"))?;

    obj.entry("$schema")
        .or_insert_with(|| Value::String("https://opencode.ai/config.json".to_string()));

    let mcp = obj
        .entry("mcp")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("`mcp` in opencode.json must be a JSON object"))?;

    let resolved_cmd = resolve_mcp_command();
    if force || !mcp.contains_key("gardawg") {
        mcp.insert(
            "gardawg".to_string(),
            json!({
                "type": "local",
                "command": [resolved_cmd, "mcp", "--workspace", "."],
                "enabled": true
            }),
        );
    }

    let pretty = serde_json::to_string_pretty(&root)?;
    fs::write(path, format!("{pretty}\n"))?;
    Ok(())
}

pub fn render_agents_managed_block(cfg: &GardawgConfig) -> String {
    let mut bullets = vec![
        "### Mandatory 3-Step Definition of Done".to_string(),
        "1. **Budget first:** Before designing wire frames, structs, or telemetry loops, call `evaluate_payload` (or `gardawg budget --profile <id> --bytes <n> --hz <r>`) to confirm MTU & goodput ceilings.".to_string(),
        "2. **Check every edit:** After every code edit, run `gardawg_check` (or `gardawg check`) and fix all reported issues until `findings_count == 0`.".to_string(),
        "3. **Verify runtime:** Before finishing, run `verify_runtime` (or `gardawg verify`) against the target profile/proxy to confirm no hangs, dropped-packet crashes, or corrupted state.".to_string(),
        String::new(),
        "### Engineering Rules".to_string(),
    ];

    if cfg.is_rule_enabled("GR001") {
        let mut types = Vec::new();
        if cfg.gate.rust { types.push("`f64`/`f32`"); }
        if cfg.gate.python { types.push("`float`"); }
        if cfg.gate.typescript { types.push("`number`"); }
        let type_str = if types.is_empty() { "floating-point types".to_string() } else { types.join("/") };
        bullets.push(format!(
            "- Never use {type_str} for money or quantities; use integer minor units or `Decimal`."
        ));
    }

    if cfg.is_rule_enabled("GR002") {
        bullets.push("- Every outbound HTTP/network client, `socket.socket()`, `HTTPServer`, and C `recv`/`connect` must set an explicit timeout.".to_string());
    }

    if cfg.is_rule_enabled("GR003") {
        bullets.push("- Every mutating external API request must include an idempotency key.".to_string());
    }

    if cfg.is_rule_enabled("GR004") {
        bullets.push("- Never swallow errors, ignore critical C I/O return codes, or overwrite JSON/state files without atomic `os.replace()`.".to_string());
    }

    if cfg.is_rule_enabled("GR005") {
        bullets.push("- Never leave `todo!()`, `unimplemented!()`, `NotImplementedError`, or `PLACEHOLDER` stubs.".to_string());
    }

    if cfg.is_rule_enabled("GR006") {
        bullets.push("- Never hardcode secrets/keys or use unsafe dynamic/buffer execution (`eval`, `shell=True`, `strcpy`, `sprintf`, `system`).".to_string());
    }

    if cfg.gate.rust && cfg.is_rule_enabled("GR007") {
        bullets.push("- Avoid `.unwrap()` in production Rust code; propagate with `?` or handle explicitly.".to_string());
    }

    if cfg.link.enabled || cfg.link.profile.is_some() {
        let prof = cfg.link.profile.as_deref().unwrap_or("lora-sf12");
        bullets.push(format!(
            "- Physical-layer profile `{prof}`: never serialize JSON/text inside loops; pack binary frames (`struct.pack` / `postcard` / `DataView`) with sequence counters + CRC, batch up to link MTU, and never block async/RTOS executors."
        ));
    }

    for custom in &cfg.agents.custom_rules {
        let trimmed = custom.trim().trim_start_matches('-').trim();
        if !trimmed.is_empty() {
            bullets.push(format!("- {trimmed}"));
        }
    }

    format!(
        "{START_MARKER}\n## Deterministic Guardrails (Managed by `gardawg sync`)\n{}\n{END_MARKER}",
        bullets.join("\n")
    )
}

fn sync_agents_md(path: &Path, cfg: &GardawgConfig) -> anyhow::Result<()> {
    let managed_block = render_agents_managed_block(cfg);

    let updated = if path.exists() {
        let existing = fs::read_to_string(path)?;
        if let (Some(start), Some(end)) = (existing.find(START_MARKER), existing.find(END_MARKER)) {
            if start < end {
                let end_after = end + END_MARKER.len();
                format!("{}{}{}", &existing[..start], managed_block, &existing[end_after..])
            } else {
                format!("{existing}\n\n{managed_block}\n")
            }
        } else if existing.trim().is_empty() {
            format!("{managed_block}\n")
        } else {
            format!("{}\n\n{managed_block}\n", existing.trim_end())
        }
    } else {
        format!("# Agent Instructions\n\n{managed_block}\n")
    };

    fs::write(path, updated)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_scaffolds_mcp_opencode_and_agents_idempotently() {
        let dir = std::env::temp_dir().join(format!("gardawg_sync_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let cfg = GardawgConfig::default();
        sync_all(&dir, &cfg, false).unwrap();
        sync_all(&dir, &cfg, false).unwrap();

        let mcp: Value = serde_json::from_str(&fs::read_to_string(dir.join(".mcp.json")).unwrap()).unwrap();
        assert!(mcp["mcpServers"]["gardawg"].is_object());

        let opencode: Value = serde_json::from_str(&fs::read_to_string(dir.join("opencode.json")).unwrap()).unwrap();
        assert_eq!(opencode["mcp"]["gardawg"]["type"], "local");
        assert_eq!(opencode["mcp"]["gardawg"]["enabled"], true);

        let agents = fs::read_to_string(dir.join("AGENTS.md")).unwrap();
        assert!(agents.contains("Mandatory 3-Step Definition of Done"));
        assert!(agents.contains("verify_runtime"));
        assert_eq!(agents.matches(START_MARKER).count(), 1);

        let _ = fs::remove_dir_all(&dir);
    }
}
