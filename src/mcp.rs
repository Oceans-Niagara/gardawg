use crate::analyzer::{scan_workspace, ScanOptions};
use crate::budgets::evaluate_payload_checks;
use crate::config::GuardrailsConfig;
use crate::gate::run_unified_gate;
use crate::physics::{all_profiles, builtin_profiles, evaluate_payload, resolve_profile};
use crate::sarif::CheckReport;
use crate::verify::{run_verify, VerifyOptions};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

pub async fn run_mcp_stdio(workspace: PathBuf, custom_profiles: Option<PathBuf>) -> anyhow::Result<()> {
    let stdin = BufReader::new(tokio::io::stdin());
    let mut stdout = tokio::io::stdout();
    let mut lines = stdin.lines();

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let err = json!({
                    "jsonrpc": "2.0",
                    "id": Value::Null,
                    "error": { "code": -32700, "message": format!("Parse error: {e}") }
                });
                stdout.write_all(err.to_string().as_bytes()).await?;
                stdout.write_all(b"\n").await?;
                stdout.flush().await?;
                continue;
            }
        };

        let id = req.get("id").cloned();
        let method = req["method"].as_str().unwrap_or("");
        let params = req.get("params").cloned().unwrap_or(json!({}));

        let result = match method {
            "initialize" => Ok(json!({
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "guardrails", "version": env!("CARGO_PKG_VERSION") }
            })),
            "notifications/initialized" => continue,
            "tools/list" => Ok(json!({
                "tools": [
                    {
                        "name": "list_link_profiles",
                        "description": "List physical-layer RF/serial link profiles (LoRa SF12, BLE 1M, Wi-Fi 2.4G, LEO sat, UART 9600, plus licensed custom profiles).",
                        "inputSchema": { "type": "object", "properties": {} }
                    },
                    {
                        "name": "evaluate_payload",
                        "description": "Step 1 (Budget first): Compute Shannon ceiling, protocol goodput, MTU fragmentation, safe byte limit, and BER loss before writing wire framing code.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "profile": { "type": "string", "description": "e.g. lora-sf12, ble-1m, wifi-24g-congested, leo-sat, uart-9600" },
                                "payload_bytes": { "type": "integer", "minimum": 1 },
                                "hz": { "type": "number", "minimum": 0.001 }
                            },
                            "required": ["profile", "payload_bytes", "hz"]
                        }
                    },
                    {
                        "name": "guardrails_check",
                        "description": "Step 2 (Check every edit): Run unified single-pass AST + physical-layer link rules + external compiler/linter gate.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": { "type": "string", "description": "Optional subpath or file to scan" },
                                "profile": { "type": "string", "description": "Optional RF/serial link profile ID (e.g. lora-sf12)" },
                                "hz": { "type": "number", "default": 10.0 },
                                "ast_only": { "type": "boolean", "default": false },
                                "pedantic": { "type": "boolean", "default": false }
                            }
                        }
                    },
                    {
                        "name": "verify_runtime",
                        "description": "Step 3 (Verify runtime): Run an automated black-box smoke test through the impairment/chaos proxy and return structured runtime diagnostics.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "command": { "type": "string", "description": "Shell command to run (e.g. 'python app.py')" },
                                "profile": { "type": "string", "description": "Optional physical link profile (e.g. lora-sf12, ble-1m)" },
                                "upstream": { "type": "string", "description": "Optional target host:port to proxy to (e.g. 127.0.0.1:8080)" },
                                "probe_path": { "type": "string", "description": "Optional HTTP path to probe through chaos proxy (e.g. /health)" },
                                "duration_secs": { "type": "integer", "default": 4 },
                                "udp": { "type": "boolean", "default": false }
                            },
                            "required": ["command"]
                        }
                    }
                ]
            })),
            "tools/call" => handle_tool_call(&workspace, custom_profiles.as_deref(), &params).await,
            _ => Err((-32601, format!("Method not found: {method}"))),
        };

        if let Some(id) = id {
            let resp = match result {
                Ok(res) => json!({ "jsonrpc": "2.0", "id": id, "result": res }),
                Err((code, msg)) => json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": msg } }),
            };
            stdout.write_all(resp.to_string().as_bytes()).await?;
            stdout.write_all(b"\n").await?;
            stdout.flush().await?;
        }
    }
    Ok(())
}

async fn handle_tool_call(
    workspace: &PathBuf,
    custom_profiles: Option<&std::path::Path>,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let tool_name = params["name"].as_str().unwrap_or("");
    let args = &params["arguments"];

    match tool_name {
        "list_link_profiles" => {
            let profs = all_profiles(custom_profiles).unwrap_or_else(|_| builtin_profiles());
            Ok(json!({
                "content": [{ "type": "text", "text": serde_json::to_string_pretty(&profs).unwrap_or_default() }]
            }))
        }

        "evaluate_payload" => {
            let pid = args["profile"].as_str().unwrap_or("lora-sf12");
            let bytes = args["payload_bytes"].as_u64().unwrap_or(32) as usize;
            let hz = args["hz"].as_f64().unwrap_or(1.0);
            match resolve_profile(pid, custom_profiles) {
                Ok(prof) => {
                    let rep = evaluate_payload(&prof, bytes, hz);
                    let out = json!({
                        "recommended_max_app_bytes": prof.recommended_app_payload_bytes(),
                        "mtu_bytes": prof.max_payload_bytes,
                        "header_overhead_bytes": prof.header_overhead_bytes,
                        "report": rep
                    });
                    Ok(json!({
                        "content": [{ "type": "text", "text": serde_json::to_string_pretty(&out).unwrap_or_default() }]
                    }))
                }
                Err(e) => Ok(json!({
                    "isError": true,
                    "content": [{ "type": "text", "text": e }]
                })),
            }
        }

        "guardrails_check" => {
            let target = args["path"]
                .as_str()
                .map(|p| workspace.join(p))
                .unwrap_or_else(|| workspace.clone());
            let cfg = GuardrailsConfig::load(workspace, None).unwrap_or_default();
            let pedantic = args["pedantic"].as_bool().unwrap_or(false);
            let ast_only = args["ast_only"].as_bool().unwrap_or(false);
            let hz = args["hz"].as_f64().unwrap_or(cfg.link.assumed_hz);

            let profile_id = args["profile"]
                .as_str()
                .map(|s| s.to_string())
                .or_else(|| if cfg.link.enabled { cfg.link.profile.clone() } else { None });

            let resolved_profile = match profile_id.as_deref() {
                Some(pid) => match resolve_profile(pid, custom_profiles) {
                    Ok(p) => Some(p),
                    Err(e) => {
                        return Ok(json!({
                            "isError": true,
                            "content": [{ "type": "text", "text": e }]
                        }));
                    }
                },
                None => None,
            };

            let scan = scan_workspace(
                &target,
                &ScanOptions {
                    exclude: &cfg.ast.exclude,
                    link_profile: resolved_profile.as_ref(),
                    assumed_hz: hz,
                    pedantic,
                },
            )
            .map_err(|e| (-32603, e.to_string()))?;

            let mut findings = scan.findings;
            if !ast_only && target.is_dir() {
                findings.extend(
                    run_unified_gate(&target, &cfg.gate, pedantic)
                        .await
                        .unwrap_or_default(),
                );
            }

            findings.retain(|f| cfg.is_rule_enabled(&f.rule_id));
            let mut seen = HashSet::new();
            findings.retain(|f| {
                seen.insert((
                    f.rule_id.clone(),
                    f.file.clone(),
                    f.start_line,
                    f.start_col,
                    f.message.clone(),
                ))
            });

            let payload_results = if let Some(ref prof) = resolved_profile {
                evaluate_payload_checks(prof, &cfg.link.payload_checks)
            } else {
                vec![]
            };
            let payload_failed = payload_results.iter().any(|p| !p.passed);
            let passed = findings.is_empty() && !payload_failed;

            let report = CheckReport {
                passed,
                files_scanned: scan.files_scanned,
                rules_evaluated: scan.rules_evaluated,
                profile: resolved_profile.map(|p| p.id.to_string()),
                pedantic,
                suppressed_by_baseline: 0,
                findings_count: findings.len(),
                findings,
                payload_results,
            };

            Ok(json!({
                "isError": !report.passed,
                "content": [{ "type": "text", "text": serde_json::to_string_pretty(&report).unwrap_or_default() }]
            }))
        }

        "verify_runtime" | "smoke_test" => {
            let cmd = args["command"].as_str().unwrap_or("").trim().to_string();
            if cmd.is_empty() {
                return Ok(json!({
                    "isError": true,
                    "content": [{ "type": "text", "text": "Provide a non-empty 'command' string." }]
                }));
            }
            let cfg = GuardrailsConfig::load(workspace, None).unwrap_or_default();
            let opts = VerifyOptions {
                command: cmd,
                profile: args["profile"].as_str().map(|s| s.to_string()),
                custom_profiles: custom_profiles.map(|p| p.to_path_buf()),
                upstream: args["upstream"].as_str().map(|s| s.to_string()),
                probe_path: args["probe_path"].as_str().map(|s| s.to_string()),
                duration_secs: args["duration_secs"].as_u64().unwrap_or(4),
                seed: cfg.resilience.seed,
                drop_rate: cfg.resilience.drop_rate,
                rate_429: cfg.resilience.rate_429,
                max_jitter_ms: cfg.resilience.max_jitter_ms,
                udp: args["udp"].as_bool().unwrap_or(false),
            };
            match run_verify(workspace, opts).await {
                Ok(report) => Ok(json!({
                    "isError": !report.passed,
                    "content": [{ "type": "text", "text": serde_json::to_string_pretty(&report).unwrap_or_default() }]
                })),
                Err(e) => Ok(json!({
                    "isError": true,
                    "content": [{ "type": "text", "text": e.to_string() }]
                })),
            }
        }

        _ => Err((-32601, format!("Unknown tool: {tool_name}"))),
    }
}
