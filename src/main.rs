mod analyzer;
mod budgets;
mod chaos;
mod config;
mod fix;
mod gate;
#[cfg(feature = "gui")]
mod gui;
mod license;
mod mcp;
mod physics;
mod proxy;
mod resilience;
mod sarif;
mod sync;
mod verify;

use crate::analyzer::{scan_workspace, ScanOptions};
use crate::budgets::{apply_baseline_ratchet, evaluate_payload_checks, load_standalone_budgets};
use crate::config::GardawgConfig;
use crate::license::{check_license_with_override, require_pro_with_key};
use crate::physics::{all_profiles, evaluate_payload, resolve_profile};
use crate::proxy::ProxyTransport;
use crate::sarif::{to_sarif_with_org, CheckReport, Severity};
use crate::verify::{run_verify, VerifyOptions};
use clap::{Parser, Subcommand, ValueEnum};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "gardawg",
    version,
    about = "Unified deterministic AI guardrails, physical-layer analyzer, and chaos/impairment proxy"
)]
struct Cli {
    /// Target workspace directory
    #[arg(short, long, global = true, default_value = ".")]
    workspace: PathBuf,

    /// Path to gardawg.toml (defaults to <workspace>/gardawg.toml)
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    /// Optional custom profiles.toml path (Pro/Team)
    #[arg(long, global = true)]
    profiles: Option<PathBuf>,

    /// Offline Ed25519 license key or path (env: GARDAWG_LICENSE_KEY or LINKGUARD_LICENSE)
    #[arg(long, global = true, env = "GARDAWG_LICENSE_KEY")]
    license_key: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Clone, Copy, ValueEnum)]
enum OutputFormat {
    Json,
    Sarif,
    Text,
}

#[derive(Clone, Copy, ValueEnum)]
enum ChaosMode {
    Http,
    Tcp,
}

#[derive(Subcommand)]
enum Commands {
    /// Create gardawg.toml, AGENTS.md, .mcp.json, and opencode.json (pass --link for starter link TOMLs)
    Init {
        #[arg(long)]
        force: bool,
        #[arg(long, value_enum)]
        profile: Option<config::Profile>,
        /// Also scaffold [link] in gardawg.toml plus starter profiles.toml & budgets.toml
        /// (default link profile: wifi-24g-congested)
        #[arg(long)]
        link: bool,
        /// Link profile ID for [link] (built-in or from profiles.toml); implies --link
        #[arg(long)]
        link_profile: Option<String>,
    },

    /// Copy this binary (+ adjacent gardawg.lic) to a per-user bin dir and add it to your user PATH
    #[command(alias = "install-path")]
    Install {
        /// Override the install directory
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Copy files only; do not modify PATH
        #[arg(long)]
        no_path: bool,
    },

    /// Sync AGENTS.md, .mcp.json, and opencode.json from gardawg.toml
    Sync {
        #[arg(long)]
        force: bool,
        /// Team/Enterprise: fail if AGENTS.md, .mcp.json, or opencode.json have drifted
        #[arg(long)]
        check: bool,
    },

    /// Run unified single-pass AST + physical-layer link rules + external lint/type gate
    Check {
        #[arg(long, value_enum, default_value = "json")]
        format: OutputFormat,
        /// Skip external clippy/tsc/ruff/mypy gate and run AST rules only
        #[arg(long)]
        ast_only: bool,
        /// Include stylistic/pedantic lints (e.g. clippy::io_other_error, TODO comments)
        #[arg(long)]
        pedantic: bool,
        /// Physical-layer profile ID (e.g. lora-sf12, ble-1m, wifi-24g-congested)
        #[arg(short, long, alias = "link-profile")]
        profile: Option<String>,
        /// Assumed transmission rate in Hz when not inferred from loop sleep/delay
        #[arg(long)]
        hz: Option<f64>,
        /// Optional standalone budgets.toml path
        #[arg(long)]
        budgets: Option<PathBuf>,
        /// Optional baseline JSON report (Pro/Team: fail only on new regressions)
        #[arg(long)]
        baseline: Option<PathBuf>,
        /// Optional output file path (writes report in UTF-8 directly)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Enterprise: run the AST/link scan against several profiles (comma-separated IDs) and print a matrix
        #[arg(long, value_delimiter = ',')]
        profile_matrix: Vec<String>,
    },

    /// List built-in (and licensed custom) RF / serial link profiles
    Profiles,

    /// Compute Shannon ceiling, MTU fragmentation, airtime, and BER loss for a payload
    Budget {
        #[arg(short, long, default_value = "lora-sf12")]
        profile: String,
        #[arg(short, long)]
        bytes: usize,
        #[arg(long, default_value_t = 1.0)]
        hz: f64,
    },

    /// Run a seeded deterministic physical-layer TCP or UDP impairment proxy
    Proxy {
        #[arg(long, default_value = "127.0.0.1:9000")]
        listen: String,
        #[arg(long)]
        target: String,
        #[arg(short, long, default_value = "wifi-24g-congested")]
        profile: String,
        #[arg(long, default_value_t = 42)]
        seed: u64,
        #[arg(long, default_value_t = false)]
        udp: bool,
    },

    /// Start standalone seeded TCP/HTTP chaos proxy with deterministic exit JSON summary
    Chaos {
        #[arg(long, default_value = "127.0.0.1:9000")]
        listen: SocketAddr,
        #[arg(long)]
        upstream: Option<String>,
        #[arg(long)]
        seed: Option<u64>,
        #[arg(long, value_enum, default_value = "http")]
        mode: ChaosMode,
    },

    /// Run an automated black-box smoke test through the impairment/chaos proxy
    Verify {
        /// Command to execute (e.g. "python app.py")
        #[arg(long)]
        cmd: String,
        /// Optional physical-layer link profile (e.g. lora-sf12)
        #[arg(short, long, alias = "link-profile")]
        profile: Option<String>,
        /// Optional target server address (e.g. 127.0.0.1:8080 or http://localhost:8080)
        #[arg(long)]
        upstream: Option<String>,
        /// Optional HTTP path to probe through chaos proxy (e.g. /health)
        #[arg(long)]
        probe_path: Option<String>,
        #[arg(long, default_value_t = 4)]
        duration: u64,
        #[arg(long)]
        seed: Option<u64>,
        #[arg(long, default_value_t = false)]
        udp: bool,
        /// Bind the impairment proxy to a fixed address (e.g. 127.0.0.1:9000) instead of a random port.
        /// Exported to the command as GARDAWG_PROXY_ADDR / GARDAWG_PROXY_PORT / GARDAWG_PROXY_URL.
        #[arg(long)]
        listen: Option<String>,
    },

    /// Run Schemathesis & Keploy through the seeded chaos proxy (Pro/Team)
    Resilience {
        #[arg(long)]
        seed: Option<u64>,
        #[arg(long)]
        openapi: Option<String>,
    },

    /// Launch Pro Desktop Dashboard (requires `--features gui` & Pro/Team license)
    Gui {
        #[arg(short, long, default_value = "lora-sf12")]
        profile: String,
        #[arg(long, default_value = "127.0.0.1:9000")]
        listen: String,
        #[arg(long)]
        target: Option<String>,
        #[arg(long, default_value_t = 42)]
        seed: u64,
        #[arg(long, default_value_t = false)]
        udp: bool,
    },

    /// Repair AST findings single-file-at-a-time using a local Ollama model (e.g. ollama/qwen2.5-coder:3b)
    Fix {
        /// Local Ollama model tag (e.g. ollama/qwen2.5-coder:3b)
        #[arg(long, default_value = "ollama/qwen2.5-coder:3b")]
        model: String,
        /// Ollama base URL
        #[arg(long, env = "OLLAMA_HOST", default_value = "http://127.0.0.1:11434")]
        ollama_url: String,
        /// Optional single file to repair (defaults to scanning workspace)
        #[arg(long)]
        file: Option<PathBuf>,
        /// Optional physical-layer link profile
        #[arg(short, long, alias = "link-profile")]
        profile: Option<String>,
        /// Maximum number of files to attempt per run
        #[arg(long, default_value_t = 5)]
        max_files: usize,
        /// Preview repairs without modifying files on disk
        #[arg(long)]
        dry_run: bool,
    },

    /// Start unified MCP JSON-RPC 2.0 server over stdio
    Mcp,

    /// Inspect offline Ed25519 license status (Free / Pro / Team)
    #[command(alias = "license-check")]
    License,
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    match run(cli).await {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    let workspace = cli.workspace.canonicalize().unwrap_or(cli.workspace);
    let cfg = GardawgConfig::load(&workspace, cli.config.as_deref())?;
    let custom_profiles = cli.profiles.as_deref();

    let command = match cli.command {
        Some(cmd) => cmd,
        None => {
            #[cfg(feature = "gui")]
            {
                Commands::Gui {
                    profile: config::DEFAULT_LINK_PROFILE.to_string(),
                    listen: "127.0.0.1:9000".to_string(),
                    target: None,
                    seed: 42,
                    udp: false,
                }
            }
            #[cfg(not(feature = "gui"))]
            {
                anyhow::bail!("No subcommand provided. Run `gardawg --help` for usage.");
            }
        }
    };

    match command {
        Commands::Init { force, profile, link, link_profile } => {
            let cfg_path = workspace.join("gardawg.toml");
            if cfg_path.exists() && !force {
                anyhow::bail!("{} already exists (pass --force to overwrite)", cfg_path.display());
            }
            let name = workspace.file_name().and_then(|n| n.to_str()).unwrap_or("app");
            let detected = config::detect_workspace(&workspace);
            let chosen_profile = profile.unwrap_or(detected.profile);
            if let Some(ref lp) = link_profile {
                if physics::get_profile(lp).is_none() {
                    let ws_profiles = workspace.join("profiles.toml");
                    let custom = custom_profiles
                        .map(|p| p.to_path_buf())
                        .or_else(|| ws_profiles.is_file().then_some(ws_profiles));
                    if custom.is_none() {
                        anyhow::bail!(
                            "--link-profile: unknown profile '{lp}'. Built-in: {}",
                            config::BUILTIN_LINK_PROFILE_IDS.join(", ")
                        );
                    }
                    resolve_profile(lp, custom.as_deref())
                        .map_err(|e| anyhow::anyhow!("--link-profile: {e}"))?;
                }
            }
            std::fs::write(
                &cfg_path,
                config::render_toml_for_init(name, &detected, profile, link, link_profile.as_deref()),
            )?;
            let init_cfg = GardawgConfig::load(&workspace, Some(&cfg_path))?;
            sync::sync_all(&workspace, &init_cfg, force)?;

            if link {
                let prof_path = workspace.join("profiles.toml");
                if !prof_path.exists() || force {
                    std::fs::write(&prof_path, config::render_starter_profiles_toml())?;
                }
                let bud_path = workspace.join("budgets.toml");
                if !bud_path.exists() || force {
                    std::fs::write(&bud_path, config::render_starter_budgets_toml())?;
                }
            }

            eprintln!(
                "Initialized {} (profile={}, link={}, rust={}, ts={}, py={}) and synced agent configs.",
                cfg_path.display(),
                chosen_profile.as_str(),
                init_cfg.link.enabled,
                init_cfg.gate.rust,
                init_cfg.gate.typescript,
                init_cfg.gate.python
            );
            if init_cfg.link.enabled {
                eprintln!(
                    "{}",
                    config::link_profile_tip(
                        init_cfg.link.profile.as_deref().unwrap_or(config::DEFAULT_LINK_PROFILE)
                    )
                );
            } else {
                eprintln!(
                    "Tip: link analysis is off; run `gardawg init --link --force` or set [link] enabled = true, profile = \"{}\" in gardawg.toml.",
                    config::DEFAULT_LINK_PROFILE
                );
            }
            Ok(ExitCode::SUCCESS)
        }

        Commands::Install { dir, no_path } => {
            install_self(dir, no_path)?;
            Ok(ExitCode::SUCCESS)
        }

        Commands::Sync { force, check } => {
            if !cfg.agents.custom_rules.is_empty() {
                crate::license::require_team_with_key("[agents].custom_rules", cli.license_key.as_deref(), &workspace)
                    .map_err(|e| anyhow::anyhow!(e))?;
            }
            if check {
                crate::license::require_team_with_key("gardawg sync --check", cli.license_key.as_deref(), &workspace)
                    .map_err(|e| anyhow::anyhow!(e))?;
                let drifted = sync::check_sync(&workspace, &cfg)?;
                if drifted.is_empty() {
                    println!("gardawg sync --check: all agent config files are in sync.");
                    return Ok(ExitCode::SUCCESS);
                }
                eprintln!("gardawg sync --check: drift detected in: {}", drifted.join(", "));
                eprintln!("Run `gardawg sync` to update them from gardawg.toml.");
                return Ok(ExitCode::from(1));
            }
            sync::sync_all(&workspace, &cfg, force)?;
            eprintln!("Synced .mcp.json, opencode.json, and AGENTS.md.");
            Ok(ExitCode::SUCCESS)
        }

        Commands::Check {
            format,
            ast_only,
            pedantic,
            profile,
            hz,
            budgets,
            baseline,
            output,
            profile_matrix,
        } => {
            if !cfg.agents.custom_rules.is_empty() {
                crate::license::require_team_with_key("[agents].custom_rules", cli.license_key.as_deref(), &workspace)
                    .map_err(|e| anyhow::anyhow!(e))?;
            }
            if !profile_matrix.is_empty() {
                crate::license::require_enterprise_with_key("check --profile-matrix", cli.license_key.as_deref())
                    .map_err(|e| anyhow::anyhow!(e))?;
                let matrix_hz = hz.unwrap_or(cfg.link.assumed_hz);
                let mut rows = Vec::new();
                let mut all_passed = true;
                for pid in &profile_matrix {
                    let pid = pid.trim();
                    if pid.is_empty() {
                        continue;
                    }
                    let prof = resolve_profile(pid, custom_profiles).map_err(|e| anyhow::anyhow!(e))?;
                    let scan = scan_workspace(
                        &workspace,
                        &ScanOptions {
                            exclude: &cfg.ast.exclude,
                            link_profile: Some(&prof),
                            assumed_hz: matrix_hz,
                            pedantic,
                        },
                    )?;
                    let findings: Vec<_> = scan
                        .findings
                        .into_iter()
                        .filter(|f| cfg.is_rule_enabled(&f.rule_id))
                        .collect();
                    let errors = findings.iter().filter(|f| matches!(f.severity, Severity::Error)).count();
                    let warnings = findings.iter().filter(|f| matches!(f.severity, Severity::Warning)).count();
                    let failed = match cfg.project.fail_on.as_str() {
                        "warning" => errors + warnings > 0,
                        _ => errors > 0,
                    };
                    all_passed &= !failed;
                    rows.push(serde_json::json!({
                        "profile": prof.id,
                        "passed": !failed,
                        "findings": findings.len(),
                        "errors": errors,
                        "warnings": warnings,
                        "rule_ids": findings.iter().map(|f| f.rule_id.clone()).collect::<std::collections::BTreeSet<_>>(),
                    }));
                }
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "passed": all_passed,
                        "assumed_hz": matrix_hz,
                        "matrix": rows,
                    }))?
                );
                return Ok(if all_passed { ExitCode::SUCCESS } else { ExitCode::from(1) });
            }
            let budgets_cfg = if let Some(ref bpath) = budgets {
                Some(load_standalone_budgets(bpath)?)
            } else if !cfg.link.enabled && workspace.join("budgets.toml").is_file() {
                Some(load_standalone_budgets(&workspace.join("budgets.toml"))?)
            } else {
                None
            };

            let active_link = budgets_cfg.as_ref().unwrap_or(&cfg.link);
            let effective_profile_id = profile.or_else(|| {
                if active_link.enabled {
                    active_link.profile.clone()
                } else {
                    None
                }
            });
            let resolved_profile = effective_profile_id
                .as_deref()
                .map(|pid| resolve_profile(pid, custom_profiles))
                .transpose()
                .map_err(|e| anyhow::anyhow!(e))?;

            let effective_hz = hz.unwrap_or(active_link.assumed_hz);
            let mut findings = Vec::new();
            let mut files_scanned = 0usize;
            let mut rules_evaluated = analyzer::TOTAL_RULES_COUNT;

            if cfg.ast.enabled {
                let scan = scan_workspace(
                    &workspace,
                    &ScanOptions {
                        exclude: &cfg.ast.exclude,
                        link_profile: resolved_profile.as_ref(),
                        assumed_hz: effective_hz,
                        pedantic,
                    },
                )?;
                files_scanned = scan.files_scanned;
                rules_evaluated = scan.rules_evaluated;
                findings.extend(scan.findings);
            }

            if !ast_only {
                findings.extend(gate::run_unified_gate(&workspace, &cfg.gate, pedantic).await?);
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

            let (findings, suppressed_by_baseline) =
                apply_baseline_ratchet(findings, baseline.as_deref(), cli.license_key.as_deref())?;

            let payload_results = if let Some(ref prof) = resolved_profile {
                evaluate_payload_checks(prof, &active_link.payload_checks)
            } else {
                vec![]
            };
            let payload_failed = payload_results.iter().any(|p| !p.passed);

            let ast_failed = findings.iter().any(|f| match cfg.project.fail_on.as_str() {
                "warning" => matches!(f.severity, Severity::Error | Severity::Warning),
                _ => matches!(f.severity, Severity::Error),
            });
            let passed = !ast_failed && !payload_failed;

            let report = CheckReport {
                passed,
                files_scanned,
                rules_evaluated,
                profile: resolved_profile.map(|p| p.id.to_string()),
                pedantic,
                suppressed_by_baseline,
                findings_count: findings.len(),
                findings,
                payload_results,
            };

            match format {
                OutputFormat::Json => {
                    let rendered = serde_json::to_string_pretty(&report)?;
                    if let Some(ref out_path) = output {
                        std::fs::write(out_path, format!("{rendered}\n"))?;
                    } else {
                        println!("{rendered}");
                    }
                }
                OutputFormat::Sarif => {
                    let failed_payloads: Vec<_> = report
                        .payload_results
                        .iter()
                        .filter(|p| !p.passed)
                        .collect();
                    let ent_org = {
                        let st = check_license_with_override(cli.license_key.as_deref());
                        st.claims.filter(|c| c.tier == crate::license::LicenseTier::Enterprise).map(|c| c.holder)
                    };
                    let sarif = to_sarif_with_org(&report.findings, &failed_payloads, budgets.as_deref(), ent_org.as_deref());
                    println!("{}", serde_json::to_string_pretty(&sarif)?);
                }
                OutputFormat::Text => {
                    println!(
                        "Gardawg Check [{}] | files={} | rules={} | profile={} | findings={} (baseline_suppressed={})",
                        if report.passed { "PASS" } else { "FAIL" },
                        report.files_scanned,
                        report.rules_evaluated,
                        report.profile.as_deref().unwrap_or("none"),
                        report.findings_count,
                        report.suppressed_by_baseline
                    );
                    for p in &report.payload_results {
                        println!("  [{}] {}: {}", if p.passed { "PASS" } else { "FAIL" }, p.name, p.reason);
                    }
                    for f in &report.findings {
                        println!(
                            "\n[{}] {} ({}:{}:{})",
                            f.tier.as_deref().unwrap_or("warn").to_uppercase(),
                            f.rule_id,
                            f.file,
                            f.start_line,
                            f.start_col
                        );
                        println!("  Message: {}", f.message);
                        if let Some(ref rem) = f.remediation {
                            println!("  Fix:     {rem}");
                        }
                        if let Some(ref hint) = f.suppression_hint {
                            println!("  Ignore:  {hint}");
                        }
                    }
                }
            }

            Ok(if report.passed {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }

        Commands::Profiles => {
            let profiles = all_profiles(custom_profiles).map_err(|e| anyhow::anyhow!(e))?;
            for p in profiles {
                println!(
                    "{:<20} | goodput={:>9.0} bps | MTU={:>4} B | header={:>2} B | base_lat={:>5.1} ms | SNR={:>5.1} dB",
                    p.id, p.effective_goodput_bps, p.max_payload_bytes, p.header_overhead_bytes, p.base_latency_ms, p.snr_db
                );
                println!("   {}", p.notes);
            }
            Ok(ExitCode::SUCCESS)
        }

        Commands::Budget { profile, bytes, hz } => {
            let prof = resolve_profile(&profile, custom_profiles).map_err(|e| anyhow::anyhow!(e))?;
            let rep = evaluate_payload(&prof, bytes, hz);
            println!("{}", serde_json::to_string_pretty(&rep)?);
            Ok(ExitCode::SUCCESS)
        }

        Commands::Proxy { listen, target, profile, seed, udp } => {
            let prof = resolve_profile(&profile, custom_profiles).map_err(|e| anyhow::anyhow!(e))?;
            let transport = if udp { ProxyTransport::Udp } else { ProxyTransport::Tcp };
            proxy::run_proxy(&listen, &target, prof, seed, transport)
                .await
                .map_err(|e| anyhow::anyhow!(e))?;
            Ok(ExitCode::SUCCESS)
        }

        Commands::Chaos { listen, upstream, seed, mode } => {
            let chaos_cfg = chaos::ChaosConfig {
                seed: seed.unwrap_or(cfg.resilience.seed),
                drop_rate: cfg.resilience.drop_rate,
                rate_429: cfg.resilience.rate_429,
                max_jitter_ms: cfg.resilience.max_jitter_ms,
                upstream: upstream.unwrap_or(cfg.resilience.upstream),
            };
            match mode {
                ChaosMode::Http => chaos::start_http_chaos_proxy(listen, chaos_cfg).await?,
                ChaosMode::Tcp => chaos::start_tcp_chaos_proxy(listen, chaos_cfg).await?,
            }
            Ok(ExitCode::SUCCESS)
        }

        Commands::Verify {
            cmd,
            profile,
            upstream,
            probe_path,
            duration,
            seed,
            udp,
            listen,
        } => {
            let report = run_verify(
                &workspace,
                VerifyOptions {
                    command: cmd,
                    profile,
                    custom_profiles: cli.profiles,
                    upstream,
                    probe_path,
                    duration_secs: duration,
                    seed: seed.unwrap_or(cfg.resilience.seed),
                    drop_rate: cfg.resilience.drop_rate,
                    rate_429: cfg.resilience.rate_429,
                    max_jitter_ms: cfg.resilience.max_jitter_ms,
                    udp,
                    listen,
                },
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(if report.passed {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }

        Commands::Resilience { seed, openapi } => {
            require_pro_with_key("Resilience Chaos Suite", cli.license_key.as_deref())
                .map_err(|e| anyhow::anyhow!(e))?;
            let opts = resilience::ResilienceOptions {
                upstream: cfg.resilience.upstream,
                seed: seed.unwrap_or(cfg.resilience.seed),
                drop_rate: cfg.resilience.drop_rate,
                rate_429: cfg.resilience.rate_429,
                max_jitter_ms: cfg.resilience.max_jitter_ms,
                openapi_spec: openapi.or(cfg.resilience.openapi_spec),
                keploy_cmd: cfg.resilience.keploy_cmd,
            };
            resilience::run_resilience_suite(&workspace, opts).await?;
            Ok(ExitCode::SUCCESS)
        }

        Commands::Gui { profile, listen, target, seed, udp } => {
            #[cfg(feature = "gui")]
            {
                let prof = resolve_profile(&profile, custom_profiles).map_err(|e| anyhow::anyhow!(e))?;
                let available = all_profiles(custom_profiles).map_err(|e| anyhow::anyhow!(e))?;
                gui::run_dashboard_with_profiles(prof, available, listen, target, seed, udp, cli.license_key.as_deref())
                    .map_err(|e| anyhow::anyhow!(e))?;
                Ok(ExitCode::SUCCESS)
            }
            #[cfg(not(feature = "gui"))]
            {
                let _ = (profile, listen, target, seed, udp);
                anyhow::bail!(
                    "GUI support is not compiled in this headless build. Run with: cargo run --features gui -- gui"
                );
            }
        }

        Commands::Fix {
            model,
            ollama_url,
            file,
            profile,
            max_files,
            dry_run,
        } => {
            let pid = profile.or_else(|| {
                if cfg.link.enabled { cfg.link.profile.clone() } else { None }
            });
            let resolved_profile = pid
                .as_deref()
                .map(|id| resolve_profile(id, custom_profiles))
                .transpose()
                .map_err(|e| anyhow::anyhow!(e))?;
            let clean = fix::run_fix(
                &workspace,
                &cfg,
                fix::FixOptions {
                    model: &model,
                    ollama_url: &ollama_url,
                    target_file: file.as_deref(),
                    link_profile: resolved_profile.as_ref(),
                    assumed_hz: cfg.link.assumed_hz,
                    max_files,
                    dry_run,
                },
            )
            .await?;
            Ok(if clean { ExitCode::SUCCESS } else { ExitCode::from(1) })
        }

        Commands::Mcp => {
            mcp::run_mcp_stdio(workspace, cli.profiles).await?;
            Ok(ExitCode::SUCCESS)
        }

        Commands::License => {
            let status = check_license_with_override(cli.license_key.as_deref());
            println!("{}", serde_json::to_string_pretty(&status)?);
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn default_install_dir() -> anyhow::Result<PathBuf> {
    if cfg!(windows) {
        let base = std::env::var_os("LOCALAPPDATA")
            .ok_or_else(|| anyhow::anyhow!("LOCALAPPDATA is not set"))?;
        Ok(PathBuf::from(base).join("Programs").join("gardawg"))
    } else {
        let home = std::env::var_os("HOME").ok_or_else(|| anyhow::anyhow!("HOME is not set"))?;
        Ok(PathBuf::from(home).join(".local").join("bin"))
    }
}

fn install_self(dir_override: Option<PathBuf>, no_path: bool) -> anyhow::Result<()> {
    let exe = std::env::current_exe()?;
    let exe_dir = exe
        .parent()
        .ok_or_else(|| anyhow::anyhow!("cannot determine executable directory"))?
        .to_path_buf();
    let dest_dir = match dir_override {
        Some(d) => d,
        None => default_install_dir()?,
    };
    std::fs::create_dir_all(&dest_dir)?;

    let same = |a: &std::path::Path, b: &std::path::Path| match (a.canonicalize(), b.canonicalize()) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    };

    let bin_name = if cfg!(windows) { "gardawg.exe" } else { "gardawg" };
    let dest_exe = dest_dir.join(bin_name);
    if same(&exe, &dest_exe) {
        eprintln!("Already running from {}; skipping binary copy.", dest_exe.display());
    } else {
        std::fs::copy(&exe, &dest_exe).map_err(|e| {
            anyhow::anyhow!("failed to copy binary to {} (is it running?): {e}", dest_exe.display())
        })?;
        eprintln!("Installed {}", dest_exe.display());
    }

    let lic_src = exe_dir.join("gardawg.lic");
    if lic_src.is_file() {
        let lic_dest = dest_dir.join("gardawg.lic");
        if !same(&lic_src, &lic_dest) {
            std::fs::copy(&lic_src, &lic_dest)?;
            eprintln!("Installed {}", lic_dest.display());
        }
    } else {
        eprintln!(
            "No gardawg.lic next to the binary; to activate a license later, place it at {}",
            dest_dir.join("gardawg.lic").display()
        );
    }

    if no_path {
        eprintln!("Skipped PATH update (--no-path).");
    } else {
        add_to_user_path(&dest_dir)?;
    }
    Ok(())
}

#[cfg(windows)]
fn add_to_user_path(dir: &std::path::Path) -> anyhow::Result<()> {
    let script = r#"$d = $env:GARDAWG_INSTALL_DIR; $p = [Environment]::GetEnvironmentVariable('Path','User'); if (-not $p) { $p = '' }; $parts = @($p -split ';' | Where-Object { $_ -ne '' }); if ($parts -notcontains $d) { [Environment]::SetEnvironmentVariable('Path', (($parts + $d) -join ';'), 'User'); 'added' } else { 'present' }"#;
    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .env("GARDAWG_INSTALL_DIR", dir)
        .output()?;
    if !out.status.success() {
        anyhow::bail!(
            "failed to update user PATH: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    match String::from_utf8_lossy(&out.stdout).trim() {
        "added" => eprintln!(
            "Added {} to your user PATH. Open a new terminal to pick it up.",
            dir.display()
        ),
        _ => eprintln!("{} is already on your user PATH.", dir.display()),
    }
    Ok(())
}

#[cfg(not(windows))]
fn add_to_user_path(dir: &std::path::Path) -> anyhow::Result<()> {
    use std::io::Write;
    let dir_s = dir.to_string_lossy().to_string();
    let on_path = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|x| x == dir))
        .unwrap_or(false);
    if on_path {
        eprintln!("{dir_s} is already on your PATH.");
        return Ok(());
    }
    let home = PathBuf::from(std::env::var_os("HOME").ok_or_else(|| anyhow::anyhow!("HOME is not set"))?);
    let mut targets = vec![home.join(".profile")];
    let zshrc = home.join(".zshrc");
    if zshrc.is_file() {
        targets.push(zshrc);
    }
    let line = format!("\n# added by gardawg install\nexport PATH=\"{dir_s}:$PATH\"\n");
    for f in targets {
        let existing = std::fs::read_to_string(&f).unwrap_or_default();
        if existing.contains(&dir_s) {
            continue;
        }
        let mut h = std::fs::OpenOptions::new().create(true).append(true).open(&f)?;
        h.write_all(line.as_bytes())?;
        eprintln!("Appended PATH export to {}. Open a new shell to pick it up.", f.display());
    }
    Ok(())
}