mod analyzer;
mod budgets;
mod chaos;
mod config;
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
use crate::sarif::{to_sarif, CheckReport, Severity};
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
    about = "Unified deterministic AI gardawg, physical-layer analyzer, and chaos/impairment proxy"
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
    command: Commands,
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
        #[arg(long)]
        link: bool,
    },

    /// Sync AGENTS.md, .mcp.json, and opencode.json from gardawg.toml
    Sync {
        #[arg(long)]
        force: bool,
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
        #[arg(short, long)]
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
        #[arg(short, long)]
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

    match cli.command {
        Commands::Init { force, profile, link } => {
            let cfg_path = workspace.join("gardawg.toml");
            if cfg_path.exists() && !force {
                anyhow::bail!("{} already exists (pass --force to overwrite)", cfg_path.display());
            }
            let name = workspace.file_name().and_then(|n| n.to_str()).unwrap_or("app");
            let detected = config::detect_workspace(&workspace);
            let chosen_profile = profile.unwrap_or(detected.profile);
            std::fs::write(
                &cfg_path,
                config::render_toml_for_init(name, &detected, profile, link),
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
            Ok(ExitCode::SUCCESS)
        }

        Commands::Sync { force } => {
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
        } => {
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
                apply_baseline_ratchet(findings, baseline.as_deref())?;

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
                    println!("{}", serde_json::to_string_pretty(&report)?);
                }
                OutputFormat::Sarif => {
                    let failed_payloads: Vec<_> = report
                        .payload_results
                        .iter()
                        .filter(|p| !p.passed)
                        .collect();
                    let sarif = to_sarif(&report.findings, &failed_payloads, budgets.as_deref());
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
                gui::run_dashboard(prof, listen, target, seed, udp)
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
