use crate::physics::PayloadCheckRule;
use ignore::WalkBuilder;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

pub const DEFAULT_LINK_PROFILE: &str = "wifi-24g-congested";
pub const BUILTIN_LINK_PROFILE_IDS: &[&str] =
    &["lora-sf12", "ble-1m", "wifi-24g-congested", "leo-sat", "uart-9600"];

pub fn link_profile_tip(profile: &str) -> String {
    format!(
        "Tip: link profile is \"{profile}\". Switch it via `profile = \"...\"` under [link] in gardawg.toml ({}) or re-run init with --link-profile <id>.",
        BUILTIN_LINK_PROFILE_IDS.join(" | ")
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Profile {
    #[default]
    General,
    Fintech,
    Frontend,
    WebApi,
    Embedded,
}

impl Profile {
    pub fn as_str(self) -> &'static str {
        match self {
            Profile::General => "general",
            Profile::Fintech => "fintech",
            Profile::Frontend => "frontend",
            Profile::WebApi => "web-api",
            Profile::Embedded => "embedded",
        }
    }

    pub fn default_disabled_rules(self) -> Vec<&'static str> {
        match self {
            Profile::General | Profile::Frontend => vec!["GR001", "GR003"],
            Profile::WebApi => vec!["GR001"],
            Profile::Fintech | Profile::Embedded => vec![],
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct GardawgConfig {
    pub project: ProjectConfig,
    pub ast: AstConfig,
    pub gate: GateConfig,
    pub link: LinkConfig,
    pub resilience: ResilienceConfig,
    pub sync: SyncConfig,
    pub rules: RulesConfig,
    pub agents: AgentsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProjectConfig {
    pub name: String,
    pub profile: Profile,
    pub fail_on: String, // "error" | "warning"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AstConfig {
    pub enabled: bool,
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GateConfig {
    pub rust: bool,
    pub typescript: bool,
    pub python: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LinkConfig {
    pub enabled: bool,
    pub profile: Option<String>,
    pub assumed_hz: f64,
    pub fail_on: String, // "none" | "critical" | "high" | "medium"
    pub max_diagnostics: Option<usize>,
    pub paths: Vec<String>,
    #[serde(default)]
    pub payload_checks: Vec<PayloadCheckRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ResilienceConfig {
    pub upstream: String,
    pub seed: u64,
    pub drop_rate: f64,
    pub rate_429: f64,
    pub max_jitter_ms: u64,
    pub openapi_spec: Option<String>,
    pub keploy_cmd: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SyncConfig {
    pub agents_md: bool,
    pub mcp_json: bool,
    pub opencode_json: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RulesConfig {
    pub disabled: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentsConfig {
    pub custom_rules: Vec<String>,
}

impl Default for ProjectConfig {
    fn default() -> Self {
        Self {
            name: "app".to_string(),
            profile: Profile::General,
            fail_on: "error".to_string(),
        }
    }
}

impl Default for AstConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            exclude: vec![
                "target/**".to_string(),
                "node_modules/**".to_string(),
                ".venv/**".to_string(),
                "dist/**".to_string(),
            ],
        }
    }
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            rust: true,
            typescript: true,
            python: true,
        }
    }
}

impl Default for LinkConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            profile: None,
            assumed_hz: 10.0,
            fail_on: "high".to_string(),
            max_diagnostics: None,
            paths: vec![".".to_string()],
            payload_checks: Vec::new(),
        }
    }
}

impl Default for ResilienceConfig {
    fn default() -> Self {
        Self {
            upstream: "127.0.0.1:8080".to_string(),
            seed: 42,
            drop_rate: 0.02,
            rate_429: 0.05,
            max_jitter_ms: 150,
            openapi_spec: None,
            keploy_cmd: None,
        }
    }
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            agents_md: true,
            mcp_json: true,
            opencode_json: true,
        }
    }
}

impl GardawgConfig {
    pub fn load(workspace: &Path, override_path: Option<&Path>) -> anyhow::Result<Self> {
        let candidate = match override_path {
            Some(p) => p.to_path_buf(),
            None => workspace.join("gardawg.toml"),
        };

        if !candidate.exists() {
            return Ok(Self::default());
        }

        let raw = fs::read_to_string(&candidate)?;
        let mut cfg: Self = toml::from_str(raw.trim_start_matches('\u{feff}'))?;
        if cfg.link.profile.is_some() && !raw.contains("[link]") {
            cfg.link.enabled = true;
        }
        Ok(cfg)
    }

    pub fn is_rule_enabled(&self, rule_id: &str) -> bool {
        let upper = rule_id.to_ascii_uppercase();
        if upper == "GR000" || upper.starts_with("GR000-") {
            return true;
        }
        !self.rules.disabled.iter().any(|entry| {
            let pat = entry.trim().to_ascii_uppercase();
            !pat.is_empty() && (upper == pat || upper.starts_with(&format!("{pat}-")))
        })
    }
}

#[derive(Debug, Clone)]
pub struct DetectedWorkspace {
    pub profile: Profile,
    pub gate: GateConfig,
    pub openapi_spec: Option<String>,
    pub has_embedded_signals: bool,
}

pub fn detect_workspace(workspace: &Path) -> DetectedWorkspace {
    let mut has_rust = false;
    let mut has_ts = false;
    let mut has_tsx = false;
    let mut has_py = false;
    let mut has_cpp = false;
    let mut openapi_spec: Option<String> = None;
    let mut manifest_corpus = String::new();
    let mut file_names_corpus = String::new();

    if let Some(name) = workspace.file_name().and_then(|n| n.to_str()) {
        file_names_corpus.push_str(&name.to_ascii_lowercase());
        file_names_corpus.push('\n');
    }

    for entry in WalkBuilder::new(workspace)
        .max_depth(Some(3))
        .hidden(true)
        .git_ignore(true)
        .build()
        .flatten()
    {
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        let path = entry.path();
        let Some(fname) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let lower_name = fname.to_ascii_lowercase();
        file_names_corpus.push_str(&lower_name);
        file_names_corpus.push('\n');

        match lower_name.as_str() {
            "cargo.toml" => has_rust = true,
            "tsconfig.json" => has_ts = true,
            "pyproject.toml" | "requirements.txt" | "setup.py" => has_py = true,
            "platformio.ini" | "cmakelists.txt" => has_cpp = true,
            "openapi.yaml" | "openapi.yml" | "openapi.json" if openapi_spec.is_none() => {
                openapi_spec = path
                    .strip_prefix(workspace)
                    .ok()
                    .map(|p| p.to_string_lossy().replace('\\', "/"));
            }
            _ => {}
        }

        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            match ext.to_ascii_lowercase().as_str() {
                "rs" => has_rust = true,
                "ts" => has_ts = true,
                "tsx" => {
                    has_ts = true;
                    has_tsx = true;
                }
                "py" => has_py = true,
                "c" | "cpp" | "cc" | "h" | "hpp" | "ino" => has_cpp = true,
                _ => {}
            }
        }

        if matches!(
            lower_name.as_str(),
            "cargo.toml" | "package.json" | "pyproject.toml" | "requirements.txt" | "setup.py" | "platformio.ini"
        ) {
            if let Ok(raw) = fs::read_to_string(path) {
                let lower_raw = raw.to_ascii_lowercase();
                if lower_name == "package.json" && lower_raw.contains("typescript") {
                    has_ts = true;
                }
                manifest_corpus.push_str(&lower_raw);
                manifest_corpus.push('\n');
            }
        }
    }

    let gate = if !has_rust && !has_ts && !has_py {
        GateConfig::default()
    } else {
        GateConfig {
            rust: has_rust,
            typescript: has_ts,
            python: has_py,
        }
    };

    let fintech_signals = [
        "stripe", "paypal", "adyen", "braintree", "plaid", "rust_decimal",
        "decimal.js", "big.js", "billing", "invoice", "ledger", "payment", "checkout",
    ];
    let embedded_signals = [
        "lora", "ble", "gatt", "serial", "pyserial", "arduino", "esp32", "stm32",
        "embedded-hal", "embassy", "freertos", "telemetry", "sensor", "radio", "uart",
    ];
    let web_api_signals = [
        "axum", "actix-web", "rocket", "tonic", "express", "fastify", "hono",
        "@nestjs/", "koa", "fastapi", "flask", "django", "starlette", "uvicorn", "aiohttp",
    ];
    let frontend_signals = [
        "\"react\"", "\"next\"", "\"vite\"", "\"vue\"", "\"svelte\"",
        "\"@angular/core\"", "\"astro\"", "\"solid-js\"",
    ];

    let combined = format!("{manifest_corpus}\n{file_names_corpus}");
    let has_embedded = has_cpp || embedded_signals.iter().any(|kw| combined.contains(kw));

    let profile = if fintech_signals.iter().any(|kw| combined.contains(kw)) {
        Profile::Fintech
    } else if has_embedded {
        Profile::Embedded
    } else if openapi_spec.is_some() || web_api_signals.iter().any(|kw| manifest_corpus.contains(kw)) {
        Profile::WebApi
    } else if !gate.rust
        && !gate.python
        && (has_tsx || frontend_signals.iter().any(|kw| manifest_corpus.contains(kw)))
    {
        Profile::Frontend
    } else {
        Profile::General
    };

    DetectedWorkspace {
        profile,
        gate,
        openapi_spec,
        has_embedded_signals: has_embedded,
    }
}

pub fn render_toml_for_init(
    project_name: &str,
    detected: &DetectedWorkspace,
    profile_override: Option<Profile>,
    enable_link: bool,
    link_profile: Option<&str>,
) -> String {
    let profile = profile_override.unwrap_or(detected.profile);
    let link_on = enable_link || link_profile.is_some() || profile == Profile::Embedded || detected.has_embedded_signals;
    let disabled = profile.default_disabled_rules();
    let rules_line = if disabled.is_empty() {
        "# disabled = [\"GR001\", \"GR003\"]".to_string()
    } else {
        let joined = disabled
            .iter()
            .map(|r| format!("\"{r}\""))
            .collect::<Vec<_>>()
            .join(", ");
        format!("disabled = [{joined}]")
    };
    let openapi_line = match &detected.openapi_spec {
        Some(spec) => format!("openapi_spec = \"{spec}\""),
        None => "# openapi_spec = \"openapi.yaml\"".to_string(),
    };

    let chosen_link = link_profile.unwrap_or(DEFAULT_LINK_PROFILE);
    let link_block = if link_on {
        format!(r#"[link]
enabled = true
profile = "{chosen_link}" # "lora-sf12" | "ble-1m" | "wifi-24g-congested" | "leo-sat" | "uart-9600"
assumed_hz = 1.0
fail_on = "high" # "none" | "critical" | "high" | "medium"
paths = ["."]

# [[link.payload_checks]]
# name = "telemetry_frame"
# bytes = 20
# hz = 0.25
# require_single_mtu = true"#)
    } else {
        r#"[link]
enabled = false
# profile = "lora-sf12"
# assumed_hz = 1.0
# fail_on = "high"
# paths = ["."]"#.to_string()
    };

    format!(
        r#"[project]
name = "{project_name}"
profile = "{}" # "general" | "fintech" | "frontend" | "web-api" | "embedded"
fail_on = "error" # "error" | "warning"

[ast]
enabled = true
exclude = ["target/**", "node_modules/**", ".venv/**", "dist/**"]

[gate]
rust = {}
typescript = {}
python = {}

[rules]
{rules_line}

{link_block}

[agents]
# custom_rules = ["Validate all CLI flags and exit non-zero on invalid input."]

[resilience]
upstream = "127.0.0.1:8080"
seed = 42
drop_rate = 0.02
rate_429 = 0.05
max_jitter_ms = 150
{openapi_line}
# keploy_cmd = "node dist/server.js"

[sync]
agents_md = true
mcp_json = true
opencode_json = true
"#,
        profile.as_str(),
        detected.gate.rust,
        detected.gate.typescript,
        detected.gate.python,
    )
}

pub fn render_starter_profiles_toml() -> &'static str {
    r#"# Custom physical-layer RF / serial link profiles for Gardawg Pro & Team
# Usage: gardawg --profiles profiles.toml check --profile custom-mesh
# All 11 [[profile]] fields are shown below:

[[profile]]
id = "custom-mesh"
name = "Custom 915MHz Tactical Mesh"
bandwidth_hz = 500000
snr_db = 6.0
effective_goodput_bps = 15000
max_payload_bytes = 128
header_overhead_bytes = 14
base_latency_ms = 25.0
jitter_ms = 3.5
queue_capacity_bytes = 2048
notes = "Custom 915MHz tactical mesh profile"
"#
}

pub fn render_starter_budgets_toml() -> &'static str {
    r#"# Standalone physical-layer link budget policy (optional when using [link] in gardawg.toml)
profile = "wifi-24g-congested"
assumed_hz = 1.0
fail_on = "high"
paths = ["."]

[[payload_checks]]
name = "telemetry_frame"
bytes = 20
hz = 0.25
require_single_mtu = true
"#
}
