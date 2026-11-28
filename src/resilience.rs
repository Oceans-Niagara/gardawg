use crate::chaos::{serve_http_chaos_proxy, ChaosConfig};
use std::path::Path;
use tokio::net::TcpListener;
use tokio::process::Command;

pub struct ResilienceOptions {
    pub upstream: String,
    pub seed: u64,
    pub drop_rate: f64,
    pub rate_429: f64,
    pub max_jitter_ms: u64,
    pub openapi_spec: Option<String>,
    pub keploy_cmd: Option<String>,
}

pub async fn run_resilience_suite(workspace: &Path, mut opts: ResilienceOptions) -> anyhow::Result<()> {
    if opts.openapi_spec.is_none() {
        if let Some(found) = crate::config::detect_workspace(workspace).openapi_spec {
            eprintln!("Resilience: auto-detected OpenAPI spec '{found}'.");
            opts.openapi_spec = Some(found);
        }
    }
    let keploy_dir = workspace.join("keploy").is_dir();
    if opts.openapi_spec.is_none() && opts.keploy_cmd.is_none() {
        eprintln!("Resilience: nothing to run under chaos (seed {}).", opts.seed);
        if keploy_dir {
            eprintln!("  - Found a keploy/ folder, but no app command is configured. Set [resilience] keploy_cmd = \"<start your app>\" in gardawg.toml.");
        } else {
            eprintln!("  - No OpenAPI spec found (checked --openapi, [resilience] openapi_spec, and openapi.yaml/.yml/.json within 3 levels).");
            eprintln!("  - No keploy/ test folder found.");
        }
        eprintln!("  Example: gardawg resilience --openapi openapi.yaml   (requires `schemathesis` on PATH)");
        return Ok(());
    }
    if let Some(spec) = &opts.openapi_spec {
        eprintln!("Resilience: fuzzing OpenAPI spec '{spec}' via Schemathesis through the chaos proxy.");
    }
    if opts.keploy_cmd.is_some() {
        eprintln!("Resilience: replaying Keploy tests through the chaos proxy.");
    }
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_addr = listener.local_addr()?;
    let proxy_url = format!("http://{proxy_addr}");

    let cfg = ChaosConfig {
        seed: opts.seed,
        drop_rate: opts.drop_rate,
        rate_429: opts.rate_429,
        max_jitter_ms: opts.max_jitter_ms,
        upstream: opts.upstream.clone(),
    };

    let proxy_task = tokio::spawn(async move {
        let _ = serve_http_chaos_proxy(listener, cfg).await;
    });

    if let Some(spec) = &opts.openapi_spec {
        let status = Command::new("schemathesis")
            .args([
                "run",
                spec,
                "--url",
                &proxy_url,
                "--hypothesis-seed",
                &opts.seed.to_string(),
            ])
            .current_dir(workspace)
            .status()
            .await
            .map_err(|e| if e.kind() == std::io::ErrorKind::NotFound {
                anyhow::anyhow!("`schemathesis` not found on PATH ? install with: pip install schemathesis")
            } else {
                anyhow::anyhow!("Failed to run schemathesis: {e}")
            })?;

        if !status.success() {
            proxy_task.abort();
            anyhow::bail!("Schemathesis fuzzing failed under chaos seed {}", opts.seed);
        }
    }

    if let Some(app_cmd) = &opts.keploy_cmd {
        let status = Command::new("keploy")
            .args(["test", "-c", app_cmd, "--delay", "5"])
            .env("GARDAWG_PROXY_URL", &proxy_url)
            .current_dir(workspace)
            .status()
            .await?;

        if !status.success() {
            proxy_task.abort();
            anyhow::bail!("Keploy replay failed under chaos seed {}", opts.seed);
        }
    }

    proxy_task.abort();
    Ok(())
}
