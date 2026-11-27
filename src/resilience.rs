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

pub async fn run_resilience_suite(workspace: &Path, opts: ResilienceOptions) -> anyhow::Result<()> {
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
            .await?;

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
