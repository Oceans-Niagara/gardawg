use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Clone, Debug)]
pub struct ChaosConfig {
    pub seed: u64,
    pub drop_rate: f64,
    pub rate_429: f64,
    pub max_jitter_ms: u64,
    pub upstream: String,
}

#[derive(Default)]
pub struct ChaosStats {
    pub requests_in: AtomicU64,
    pub faults_injected: AtomicU64,
    pub upstream_errors: AtomicU64,
    pub total_latency_ms: AtomicU64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChaosSummary {
    pub mode: String,
    pub upstream: String,
    pub seed: u64,
    pub requests_in: u64,
    pub faults_injected: u64,
    pub upstream_errors: u64,
    pub avg_latency_ms: f64,
}

impl ChaosStats {
    pub fn snapshot(&self, mode: &str, upstream: &str, seed: u64) -> ChaosSummary {
        let reqs = self.requests_in.load(Ordering::Relaxed);
        let total_ms = self.total_latency_ms.load(Ordering::Relaxed);
        let avg = if reqs > 0 {
            ((total_ms as f64 / reqs as f64) * 100.0).round() / 100.0
        } else {
            0.0
        };
        ChaosSummary {
            mode: mode.to_string(),
            upstream: upstream.to_string(),
            seed,
            requests_in: reqs,
            faults_injected: self.faults_injected.load(Ordering::Relaxed),
            upstream_errors: self.upstream_errors.load(Ordering::Relaxed),
            avg_latency_ms: avg,
        }
    }
}

/// Strip leading `http://` / `https://` and trailing slashes/paths so host:port connects cleanly.
pub fn normalize_upstream(raw: &str) -> anyhow::Result<String> {
    let trimmed = raw.trim();
    let no_scheme = if let Some(rest) = trimmed.strip_prefix("http://") {
        rest
    } else if let Some(rest) = trimmed.strip_prefix("https://") {
        rest
    } else if trimmed.to_ascii_lowercase().starts_with("http://") {
        &trimmed[7..]
    } else if trimmed.to_ascii_lowercase().starts_with("https://") {
        &trimmed[8..]
    } else {
        trimmed
    };
    let host_port = no_scheme.split('/').next().unwrap_or(no_scheme).trim();
    if host_port.is_empty() || !host_port.contains(':') {
        anyhow::bail!(
            "Invalid --upstream '{raw}': expected host:port (e.g. 127.0.0.1:8080 or http://localhost:8080)"
        );
    }
    Ok(host_port.to_string())
}

/// Resolve hostnames (like `localhost:8080`) via OS DNS / ToSocketAddrs instead of strict IP parsing.
pub async fn resolve_upstream_addrs(upstream: &str) -> anyhow::Result<Vec<SocketAddr>> {
    let normalized = normalize_upstream(upstream)?;
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&normalized)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to resolve upstream '{normalized}': {e}"))?
        .collect();
    if addrs.is_empty() {
        anyhow::bail!("Upstream '{normalized}' resolved to zero socket addresses");
    }
    Ok(addrs)
}

pub async fn start_http_chaos_proxy(listen: SocketAddr, mut cfg: ChaosConfig) -> anyhow::Result<()> {
    cfg.upstream = normalize_upstream(&cfg.upstream)?;
    let _ = resolve_upstream_addrs(&cfg.upstream).await?;
    let listener = TcpListener::bind(listen).await?;
    let stats = Arc::new(ChaosStats::default());
    eprintln!(
        "[guardrails http chaos] {} -> {} (seed={}). Press Ctrl-C to stop.",
        listen, cfg.upstream, cfg.seed
    );
    let summary = serve_http_chaos_proxy_until_ctrl_c(listener, cfg, stats).await?;
    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}

pub async fn serve_http_chaos_proxy(listener: TcpListener, mut cfg: ChaosConfig) -> anyhow::Result<()> {
    cfg.upstream = normalize_upstream(&cfg.upstream)?;
    let stats = Arc::new(ChaosStats::default());
    serve_http_chaos_proxy_inner(listener, cfg, stats).await
}

pub async fn serve_http_chaos_proxy_with_stats(
    listener: TcpListener,
    mut cfg: ChaosConfig,
    stats: Arc<ChaosStats>,
) -> anyhow::Result<()> {
    cfg.upstream = normalize_upstream(&cfg.upstream)?;
    serve_http_chaos_proxy_inner(listener, cfg, stats).await
}

async fn serve_http_chaos_proxy_until_ctrl_c(
    listener: TcpListener,
    cfg: ChaosConfig,
    stats: Arc<ChaosStats>,
) -> anyhow::Result<ChaosSummary> {
    let seed = cfg.seed;
    let upstream = cfg.upstream.clone();
    let stats_run = Arc::clone(&stats);

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        res = serve_http_chaos_proxy_inner(listener, cfg, stats_run) => {
            res?;
        }
    }
    Ok(stats.snapshot("http", &upstream, seed))
}

async fn serve_http_chaos_proxy_inner(
    listener: TcpListener,
    cfg: ChaosConfig,
    stats: Arc<ChaosStats>,
) -> anyhow::Result<()> {
    let counter = Arc::new(AtomicU64::new(0));

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let cfg = cfg.clone();
        let counter = counter.clone();
        let stats = Arc::clone(&stats);

        tokio::spawn(async move {
            let service = service_fn(move |req: Request<hyper::body::Incoming>| {
                let cfg = cfg.clone();
                let seq = counter.fetch_add(1, Ordering::Relaxed);
                let stats = Arc::clone(&stats);

                async move {
                    stats.requests_in.fetch_add(1, Ordering::Relaxed);
                    let mut rng = ChaCha8Rng::seed_from_u64(cfg.seed ^ seq);

                    if cfg.max_jitter_ms > 0 {
                        let delay = rng.gen_range(0..=cfg.max_jitter_ms);
                        stats.total_latency_ms.fetch_add(delay, Ordering::Relaxed);
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                    }

                    if rng.gen_bool(cfg.rate_429.clamp(0.0, 1.0)) {
                        stats.faults_injected.fetch_add(1, Ordering::Relaxed);
                        return Ok::<_, hyper::Error>(
                            Response::builder()
                                .status(StatusCode::TOO_MANY_REQUESTS)
                                .header("Retry-After", "1")
                                .body(Full::new(Bytes::from("Injected deterministic 429")))
                                .unwrap(),
                        );
                    }

                    if rng.gen_bool(cfg.drop_rate.clamp(0.0, 1.0)) {
                        stats.faults_injected.fetch_add(1, Ordering::Relaxed);
                        return Ok(Response::builder()
                            .status(StatusCode::BAD_GATEWAY)
                            .body(Full::new(Bytes::from("Injected deterministic chaos drop")))
                            .unwrap());
                    }

                    forward_http(&cfg.upstream, req, &stats).await
                }
            });

            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                tracing::debug!("HTTP chaos connection closed: {err}");
            }
        });
    }
}

async fn forward_http(
    upstream: &str,
    req: Request<hyper::body::Incoming>,
    stats: &ChaosStats,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let stream = match TcpStream::connect(upstream).await {
        Ok(s) => s,
        Err(err) => {
            stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
            let msg = format!("Upstream dial to '{upstream}' failed: {err}");
            tracing::warn!("{msg}");
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from(msg)))
                .unwrap());
        }
    };

    let io = TokioIo::new(stream);
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok(pair) => pair,
        Err(err) => {
            stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
            let msg = format!("Upstream HTTP handshake to '{upstream}' failed: {err}");
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from(msg)))
                .unwrap());
        }
    };

    tokio::spawn(async move {
        if let Err(err) = conn.await {
            tracing::debug!("Upstream connection error: {err}");
        }
    });

    match sender.send_request(req).await {
        Ok(resp) => {
            let (parts, body) = resp.into_parts();
            let collected = body.collect().await?.to_bytes();
            Ok(Response::from_parts(parts, Full::new(collected)))
        }
        Err(err) => {
            stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
            let msg = format!("Upstream request to '{upstream}' failed: {err}");
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from(msg)))
                .unwrap())
        }
    }
}

pub async fn start_tcp_chaos_proxy(listen: SocketAddr, mut cfg: ChaosConfig) -> anyhow::Result<()> {
    cfg.upstream = normalize_upstream(&cfg.upstream)?;
    let _ = resolve_upstream_addrs(&cfg.upstream).await?;
    let listener = TcpListener::bind(listen).await?;
    let stats = Arc::new(ChaosStats::default());
    eprintln!(
        "[guardrails tcp chaos] {} -> {} (seed={}). Press Ctrl-C to stop.",
        listen, cfg.upstream, cfg.seed
    );

    let seed = cfg.seed;
    let upstream = cfg.upstream.clone();
    let stats_run = Arc::clone(&stats);
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        res = serve_tcp_chaos_proxy_inner(listener, cfg, stats_run) => {
            res?;
        }
    }
    let summary = stats.snapshot("tcp", &upstream, seed);
    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}

pub async fn serve_tcp_chaos_proxy(listener: TcpListener, mut cfg: ChaosConfig) -> anyhow::Result<()> {
    cfg.upstream = normalize_upstream(&cfg.upstream)?;
    let stats = Arc::new(ChaosStats::default());
    serve_tcp_chaos_proxy_inner(listener, cfg, stats).await
}

async fn serve_tcp_chaos_proxy_inner(
    listener: TcpListener,
    cfg: ChaosConfig,
    stats: Arc<ChaosStats>,
) -> anyhow::Result<()> {
    let counter = Arc::new(AtomicU64::new(0));

    loop {
        let (client, _) = listener.accept().await?;
        let cfg = cfg.clone();
        let seq = counter.fetch_add(1, Ordering::Relaxed);
        let stats = Arc::clone(&stats);

        tokio::spawn(async move {
            stats.requests_in.fetch_add(1, Ordering::Relaxed);
            let mut rng = ChaCha8Rng::seed_from_u64(cfg.seed ^ seq);
            if rng.gen_bool(cfg.drop_rate.clamp(0.0, 1.0)) {
                stats.faults_injected.fetch_add(1, Ordering::Relaxed);
                drop(client);
                return;
            }

            let Ok(upstream) = TcpStream::connect(&cfg.upstream).await else {
                stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
                drop(client);
                return;
            };

            let (c_read, c_write) = client.into_split();
            let (u_read, u_write) = upstream.into_split();

            let c_to_u = pump_tcp_with_chaos(
                c_read,
                u_write,
                cfg.seed ^ seq ^ 0xA11C_E001,
                cfg.max_jitter_ms,
                cfg.drop_rate,
                &stats,
            );
            let u_to_c = pump_tcp_with_chaos(
                u_read,
                c_write,
                cfg.seed ^ seq ^ 0xB0B0_0002,
                cfg.max_jitter_ms,
                cfg.drop_rate,
                &stats,
            );

            let _ = tokio::join!(c_to_u, u_to_c);
        });
    }
}

async fn pump_tcp_with_chaos<R, W>(
    mut reader: R,
    mut writer: W,
    seed: u64,
    max_jitter_ms: u64,
    drop_rate: f64,
    stats: &ChaosStats,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut buf = vec![0u8; 8192];

    loop {
        match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if max_jitter_ms > 0 {
                    let delay = rng.gen_range(0..=max_jitter_ms);
                    stats.total_latency_ms.fetch_add(delay, Ordering::Relaxed);
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
                if rng.gen_bool((drop_rate * 0.25).clamp(0.0, 1.0)) {
                    stats.faults_injected.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                if writer.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        }
    }
    let _ = writer.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_http_and_https_upstream_schemes() {
        assert_eq!(normalize_upstream("http://127.0.0.1:8080").unwrap(), "127.0.0.1:8080");
        assert_eq!(normalize_upstream("https://localhost:8443/api").unwrap(), "localhost:8443");
        assert_eq!(normalize_upstream("127.0.0.1:9000").unwrap(), "127.0.0.1:9000");
        assert!(normalize_upstream("http://only-host").is_err());
    }

    #[tokio::test]
    async fn resolves_localhost_via_to_socket_addrs() {
        let addrs = resolve_upstream_addrs("http://localhost:8080").await.unwrap();
        assert!(!addrs.is_empty());
    }
}
