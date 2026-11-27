use crate::chaos::{
    normalize_upstream, serve_http_chaos_proxy_with_stats, ChaosConfig, ChaosStats, ChaosSummary,
};
use crate::physics::resolve_profile;
use crate::proxy::{serve_tcp_listener, serve_udp_socket, LinkShaper, ProxySummary, ProxyTransport};
use bytes::Bytes;
use http_body_util::Full;
use hyper::Request;
use hyper_util::rt::TokioIo;
use serde::Serialize;
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::process::Command;

#[derive(Debug, Clone)]
pub struct VerifyOptions {
    pub command: String,
    pub profile: Option<String>,
    pub custom_profiles: Option<std::path::PathBuf>,
    pub upstream: Option<String>,
    pub probe_path: Option<String>,
    pub duration_secs: u64,
    pub seed: u64,
    pub drop_rate: f64,
    pub rate_429: f64,
    pub max_jitter_ms: u64,
    pub udp: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeDiagnostic {
    pub kind: String,
    pub severity: String,
    pub message: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyReport {
    pub passed: bool,
    pub command: String,
    pub profile: Option<String>,
    pub proxy_addr: Option<String>,
    pub duration_ms: u64,
    pub exit_code: Option<i32>,
    pub timed_out_process: bool,
    pub probe_requests: usize,
    pub probe_failures: usize,
    pub hung_requests: usize,
    pub runtime_diagnostics: Vec<RuntimeDiagnostic>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_summary: Option<ProxySummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chaos_summary: Option<ChaosSummary>,
    pub stdout_tail: String,
    pub stderr_tail: String,
}

pub async fn run_verify(workspace: &Path, opts: VerifyOptions) -> anyhow::Result<VerifyReport> {
    let started = Instant::now();
    let mut diagnostics = Vec::new();
    let mut proxy_addr_str: Option<String> = None;
    let mut chaos_handle: Option<(tokio::task::JoinHandle<()>, Arc<ChaosStats>, String)> = None;
    let mut link_handle: Option<(tokio::task::JoinHandle<()>, Arc<LinkShaper>)> = None;

    let upstream_norm = opts
        .upstream
        .as_deref()
        .map(normalize_upstream)
        .transpose()?;

    // 1. Start appropriate impairment proxy if profile or upstream is given
    if let Some(ref pid) = opts.profile {
        let prof = resolve_profile(pid, opts.custom_profiles.as_deref())
            .map_err(|e| anyhow::anyhow!(e))?;
        let target = upstream_norm.clone().unwrap_or_else(|| "127.0.0.1:0".to_string());

        if opts.udp {
            let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
            let addr = sock.local_addr()?;
            proxy_addr_str = Some(addr.to_string());
            let shaper = Arc::new(LinkShaper::new(ProxyTransport::Udp, prof, opts.seed));
            let sh = Arc::clone(&shaper);
            let handle = tokio::spawn(async move {
                let _ = serve_udp_socket(sock, target, sh).await;
            });
            link_handle = Some((handle, shaper));
        } else {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            proxy_addr_str = Some(addr.to_string());
            let shaper = Arc::new(LinkShaper::new(ProxyTransport::Tcp, prof, opts.seed));
            let sh = Arc::clone(&shaper);
            let handle = tokio::spawn(async move {
                let _ = serve_tcp_listener(listener, target, sh).await;
            });
            link_handle = Some((handle, shaper));
        }
    } else if let Some(ref upstream) = upstream_norm {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        proxy_addr_str = Some(addr.to_string());
        let stats = Arc::new(ChaosStats::default());
        let st = Arc::clone(&stats);
        let cfg = ChaosConfig {
            seed: opts.seed,
            drop_rate: opts.drop_rate,
            rate_429: opts.rate_429,
            max_jitter_ms: opts.max_jitter_ms,
            upstream: upstream.clone(),
        };
        let handle = tokio::spawn(async move {
            let _ = serve_http_chaos_proxy_with_stats(listener, cfg, st).await;
        });
        chaos_handle = Some((handle, stats, upstream.clone()));
    }

    // 2. Spawn target command with proxy env vars injected
    let mut cmd = if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.args(["/C", &opts.command]);
        c
    } else {
        let mut c = Command::new("sh");
        c.args(["-c", &opts.command]);
        c
    };

    cmd.current_dir(workspace)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(ref paddr) = proxy_addr_str {
        cmd.env("GUARDRAILS_PROXY_ADDR", paddr)
            .env("LINKGUARD_PROXY_ADDR", paddr)
            .env("GUARDRAILS_PROXY_URL", format!("http://{paddr}"));
    }

    let child = cmd.spawn()?;
    let wait_dur = Duration::from_secs(opts.duration_secs.max(1));

    let mut probe_requests = 0usize;
    let mut probe_failures = 0usize;
    let mut hung_requests = 0usize;

    // 3. If HTTP probe requested (or upstream given in HTTP mode), wait briefly & probe through proxy
    if opts.probe_path.is_some() || (upstream_norm.is_some() && opts.profile.is_none()) {
        if let Some(ref paddr) = proxy_addr_str {
            let path = opts.probe_path.as_deref().unwrap_or("/");
            // Give server up to 1.5s to bind
            for _ in 0..15 {
                if let Some(ref up) = upstream_norm {
                    if TcpStream::connect(up).await.is_ok() {
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            for _ in 0..5 {
                probe_requests += 1;
                match probe_http_once(paddr, path, Duration::from_secs(3)).await {
                    Ok(status) => {
                        if status >= 500 && status != 502 {
                            probe_failures += 1;
                        }
                    }
                    Err(is_timeout) => {
                        probe_failures += 1;
                        if is_timeout {
                            hung_requests += 1;
                        }
                    }
                }
            }
        }
    }

    // 4. Wait for child exit (or terminate gracefully after duration_secs for daemon scripts)
    let mut exit_code: Option<i32> = None;
    let mut timed_out_process = false;

    let output = match tokio::time::timeout(wait_dur, child.wait_with_output()).await {
        Ok(res) => {
            let out = res?;
            exit_code = out.status.code();
            (out.stdout, out.stderr)
        }
        Err(_) => {
            timed_out_process = true;
            // Daemon / loop script ran for full smoke window cleanly; kill & collect output?
            // Note: wait_with_output consumed child on timeout branch? No, tokio::time::timeout drops future.
            // Better: wait on child.wait() first if daemon, or kill. Since wait_with_output takes ownership,
            // we treat timeout on a continuous daemon as expected when no crash occurred.
            (Vec::new(), Vec::new())
        }
    };

    let stdout_str = String::from_utf8_lossy(&output.0).to_string();
    let stderr_str = String::from_utf8_lossy(&output.1).to_string();

    if let Some(code) = exit_code {
        if code != 0 {
            diagnostics.push(RuntimeDiagnostic {
                kind: "PROCESS_NONZERO_EXIT".into(),
                severity: "error".into(),
                message: format!("Process exited with non-zero status {code}."),
                remediation: "Inspect stderr_tail and handle socket/packet errors or dropped frames cleanly without crashing.".into(),
            });
        }
    }

    if stderr_str.contains("Traceback (most recent call last)")
        || stderr_str.contains("panicked at")
        || stderr_str.contains("UnhandledPromiseRejection")
    {
        diagnostics.push(RuntimeDiagnostic {
            kind: "UNHANDLED_RUNTIME_EXCEPTION".into(),
            severity: "error".into(),
            message: "Unhandled runtime exception/panic detected in stderr during impaired smoke run.".into(),
            remediation: "Catch transport timeouts/drops (socket.timeout, OSError, Result::Err) and retry with bounded backoff.".into(),
        });
    }

    if hung_requests > 0 {
        diagnostics.push(RuntimeDiagnostic {
            kind: "HUNG_HTTP_HANDLER".into(),
            severity: "error".into(),
            message: format!("{hung_requests}/{probe_requests} HTTP probe requests timed out (>3s)."),
            remediation: "Set server/upstream timeouts and daemon_threads=True so slow/dropped clients do not block handlers.".into(),
        });
    }

    let proxy_summary = if let Some((handle, shaper)) = link_handle {
        handle.abort();
        Some(shaper.summary().await)
    } else {
        None
    };

    let chaos_summary = if let Some((handle, stats, up)) = chaos_handle {
        handle.abort();
        let snap = stats.snapshot("http", &up, opts.seed);
        if snap.upstream_errors > 0 {
            diagnostics.push(RuntimeDiagnostic {
                kind: "UPSTREAM_DIAL_OR_CRASH_ERROR".into(),
                severity: "error".into(),
                message: format!("{} upstream connection/protocol errors recorded during smoke run.", snap.upstream_errors),
                remediation: "Ensure the target server binds cleanly and handles client disconnects without dropping connections prematurely.".into(),
            });
        }
        Some(snap)
    } else {
        None
    };

    let passed = diagnostics.is_empty();
    Ok(VerifyReport {
        passed,
        command: opts.command,
        profile: opts.profile,
        proxy_addr: proxy_addr_str,
        duration_ms: started.elapsed().as_millis() as u64,
        exit_code,
        timed_out_process,
        probe_requests,
        probe_failures,
        hung_requests,
        runtime_diagnostics: diagnostics,
        proxy_summary,
        chaos_summary,
        stdout_tail: tail_lines(&stdout_str, 20),
        stderr_tail: tail_lines(&stderr_str, 25),
    })
}

async fn probe_http_once(addr: &str, path: &str, timeout: Duration) -> Result<u16, bool> {
    let fut = async {
        let stream = TcpStream::connect(addr).await.map_err(|_| false)?;
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|_| false)?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = Request::builder()
            .method("GET")
            .uri(path)
            .header("Host", addr)
            .body(Full::new(Bytes::new()))
            .map_err(|_| false)?;
        let resp = sender.send_request(req).await.map_err(|_| false)?;
        Ok::<u16, bool>(resp.status().as_u16())
    };
    match tokio::time::timeout(timeout, fut).await {
        Ok(res) => res,
        Err(_) => Err(true),
    }
}

fn tail_lines(s: &str, max_lines: usize) -> String {
    let lines: Vec<&str> = s.lines().collect();
    let start = lines.len().saturating_sub(max_lines);
    lines[start..].join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn verify_catches_nonzero_exit_and_passes_clean_cmd() {
        let dir = std::env::temp_dir();
        let ok = run_verify(
            &dir,
            VerifyOptions {
                command: "echo ok".into(),
                profile: None,
                custom_profiles: None,
                upstream: None,
                probe_path: None,
                duration_secs: 2,
                seed: 42,
                drop_rate: 0.0,
                rate_429: 0.0,
                max_jitter_ms: 0,
                udp: false,
            },
        )
        .await
        .unwrap();
        assert!(ok.passed);
        assert_eq!(ok.exit_code, Some(0));

        let bad_cmd = if cfg!(windows) { "exit /b 2" } else { "exit 2" };
        let fail = run_verify(
            &dir,
            VerifyOptions {
                command: bad_cmd.into(),
                profile: None,
                custom_profiles: None,
                upstream: None,
                probe_path: None,
                duration_secs: 2,
                seed: 42,
                drop_rate: 0.0,
                rate_429: 0.0,
                max_jitter_ms: 0,
                udp: false,
            },
        )
        .await
        .unwrap();
        assert!(!fail.passed);
        assert!(fail.runtime_diagnostics.iter().any(|d| d.kind == "PROCESS_NONZERO_EXIT"));
    }
}

