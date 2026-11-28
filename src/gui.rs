use crate::license::{current_unix_secs, require_pro_with_key};
use crate::physics::{all_profiles, evaluate_payload, shannon_capacity_bps, LinkProfile};
use crate::proxy::{
    run_proxy_live, spawn_metrics_sampler, LinkShaper, PacketDecision, ProxyMetrics, ProxyTransport,
};
use eframe::egui;
use egui_plot::{Legend, Line, Plot, PlotPoints};
use std::collections::VecDeque;
use std::fs;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

const MAX_PLOT_SAMPLES: usize = 300;

pub fn run_dashboard(
    initial_profile: LinkProfile,
    listen: String,
    target: Option<String>,
    seed: u64,
    udp: bool,
) -> Result<(), String> {
    let available = all_profiles(None).unwrap_or_else(|_| vec![initial_profile.clone()]);
    run_dashboard_with_profiles(initial_profile, available, listen, target, seed, udp, None)
}

pub fn run_dashboard_with_profiles(
    initial_profile: LinkProfile,
    mut available_profiles: Vec<LinkProfile>,
    listen: String,
    target: Option<String>,
    seed: u64,
    udp: bool,
    cli_key: Option<&str>,
) -> Result<(), String> {
    let claims = require_pro_with_key("Pro Desktop Dashboard", cli_key)?;

    if !available_profiles.iter().any(|p| p.id == initial_profile.id) {
        available_profiles.insert(0, initial_profile.clone());
    }
    let selected_profile_idx = available_profiles
        .iter()
        .position(|p| p.id == initial_profile.id)
        .unwrap_or(0);

    let transport = if udp { ProxyTransport::Udp } else { ProxyTransport::Tcp };
    let (metrics_tx, metrics_rx) = watch::channel(ProxyMetrics::from_profile(&initial_profile));
    let (profile_tx, profile_rx) = watch::channel(initial_profile.clone());
    let shaper = Arc::new(LinkShaper::new(transport, initial_profile.clone(), seed));

    let synth_default_on = target.is_none();
    let (synth_tx, mut synth_rx) = watch::channel((synth_default_on, 64_usize, 5.0_f64));

    spawn_metrics_sampler(Arc::clone(&shaper), metrics_tx.clone(), profile_rx.clone());
    let proxy_err = Arc::new(std::sync::Mutex::new(None::<String>));
    let mut proxy_task: Option<tokio::task::JoinHandle<()>> = None;
    if let Some(target_addr) = target.clone() {
        let sh = Arc::clone(&shaper);
        let mtx = metrics_tx.clone();
        let prx = profile_rx.clone();
        let l_addr = listen.clone();
        let perr = Arc::clone(&proxy_err);
        proxy_task = Some(tokio::spawn(async move {
            if let Err(e) = run_proxy_live(&l_addr, &target_addr, sh, transport, mtx, prx).await {
                if let Ok(mut guard) = perr.lock() {
                    *guard = Some(format!("Proxy error: {e}"));
                }
            }
        }));
    }

    let synth_shaper = Arc::clone(&shaper);
    tokio::spawn(async move {
        loop {
            let (enabled, payload_bytes, hz) = *synth_rx.borrow();
            if !enabled {
                if synth_rx.changed().await.is_err() {
                    break;
                }
                continue;
            }
            let interval = Duration::from_secs_f64((1.0 / hz.max(0.1)).clamp(0.005, 5.0));
            tokio::select! {
                _ = tokio::time::sleep(interval) => {
                    let sh = Arc::clone(&synth_shaper);
                    tokio::spawn(async move {
                        if let PacketDecision::Forward { delay, wire_bytes } = sh.admit_and_shape(payload_bytes).await {
                            if !delay.is_zero() {
                                tokio::time::sleep(delay).await;
                            }
                            sh.release_queue(wire_bytes).await;
                        }
                    });
                }
                res = synth_rx.changed() => {
                    if res.is_err() { break; }
                }
            }
        }
    });

    let app = DashboardApp {
        holder: claims.holder,
        cli_key: cli_key.map(|s| s.to_string()),
        available_profiles,
        selected_profile_idx,
        profile: initial_profile,
        profile_tx,
        profile_rx,
        metrics_tx,
        metrics_rx,
        shaper,
        synth_tx,
        synth_enabled: synth_default_on,
        synth_bytes: 64,
        synth_hz: 5.0,
        live_mode: target.is_some(),
        listen_input: listen,
        target_input: target.clone().unwrap_or_else(|| "127.0.0.1:8080".to_string()),
        udp_mode: udp,
        proxy_task,
        proxy_err,
        history: VecDeque::with_capacity(MAX_PLOT_SAMPLES),
        full_capture: Vec::new(),
        status_msg: if let Some(t) = target {
            format!("Live proxy active -> {t}")
        } else {
            "Standalone Simulator active (use Mode switcher above to start a Live Proxy)".into()
        },
        last_timestamp: -1.0,
    };

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1160.0, 760.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Gardawg Pro Dashboard",
        options,
        Box::new(|_cc| Ok(Box::new(app))),
    )
    .map_err(|e| format!("GUI error: {e}"))
}

struct DashboardApp {
    holder: String,
    cli_key: Option<String>,
    available_profiles: Vec<LinkProfile>,
    selected_profile_idx: usize,
    profile: LinkProfile,
    profile_tx: watch::Sender<LinkProfile>,
    profile_rx: watch::Receiver<LinkProfile>,
    metrics_tx: watch::Sender<ProxyMetrics>,
    metrics_rx: watch::Receiver<ProxyMetrics>,
    shaper: Arc<LinkShaper>,
    synth_tx: watch::Sender<(bool, usize, f64)>,
    synth_enabled: bool,
    synth_bytes: usize,
    synth_hz: f64,
    live_mode: bool,
    listen_input: String,
    target_input: String,
    udp_mode: bool,
    proxy_task: Option<tokio::task::JoinHandle<()>>,
    proxy_err: Arc<std::sync::Mutex<Option<String>>>,
    history: VecDeque<ProxyMetrics>,
    full_capture: Vec<ProxyMetrics>,
    status_msg: String,
    last_timestamp: f64,
}

impl eframe::App for DashboardApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.request_repaint_after(Duration::from_millis(100));

        let latest = self.metrics_rx.borrow().clone();
        if latest.timestamp_s > self.last_timestamp {
            self.last_timestamp = latest.timestamp_s;
            if self.history.len() >= MAX_PLOT_SAMPLES {
                self.history.pop_front();
            }
            self.history.push_back(latest.clone());
            self.full_capture.push(latest.clone());
        }

        egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Gardawg Pro Dashboard");
                ui.separator();
                ui.label("Profile:");
                let current_label = self
                    .available_profiles
                    .get(self.selected_profile_idx)
                    .map(|p| p.id.as_ref())
                    .unwrap_or(self.profile.id.as_ref());
                let mut switched_to: Option<usize> = None;
                egui::ComboBox::from_label("")
                    .selected_text(current_label)
                    .show_ui(ui, |ui| {
                        for (idx, p) in self.available_profiles.iter().enumerate() {
                            let label = format!("{} — {}", p.id, p.name);
                            if ui.selectable_value(&mut self.selected_profile_idx, idx, label).clicked() {
                                switched_to = Some(idx);
                            }
                        }
                    });
                if let Some(idx) = switched_to {
                    if let Some(chosen) = self.available_profiles.get(idx) {
                        self.profile = chosen.clone();
                        let _ = self.profile_tx.send(self.profile.clone());
                        self.status_msg = format!("Switched link profile to {}", self.profile.id);
                    }
                }
                ui.separator();
                ui.label("Mode:");
                if ui.selectable_label(!self.live_mode, "Standalone Simulator").clicked() && self.live_mode {
                    if let Some(handle) = self.proxy_task.take() {
                        handle.abort();
                    }
                    self.live_mode = false;
                    self.synth_enabled = true;
                    let _ = self.synth_tx.send((true, self.synth_bytes, self.synth_hz));
                    self.status_msg = "Switched to Standalone Simulator".into();
                }
                if ui.selectable_label(self.live_mode, "Live Proxy").clicked() && !self.live_mode {
                    self.live_mode = true;
                    self.synth_enabled = false;
                    self.history.clear();
                    let _ = self.synth_tx.send((false, self.synth_bytes, self.synth_hz));
                    self.status_msg = "Live Proxy mode selected ? configure Listen/Target and click Start Proxy".into();
                }
                if let Ok(mut guard) = self.proxy_err.lock() {
                    if let Some(err_msg) = guard.take() {
                        self.status_msg = err_msg;
                        if let Some(h) = self.proxy_task.take() {
                            h.abort();
                        }
                    }
                }
                ui.separator();
                ui.label(format!("Licensed to: {}", self.holder));
            });
            if self.live_mode {
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label("Listen:");
                    ui.add(egui::TextEdit::singleline(&mut self.listen_input).desired_width(130.0));
                    ui.label("Target:");
                    ui.add(egui::TextEdit::singleline(&mut self.target_input).desired_width(130.0));
                    ui.checkbox(&mut self.udp_mode, "UDP");
                    let running = self.proxy_task.is_some();
                    if !running {
                        if ui.button("Start Proxy").clicked() {
                            let sh = Arc::clone(&self.shaper);
                            let mtx = self.metrics_tx.clone();
                            let prx = self.profile_rx.clone();
                            let l_addr = self.listen_input.trim().to_string();
                            let t_addr = self.target_input.trim().to_string();
                            let tr = if self.udp_mode { ProxyTransport::Udp } else { ProxyTransport::Tcp };
                            let perr = Arc::clone(&self.proxy_err);
                            self.history.clear();
                            self.proxy_task = Some(tokio::spawn(async move {
                                if let Err(e) = run_proxy_live(&l_addr, &t_addr, sh, tr, mtx, prx).await {
                                    if let Ok(mut guard) = perr.lock() {
                                        *guard = Some(format!("Proxy error: {e}"));
                                    }
                                }
                            }));
                            self.status_msg = format!("Live proxy listening on {} -> {}", self.listen_input, self.target_input);
                        }
                    } else if ui.button("Stop Proxy").clicked() {
                        if let Some(handle) = self.proxy_task.take() {
                            handle.abort();
                        }
                        self.status_msg = "Live proxy stopped".into();
                    }
                });
            }
        });

        egui::SidePanel::left("controls")
            .min_width(320.0)
            .show(ctx, |ui| {
                ui.heading("Channel Parameters");
                let mut changed = false;

                changed |= ui
                    .add(
                        egui::Slider::new(&mut self.profile.bandwidth_hz, 1_000.0..=50_000_000.0)
                            .logarithmic(true)
                            .text("Bandwidth (Hz)"),
                    )
                    .changed();

                changed |= ui
                    .add(egui::Slider::new(&mut self.profile.snr_db, -25.0..=40.0).text("SNR (dB)"))
                    .changed();

                let shannon = shannon_capacity_bps(self.profile.bandwidth_hz, self.profile.snr_db);
                ui.label(format!("Shannon Ceiling: {:.0} bps", shannon));

                changed |= ui
                    .add(
                        egui::Slider::new(&mut self.profile.effective_goodput_bps, 100.0..=20_000_000.0)
                            .logarithmic(true)
                            .text("Effective Goodput (bps)"),
                    )
                    .changed();

                if ui.button("Sync Goodput to 50% Shannon").clicked() {
                    self.profile.effective_goodput_bps = (shannon * 0.5).max(100.0);
                    changed = true;
                }

                changed |= ui
                    .add(egui::Slider::new(&mut self.profile.max_payload_bytes, 8..=1500).text("MTU (bytes)"))
                    .changed();

                changed |= ui
                    .add(egui::Slider::new(&mut self.profile.header_overhead_bytes, 0..=128).text("Header (bytes)"))
                    .changed();

                changed |= ui
                    .add(
                        egui::Slider::new(&mut self.profile.queue_capacity_bytes, 64..=65_536)
                            .logarithmic(true)
                            .text("Queue Cap (bytes)"),
                    )
                    .changed();

                if changed {
                    let _ = self.profile_tx.send(self.profile.clone());
                }

                ui.separator();
                ui.heading("Synthetic Load & Calculator");
                let mut synth_changed = ui.checkbox(&mut self.synth_enabled, "Inject Periodic Packets").changed();
                synth_changed |= ui.add(egui::Slider::new(&mut self.synth_bytes, 8..=512).text("Payload (B)")).changed();
                synth_changed |= ui
                    .add(egui::Slider::new(&mut self.synth_hz, 0.2..=200.0).logarithmic(true).text("Rate (Hz)"))
                    .changed();
                if synth_changed {
                    let _ = self.synth_tx.send((self.synth_enabled, self.synth_bytes, self.synth_hz));
                }

                let calc = evaluate_payload(&self.profile, self.synth_bytes, self.synth_hz);
                ui.label(format!(
                    "Budget: {} frag(s), {:.1} ms airtime, {:.1}% util, max {:.2} Hz, BER loss {:.2}%",
                    calc.fragments_per_message,
                    calc.airtime_ms_per_message,
                    calc.utilization_pct,
                    calc.max_sustainable_hz,
                    calc.packet_loss_prob_pct
                ));

                ui.separator();
                ui.heading("Replay Capture Export");
                ui.label(format!("Captured samples: {}", self.full_capture.len()));
                ui.horizontal(|ui| {
                    if ui.button("Export CSV").clicked() {
                        match export_csv(&self.full_capture, self.cli_key.as_deref()) {
                            Ok(path) => self.status_msg = format!("Exported CSV: {path}"),
                            Err(e) => self.status_msg = format!("Export error: {e}"),
                        }
                    }
                    if ui.button("Export JSON").clicked() {
                        match export_json(&self.profile, &self.full_capture, self.cli_key.as_deref()) {
                            Ok(path) => self.status_msg = format!("Exported JSON: {path}"),
                            Err(e) => self.status_msg = format!("Export error: {e}"),
                        }
                    }
                    if ui.button("Clear").clicked() {
                        self.full_capture.clear();
                        self.history.clear();
                    }
                });
                ui.separator();
                ui.label(&self.status_msg);
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(format!("Offered: {:.0} bps", latest.offered_load_bps));
                ui.separator();
                ui.label(format!("Delivered: {:.0} bps", latest.delivered_goodput_bps));
                ui.separator();
                ui.label(format!("Forwarded: {}/{} pkts", latest.packets_forwarded, latest.packets_in));
                ui.separator();
                let total_drops = latest.queue_drops + latest.ber_drops;
                ui.colored_label(
                    if total_drops > 0 { egui::Color32::LIGHT_RED } else { egui::Color32::LIGHT_GREEN },
                    format!("Drops: {} (queue={}, ber={})", total_drops, latest.queue_drops, latest.ber_drops),
                );
            });

            let q_frac = if latest.queue_capacity_bytes > 0 {
                (latest.queued_bytes as f32 / latest.queue_capacity_bytes as f32).clamp(0.0, 1.0)
            } else {
                0.0
            };
            ui.add(egui::ProgressBar::new(q_frac).text(format!(
                "Queue Depth: {} / {} B ({:.0}%)",
                latest.queued_bytes, latest.queue_capacity_bytes, q_frac * 100.0
            )));

            ui.add_space(8.0);

            let offered_pts: PlotPoints = self.history.iter().map(|m| [m.timestamp_s, m.offered_load_bps]).collect();
            let delivered_pts: PlotPoints = self.history.iter().map(|m| [m.timestamp_s, m.delivered_goodput_bps]).collect();
            let effective_pts: PlotPoints = self.history.iter().map(|m| [m.timestamp_s, m.effective_goodput_bps]).collect();
            let shannon_pts: PlotPoints = self.history.iter().map(|m| [m.timestamp_s, m.shannon_ceiling_bps]).collect();

            Plot::new("throughput_plot")
                .legend(Legend::default())
                .x_axis_label("Time (s)")
                .y_axis_label("bps")
                .show(ui, |plot_ui| {
                    plot_ui.line(Line::new(offered_pts).name("Offered Load (bps)"));
                    plot_ui.line(Line::new(delivered_pts).name("Delivered Goodput (bps)"));
                    plot_ui.line(Line::new(effective_pts).name("Effective Goodput Ceiling"));
                    plot_ui.line(Line::new(shannon_pts).name("Shannon Ceiling (bps)"));
                });
        });
    }
}

fn export_csv(samples: &[ProxyMetrics], cli_key: Option<&str>) -> Result<String, String> {
    require_pro_with_key("Replay Capture Export", cli_key)?;
    let path = format!("gardawg_capture_{}.csv", current_unix_secs());
    let mut out = String::from(
        "timestamp_s,profile_id,offered_load_bps,delivered_goodput_bps,effective_goodput_bps,shannon_ceiling_bps,queued_bytes,queue_capacity_bytes,packets_in,packets_forwarded,queue_drops,ber_drops,bytes_in,bytes_forwarded,fragments\n",
    );
    for s in samples {
        out.push_str(&format!(
            "{:.3},{},{:.2},{:.2},{:.2},{:.2},{},{},{},{},{},{},{},{},{}\n",
            s.timestamp_s, s.profile_id, s.offered_load_bps, s.delivered_goodput_bps,
            s.effective_goodput_bps, s.shannon_ceiling_bps, s.queued_bytes, s.queue_capacity_bytes,
            s.packets_in, s.packets_forwarded, s.queue_drops, s.ber_drops,
            s.bytes_in, s.bytes_forwarded, s.fragments
        ));
    }
    fs::write(&path, out).map_err(|e| e.to_string())?;
    Ok(path)
}

fn export_json(profile: &LinkProfile, samples: &[ProxyMetrics], cli_key: Option<&str>) -> Result<String, String> {
    require_pro_with_key("Replay Capture Export", cli_key)?;
    let path = format!("gardawg_capture_{}.json", current_unix_secs());
    let payload = serde_json::json!({
        "exported_unix": current_unix_secs(),
        "profile": profile,
        "samples": samples,
    });
    let text = serde_json::to_string_pretty(&payload).map_err(|e| e.to_string())?;
    fs::write(&path, text).map_err(|e| e.to_string())?;
    Ok(path)
}