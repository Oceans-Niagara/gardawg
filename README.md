# Gardawg

**Deterministic AI-code guardrails, physical-layer link analysis, and chaos testing in one offline-first binary.**

Gardawg is an offline-first Rust CLI and MCP server by [Oceans Niagara, LLC](https://oceansniagara.com). It enforces deterministic AST rules and quality gates on your code, checks payloads against real physical-layer limits (LoRa, BLE, Wi-Fi, LEO satellite, UART), and runs seeded chaos/impairment proxies, all with zero LLM dependencies and zero code leaving your machine.

- **Website, WASM sandbox & licensing:** https://oceans-niagara.github.io/gardawg/
- **Interactive sandbox:** https://oceans-niagara.github.io/gardawg/sandbox.html

## What It Catches

* **`GR000` Syntax & stray fences:** parse errors and stray Markdown code fences, even without `tsc`/`cargo`/`ruff`.
* **`GR001` Money floats:** `f32`/`f64` on money and quantity identifiers.
* **`GR002` Missing timeouts:** `fetch`, `axios`, `reqwest`, `requests`, and `httpx` calls without explicit timeouts.
* **`GR004`–`GR005` Swallowed errors & stubs:** empty `catch`/`except: pass`, ignored results, `todo!()`, `NotImplementedError`, and placeholder comments.
* **`GR006`–`GR007` Security & panics:** hardcoded secrets (`sk_live_`, `AKIA`, `ghp_`, private keys), `eval`/`exec`/`shell=True`, and non-test Rust `.unwrap()`.
* **Link budgets:** `budget` computes the Shannon ceiling, MTU fragmentation, airtime, and BER loss for a payload on a chosen link profile.
* **Chaos & SARIF:** seeded TCP/UDP/HTTP impairment proxies and OASIS SARIF 2.1.0 output (`--format sarif`).

`init` detects your stack and generates `gardawg.toml`, `AGENTS.md`, `.mcp.json`, and `opencode.json`. Re-sync them after editing `gardawg.toml` with `gardawg sync`.

## Install & Quickstart

**Prebuilt binaries (no Rust required):** download from [GitHub Releases](https://github.com/Oceans-Niagara/gardawg/releases/latest). Headless builds suit CI and servers; `-gui` builds add the desktop dashboard.

| OS | Headless | GUI |
|---|---|---|
| Windows | `gardawg-windows-x86_64.exe` | `gardawg-gui-windows-x86_64.exe` |
| macOS (Apple Silicon) | `gardawg-macos-arm64` | `gardawg-gui-macos-arm64` |
| macOS (Intel) | `gardawg-macos-x86_64` | `gardawg-gui-macos-x86_64` |
| Linux | `gardawg-linux-x86_64` | `gardawg-gui-linux-x86_64` |

```powershell
# Windows (PowerShell, from your project root)
.\gardawg-windows-x86_64.exe init
.\gardawg-windows-x86_64.exe check
```

```bash
# macOS / Linux (swap the binary name for your OS/arch)
chmod +x ./gardawg-macos-arm64
./gardawg-macos-arm64 init
./gardawg-macos-arm64 check --format sarif
```

```bash
# Or build from source
cargo install --git https://github.com/Oceans-Niagara/gardawg
cargo install --git https://github.com/Oceans-Niagara/gardawg --features gui   # includes the desktop dashboard

gardawg init
gardawg check --format sarif
gardawg budget --profile lora-sf12 --bytes 64 --hz 10
gardawg proxy --listen 127.0.0.1:9000 --target 127.0.0.1:9001 --profile ble-1m --seed 42
gardawg mcp
```

## Licensing

Offline Ed25519-signed keys (`LG1...`), verified locally with zero network calls. Perpetual, one-time purchase.

* **Free ($0):** core CLI, AST rules, quality gates, SARIF output, built-in link profiles, seeded `proxy` and `chaos`, stdio MCP server, and the browser sandbox.
* **Pro ($19.99):** everything in Free, plus `gardawg resilience` (Schemathesis & Keploy through the chaos proxy), custom `profiles.toml`, the CI baseline ratchet (`--baseline`), the desktop GUI, and commercial/CI usage.
* **Team ($59.99):** everything in Pro for your team, with a shared offline key for CI runners and priority email support.

Activate by saving your key as `gardawg.lic` in your project folder, or by setting `GARDAWG_LICENSE_KEY`. Verify with `gardawg license`.

---

&copy; 2026 Oceans Niagara, LLC &bull; [connect@oceansniagara.com](mailto:connect@oceansniagara.com)