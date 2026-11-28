use crate::config::LinkConfig;
use crate::license::require_pro_with_key;
use crate::physics::{evaluate_payload, LinkProfile, PayloadCheckRule};
use crate::sarif::{normalize_sarif_uri, Finding, PayloadCheckResult};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct StandaloneBudgetsFile {
    pub profile: String,
    #[serde(default = "default_hz")]
    pub assumed_hz: f64,
    #[serde(default = "default_fail_on")]
    pub fail_on: String,
    pub max_diagnostics: Option<usize>,
    #[serde(default = "default_paths")]
    pub paths: Vec<String>,
    #[serde(default)]
    pub payload_checks: Vec<PayloadCheckRule>,
}

fn default_hz() -> f64 { 1.0 }
fn default_fail_on() -> String { "high".to_string() }
fn default_paths() -> Vec<String> { vec![".".to_string()] }

#[derive(Debug, Deserialize)]
struct BaselineFile {
    #[serde(default, alias = "diagnostics")]
    findings: Vec<Finding>,
}

pub fn load_standalone_budgets(path: &Path) -> anyhow::Result<LinkConfig> {
    let raw = fs::read_to_string(path)?;
    let parsed: StandaloneBudgetsFile = toml::from_str(raw.trim_start_matches('\u{feff}'))?;
    Ok(LinkConfig {
        enabled: true,
        profile: Some(parsed.profile),
        assumed_hz: parsed.assumed_hz,
        fail_on: parsed.fail_on,
        max_diagnostics: parsed.max_diagnostics,
        paths: parsed.paths,
        payload_checks: parsed.payload_checks,
    })
}

pub fn evaluate_payload_checks(
    profile: &LinkProfile,
    checks: &[PayloadCheckRule],
) -> Vec<PayloadCheckResult> {
    let mut results = Vec::with_capacity(checks.len());
    for rule in checks {
        let rep = evaluate_payload(profile, rule.bytes, rule.hz);
        let mut passed = !rep.exceeds_effective_capacity;
        let mut reason = rep.verdict.clone();
        if rule.require_single_mtu && rep.fragments_per_message > 1 {
            passed = false;
            reason = format!(
                "FAIL (MTU): {} B splits into {} fragments (max MTU {} B)",
                rule.bytes, rep.fragments_per_message, profile.max_payload_bytes
            );
        }
        results.push(PayloadCheckResult {
            name: rule.name.clone(),
            passed,
            reason,
            report: rep,
        });
    }
    results
}

pub fn apply_baseline_ratchet(
    current: Vec<Finding>,
    baseline_path: Option<&Path>,
    cli_key: Option<&str>,
) -> anyhow::Result<(Vec<Finding>, usize)> {
    let Some(bpath) = baseline_path else {
        return Ok((current, 0));
    };
    require_pro_with_key("CI Regression Baseline (--baseline)", cli_key)
        .map_err(|e| anyhow::anyhow!(e))?;
    let bytes = fs::read(bpath)?;
    let raw = if bytes.starts_with(&[0xFF, 0xFE]) {
        let u16s: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16(&u16s)?
    } else if bytes.starts_with(&[0xFE, 0xFF]) {
        let u16s: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16(&u16s)?
    } else {
        String::from_utf8(bytes)?
    };
    let parsed: BaselineFile = serde_json::from_str(raw.trim_start_matches('\u{feff}'))?;
    Ok(filter_against_baseline(current, &parsed.findings))
}

fn baseline_key(f: &Finding) -> (String, String, String) {
    (
        normalize_sarif_uri(&f.file),
        f.rule_id.clone(),
        f.snippet.clone().unwrap_or_else(|| f.message.clone()),
    )
}

pub fn filter_against_baseline(
    current: Vec<Finding>,
    baseline: &[Finding],
) -> (Vec<Finding>, usize) {
    let mut counts: HashMap<(String, String, String), usize> = HashMap::new();
    for b in baseline {
        *counts.entry(baseline_key(b)).or_insert(0) += 1;
    }

    let mut regressions = Vec::new();
    let mut suppressed = 0;
    for f in current {
        let key = baseline_key(&f);
        if let Some(c) = counts.get_mut(&key) {
            if *c > 0 {
                *c -= 1;
                suppressed += 1;
                continue;
            }
        }
        regressions.push(f);
    }
    (regressions, suppressed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::physics::get_profile;
    use crate::sarif::Severity;

    #[test]
    fn payload_checks_enforce_single_mtu() {
        let lora = get_profile("lora-sf12").unwrap();
        let pass = evaluate_payload_checks(
            &lora,
            &[PayloadCheckRule {
                name: "compact".into(),
                bytes: 20,
                hz: 0.2,
                require_single_mtu: true,
            }],
        );
        assert!(pass[0].passed);

        let fail = evaluate_payload_checks(
            &lora,
            &[PayloadCheckRule {
                name: "oversized".into(),
                bytes: 60,
                hz: 0.1,
                require_single_mtu: true,
            }],
        );
        assert!(!fail[0].passed);
    }

    #[test]
    fn baseline_suppresses_shifted_legacy_findings() {
        let legacy = Finding {
            rule_id: "JSON_IN_LOOP".into(),
            tool: "linkguard-ast".into(),
            severity: Severity::Error,
            tier: Some("critical".into()),
            message: "Legacy".into(),
            file: r".\src\app.py".into(),
            start_line: 10,
            start_col: 5,
            snippet: Some("json.dumps(x)".into()),
            physics_law: None,
            remediation: None,
            suppression_hint: None,
            budget: None,
        };
        let mut shifted = legacy.clone();
        shifted.file = "src/app.py".into();
        shifted.start_line = 25;

        let mut regression = legacy.clone();
        regression.snippet = Some("json.dumps(y)".into());

        let (kept, suppressed) = filter_against_baseline(vec![shifted, regression], &[legacy]);
        assert_eq!(suppressed, 1);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].snippet.as_deref(), Some("json.dumps(y)"));
    }
}
