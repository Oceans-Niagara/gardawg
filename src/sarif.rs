use crate::physics::PayloadBudgetReport;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;

const SARIF_SCHEMA: &str =
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Note,
}

impl Severity {
    pub fn rank(self) -> u8 {
        match self {
            Severity::Error => 1,
            Severity::Warning => 2,
            Severity::Note => 3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub tool: String,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    pub message: String,
    pub file: String,
    pub start_line: usize,
    pub start_col: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub physics_law: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppression_hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget: Option<PayloadBudgetReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadCheckResult {
    pub name: String,
    pub passed: bool,
    pub reason: String,
    pub report: PayloadBudgetReport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckReport {
    pub passed: bool,
    pub files_scanned: usize,
    pub rules_evaluated: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    pub pedantic: bool,
    pub suppressed_by_baseline: usize,
    pub findings_count: usize,
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub payload_results: Vec<PayloadCheckResult>,
}

pub fn normalize_sarif_uri(path: &str) -> String {
    let forward = path.replace('\\', "/");
    forward.strip_prefix("./").unwrap_or(&forward).to_string()
}

pub fn to_sarif(findings: &[Finding], failed_payloads: &[&PayloadCheckResult], config_path: Option<&Path>) -> Value {
    to_sarif_with_org(findings, failed_payloads, config_path, None)
}

pub fn to_sarif_with_org(
    findings: &[Finding],
    failed_payloads: &[&PayloadCheckResult],
    config_path: Option<&Path>,
    enterprise_org: Option<&str>,
) -> Value {
    let mut rules_map: BTreeMap<String, Value> = BTreeMap::new();
    let mut results: Vec<Value> = Vec::with_capacity(findings.len() + failed_payloads.len());

    for f in findings {
        let level = match f.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Note => "note",
        };
        rules_map.entry(f.rule_id.clone()).or_insert_with(|| {
            json!({
                "id": f.rule_id,
                "name": f.rule_id,
                "shortDescription": { "text": f.physics_law.as_deref().unwrap_or(&f.message) },
                "fullDescription": { "text": f.remediation.as_deref().unwrap_or(&f.message) },
                "defaultConfiguration": { "level": level },
                "properties": {
                    "tool": f.tool,
                    "tags": ["gardawg", &f.tool, level]
                }
            })
        });

        let mut msg_parts = vec![f.message.clone()];
        if let Some(law) = &f.physics_law {
            msg_parts.push(format!("Physics: {law}"));
        }
        if let Some(rem) = &f.remediation {
            msg_parts.push(format!("Fix: {rem}"));
        }

        results.push(json!({
            "ruleId": f.rule_id,
            "level": level,
            "message": { "text": msg_parts.join(" | ") },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": normalize_sarif_uri(&f.file),
                        "uriBaseId": "%SRCROOT%"
                    },
                    "region": {
                        "startLine": f.start_line.max(1),
                        "startColumn": f.start_col.max(1)
                    }
                }
            }]
        }));
    }

    if !failed_payloads.is_empty() {
        let rule_id = "PAYLOAD_BUDGET_EXCEEDED";
        rules_map.entry(rule_id.to_string()).or_insert_with(|| {
            json!({
                "id": rule_id,
                "name": rule_id,
                "shortDescription": { "text": "Configured payload_checks budget exceeded physical channel MTU or goodput" },
                "fullDescription": { "text": "Reduce payload bytes, lower transmit Hz, or batch frames to fit channel limits." },
                "defaultConfiguration": { "level": "error" },
                "properties": { "tags": ["gardawg", "physical-layer", "budget"] }
            })
        });
        let uri = config_path
            .map(|p| normalize_sarif_uri(&p.display().to_string()))
            .unwrap_or_else(|| "gardawg.toml".to_string());

        for p in failed_payloads {
            results.push(json!({
                "ruleId": rule_id,
                "level": "error",
                "message": {
                    "text": format!(
                        "Payload check '{}' ({} B @ {} Hz) failed: {}",
                        p.name, p.report.payload_bytes, p.report.assumed_hz, p.reason
                    )
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": uri, "uriBaseId": "%SRCROOT%" },
                        "region": { "startLine": 1, "startColumn": 1 }
                    }
                }]
            }));
        }
    }

    let rules: Vec<Value> = rules_map.into_values().collect();
    let driver = match enterprise_org {
        Some(org) => json!({
            "name": "gardawg",
            "version": env!("CARGO_PKG_VERSION"),
            "rules": rules,
            "properties": { "licenseAudit": format!("Licensed to {org} — Enterprise") }
        }),
        None => json!({
            "name": "gardawg",
            "version": env!("CARGO_PKG_VERSION"),
            "rules": rules
        }),
    };
    let mut run = json!({
        "tool": { "driver": driver },
        "results": results
    });
    if let Some(org) = enterprise_org {
        run["properties"] = json!({ "licensedTo": format!("Licensed to {org} — Enterprise") });
    }
    json!({
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [run]
    })
}
