use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// Live LinkGuard/Gardawg Cloudflare Worker Ed25519 public key (LG1.<payload>.<sig>).
pub const EMBEDDED_PUBLIC_KEY_B64: &str = "TMUezvEDd_pBdrqZR3_2qfVn48lD7azxhWGMn9Ph308";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LicenseTier {
    Free,
    Pro,
    Team,
    Enterprise,
}

impl LicenseTier {
    pub fn is_paid(self) -> bool {
        matches!(self, Self::Pro | Self::Team | Self::Enterprise)
    }

    pub fn is_team_or_higher(self) -> bool {
        matches!(self, Self::Team | Self::Enterprise)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseClaims {
    pub tier: LicenseTier,
    pub holder: String,
    pub issued_unix: u64,
    pub expires_unix: Option<u64>,
    pub license_id: String,
    #[serde(default)]
    pub max_seats: Option<u32>,
    #[serde(default)]
    pub ci_allowed: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LicenseStatus {
    pub tier: LicenseTier,
    pub valid_paid: bool,
    pub ci_detected: bool,
    pub ci_allowed: bool,
    pub source: String,
    pub claims: Option<LicenseClaims>,
    pub error: Option<String>,
}

pub fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn is_ci_environment() -> bool {
    const CI_VARS: &[&str] = &[
        "CI",
        "GITHUB_ACTIONS",
        "GITLAB_CI",
        "JENKINS_URL",
        "CIRCLECI",
        "TF_BUILD",
        "BUILDKITE",
        "TRAVIS",
    ];
    CI_VARS.iter().any(|k| {
        env::var(k)
            .map(|v| {
                let low = v.trim().to_ascii_lowercase();
                !low.is_empty() && low != "0" && low != "false"
            })
            .unwrap_or(false)
    })
}

pub fn claims_allow_ci(claims: &LicenseClaims) -> bool {
    match claims.ci_allowed {
        Some(allowed) => allowed,
        None => claims.tier.is_team_or_higher(),
    }
}

pub fn embedded_verifying_key() -> Result<VerifyingKey, String> {
    let raw = URL_SAFE_NO_PAD
        .decode(EMBEDDED_PUBLIC_KEY_B64.trim())
        .map_err(|e| format!("Invalid embedded public key base64: {e}"))?;
    let arr: [u8; 32] = raw
        .try_into()
        .map_err(|_| "Embedded public key must be 32 bytes".to_string())?;
    VerifyingKey::from_bytes(&arr).map_err(|e| format!("Invalid Ed25519 public key: {e}"))
}

pub fn verify_token_with_key(
    token: &str,
    key: &VerifyingKey,
    now_unix: u64,
) -> Result<LicenseClaims, String> {
    let trimmed = token.trim();
    let mut parts = trimmed.split('.');
    let prefix = parts.next().unwrap_or("");
    let payload_b64 = parts.next().ok_or("Malformed license: missing payload")?;
    let sig_b64 = parts.next().ok_or("Malformed license: missing signature")?;
    if prefix != "LG1" || parts.next().is_some() {
        return Err("Invalid license format (expected LG1.<payload>.<sig>)".into());
    }

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|e| format!("Invalid license signature encoding: {e}"))?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| "Invalid license signature length (expected 64 bytes)".to_string())?;
    let sig = Signature::from_bytes(&sig_arr);

    let signed_msg = format!("LG1.{payload_b64}");
    key.verify_strict(signed_msg.as_bytes(), &sig)
        .map_err(|_| "License signature verification failed".to_string())?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| format!("Invalid license payload encoding: {e}"))?;
    let claims: LicenseClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("Invalid license JSON claims: {e}"))?;

    if let Some(exp) = claims.expires_unix {
        if now_unix > exp {
            return Err(format!(
                "License '{}' expired at unix timestamp {exp}",
                claims.license_id
            ));
        }
    }

    Ok(claims)
}

fn default_license_paths() -> Vec<PathBuf> {
    let mut paths = vec![
        PathBuf::from("gardawg.lic"),
        PathBuf::from("linkguard.lic"),
    ];
    if let Ok(exe) = env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            paths.push(exe_dir.join("gardawg.lic"));
            paths.push(exe_dir.join("linkguard.lic"));
        }
    }
    if let Some(appdata) = env::var_os("APPDATA") {
        let base = PathBuf::from(appdata);
        paths.push(base.join("gardawg").join("license.lic"));
        paths.push(base.join("linkguard").join("license.lic"));
    }
    if let Some(home) = env::var_os("HOME") {
        let cfg = PathBuf::from(home).join(".config");
        paths.push(cfg.join("gardawg").join("license.lic"));
        paths.push(cfg.join("linkguard").join("license.lic"));
    }
    paths
}

pub fn check_license_with_override(cli_key: Option<&str>) -> LicenseStatus {
    let ci_detected = is_ci_environment();
    let key = match embedded_verifying_key() {
        Ok(k) => k,
        Err(e) => {
            return LicenseStatus {
                tier: LicenseTier::Free,
                valid_paid: false,
                ci_detected,
                ci_allowed: false,
                source: "none".into(),
                claims: None,
                error: Some(e),
            }
        }
    };

    if let Some(raw) = cli_key {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return resolve_token_or_path(trimmed, "--license-key", &key, ci_detected);
        }
    }

    for env_name in ["GARDAWG_LICENSE_KEY", "LINKGUARD_LICENSE"] {
        if let Ok(env_val) = env::var(env_name) {
            let trimmed = env_val.trim();
            if !trimmed.is_empty() {
                return resolve_token_or_path(trimmed, env_name, &key, ci_detected);
            }
        }
    }

    for path in default_license_paths() {
        if path.is_file() {
            let src = path.display().to_string();
            match fs::read_to_string(&path) {
                Ok(contents) => return evaluate_token(&contents, &src, &key, ci_detected),
                Err(e) => {
                    return LicenseStatus {
                        tier: LicenseTier::Free,
                        valid_paid: false,
                        ci_detected,
                        ci_allowed: false,
                        source: src,
                        claims: None,
                        error: Some(format!("Failed to read license file: {e}")),
                    };
                }
            }
        }
    }

    LicenseStatus {
        tier: LicenseTier::Free,
        valid_paid: false,
        ci_detected,
        ci_allowed: false,
        source: "none".into(),
        claims: None,
        error: None,
    }
}

pub fn check_license() -> LicenseStatus {
    check_license_with_override(None)
}

fn resolve_token_or_path(val: &str, label: &str, key: &VerifyingKey, ci_detected: bool) -> LicenseStatus {
    if !val.starts_with("LG1.") && Path::new(val).is_file() {
        match fs::read_to_string(val) {
            Ok(contents) => evaluate_token(&contents, &format!("{label} ({val})"), key, ci_detected),
            Err(e) => LicenseStatus {
                tier: LicenseTier::Free,
                valid_paid: false,
                ci_detected,
                ci_allowed: false,
                source: format!("{label} ({val})"),
                claims: None,
                error: Some(format!("Failed to read license file: {e}")),
            },
        }
    } else {
        evaluate_token(val, label, key, ci_detected)
    }
}

fn evaluate_token(token: &str, source: &str, key: &VerifyingKey, ci_detected: bool) -> LicenseStatus {
    match verify_token_with_key(token, key, current_unix_secs()) {
        Ok(claims) => {
            let valid_paid = claims.tier.is_paid();
            let ci_allowed = claims_allow_ci(&claims);
            LicenseStatus {
                tier: claims.tier,
                valid_paid,
                ci_detected,
                ci_allowed,
                source: source.to_string(),
                claims: Some(claims),
                error: None,
            }
        }
        Err(e) => LicenseStatus {
            tier: LicenseTier::Free,
            valid_paid: false,
            ci_detected,
            ci_allowed: false,
            source: source.to_string(),
            claims: None,
            error: Some(e),
        },
    }
}

/// Count distinct non-bot committers in the last 90 days for offline Team seat checks.
pub fn count_recent_git_committers(workspace: &Path) -> Option<usize> {
    let out = Command::new("git")
        .args(["-C", &workspace.to_string_lossy(), "shortlog", "-sne", "--since=90 days ago", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut seen: HashSet<String> = HashSet::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        if lower.contains("[bot]")
            || lower.contains("noreply@github.com")
            || lower.contains("actions@github.com")
        {
            continue;
        }
        let identity = if let (Some(l), Some(r)) = (lower.rfind('<'), lower.rfind('>')) {
            if l < r {
                lower[l + 1..r].trim().to_string()
            } else {
                lower
            }
        } else {
            lower
        };
        if !identity.is_empty() {
            seen.insert(identity);
        }
    }
    Some(seen.len())
}

fn enforce_seat_cap(claims: &LicenseClaims, workspace: &Path) -> Result<(), String> {
    if claims.tier == LicenseTier::Team {
        let cap = claims.max_seats.unwrap_or(6) as usize;
        if let Some(active) = count_recent_git_committers(workspace) {
            if active > cap {
                return Err(format!(
                    "Gardawg Team license allows up to {cap} active contributors (found {active} in the last 90 days via `git shortlog`). Upgrade to Gardawg Enterprise for unlimited seats at https://oceans-niagara.github.io/gardawg/#pricing"
                ));
            }
        }
    }
    Ok(())
}

pub fn require_pro(feature_name: &str) -> Result<LicenseClaims, String> {
    require_pro_with_key(feature_name, None)
}

pub fn require_pro_with_key(feature_name: &str, cli_key: Option<&str>) -> Result<LicenseClaims, String> {
    let status = check_license_with_override(cli_key);
    if status.valid_paid {
        if let Some(claims) = status.claims {
            if status.ci_detected && !claims_allow_ci(&claims) {
                return Err(format!(
                    "'{feature_name}' cannot run in CI on a Pro license (Pro is for local workstations only). Upgrade to Gardawg Team (up to 6 seats + CI) or Enterprise at https://oceans-niagara.github.io/gardawg/#pricing"
                ));
            }
            enforce_seat_cap(&claims, Path::new("."))?;
            return Ok(claims);
        }
    }
    let detail = status.error.map(|e| format!(" ({e})")).unwrap_or_default();
    Err(format!(
        "'{feature_name}' requires a Pro, Team, or Enterprise license{detail}. Pass --license-key, set GARDAWG_LICENSE_KEY, or place gardawg.lic in ./ or next to the gardawg binary."
    ))
}

pub fn require_team_with_key(
    feature_name: &str,
    cli_key: Option<&str>,
    workspace: &Path,
) -> Result<LicenseClaims, String> {
    let status = check_license_with_override(cli_key);
    if status.valid_paid {
        if let Some(claims) = status.claims {
            if !claims.tier.is_team_or_higher() {
                return Err(format!(
                    "'{feature_name}' requires a Gardawg Team or Enterprise license (current tier: {:?}). Upgrade at https://oceans-niagara.github.io/gardawg/#pricing",
                    claims.tier
                ));
            }
            enforce_seat_cap(&claims, workspace)?;
            return Ok(claims);
        }
    }
    let detail = status.error.map(|e| format!(" ({e})")).unwrap_or_default();
    Err(format!(
        "'{feature_name}' requires a Gardawg Team or Enterprise license{detail}."
    ))
}

pub fn require_enterprise_with_key(
    feature_name: &str,
    cli_key: Option<&str>,
) -> Result<LicenseClaims, String> {
    let status = check_license_with_override(cli_key);
    if status.valid_paid {
        if let Some(claims) = status.claims {
            if claims.tier != LicenseTier::Enterprise {
                return Err(format!(
                    "'{feature_name}' requires a Gardawg Enterprise license (current tier: {:?}). Contact connect@oceansniagara.com",
                    claims.tier
                ));
            }
            return Ok(claims);
        }
    }
    let detail = status.error.map(|e| format!(" ({e})")).unwrap_or_default();
    Err(format!(
        "'{feature_name}' requires a Gardawg Enterprise license{detail}."
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn mint_test_token(sk: &SigningKey, claims: &LicenseClaims) -> String {
        let json = serde_json::to_vec(claims).unwrap();
        let payload_b64 = URL_SAFE_NO_PAD.encode(json);
        let msg = format!("LG1.{payload_b64}");
        let sig = sk.sign(msg.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        format!("{msg}.{sig_b64}")
    }

    #[test]
    fn ed25519_license_verifies_valid_rejects_tampered_and_expired() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();

        let claims = LicenseClaims {
            tier: LicenseTier::Pro,
            holder: "Test Lab".into(),
            issued_unix: 1_700_000_000,
            expires_unix: Some(1_800_000_000),
            license_id: "lic-001".into(),
            max_seats: Some(2),
            ci_allowed: Some(false),
        };
        let token = mint_test_token(&sk, &claims);

        let verified = verify_token_with_key(&token, &vk, 1_750_000_000).unwrap();
        assert_eq!(verified.tier, LicenseTier::Pro);
        assert_eq!(verified.holder, "Test Lab");
        assert!(!claims_allow_ci(&verified));

        assert!(verify_token_with_key(&token, &vk, 1_900_000_000).is_err());

        let mut tampered = token.clone();
        tampered.replace_range(6..7, if &token[6..7] == "A" { "B" } else { "A" });
        assert!(verify_token_with_key(&tampered, &vk, 1_750_000_000).is_err());
    }

    #[test]
    fn enterprise_and_team_allow_ci() {
        let team = LicenseClaims {
            tier: LicenseTier::Team,
            holder: "Acme".into(),
            issued_unix: 1_700_000_000,
            expires_unix: None,
            license_id: "t-1".into(),
            max_seats: Some(6),
            ci_allowed: Some(true),
        };
        let ent = LicenseClaims {
            tier: LicenseTier::Enterprise,
            holder: "BigCorp".into(),
            issued_unix: 1_700_000_000,
            expires_unix: None,
            license_id: "e-1".into(),
            max_seats: None,
            ci_allowed: None,
        };
        assert!(claims_allow_ci(&team));
        assert!(claims_allow_ci(&ent));
    }
}
