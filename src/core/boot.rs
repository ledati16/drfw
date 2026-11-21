//! Boot persistence: does a systemd unit load the saved rules at boot?
//!
//! Save to System writes [`crate::SYSTEM_NFT_PATH`], but only an enabled unit
//! loads that file at boot. This module asks systemd, **without privileges**:
//! `systemctl is-enabled <unit>` and `systemctl is-active <unit>` (each with a
//! timeout, killed on drop), for [`crate::SYSTEM_NFT_SERVICE`] and, when that
//! one is not enabled, for DRFW's own [`BUNDLED_SERVICE`], which loads the same
//! file (`drfw print-service-unit`).
//!
//! The GUI shows the result in the Save to System dialog and after saving;
//! `drfw status` prints it as "Boot persistence".

use std::time::Duration;

use crate::distro::{BUNDLED_SERVICE, SYSTEM_NFT_PATH, SYSTEM_NFT_SERVICE};

/// Maximum time for one `systemctl` query (it never prompts).
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// What `systemctl is-enabled` says about a unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Enablement {
    /// `enabled`: started at boot
    Enabled,
    /// `disabled`: installed, not started at boot
    Disabled,
    /// `masked` / `masked-runtime`: cannot be started at all
    Masked,
    /// `not-found`: no such unit is installed
    NotFound,
    /// Any other state systemd reports (`static`, `indirect`,
    /// `enabled-runtime`, `generated`, ...)
    Other(String),
    /// `systemctl` is missing or systemd is not running (containers, other
    /// init systems)
    SystemdUnavailable,
    /// The query failed in another way (the reason)
    Unknown(String),
}

/// Maps the output of `systemctl is-enabled <unit>` to an [`Enablement`].
///
/// systemd prints the state on stdout (exit status 0 only for enabled-like
/// states, so the status itself is not used). With no state on stdout, stderr
/// tells "systemd is not running" apart from "no such unit" (older systemd
/// versions report a missing unit as `No such file or directory`).
pub fn enablement_from_output(stdout: &str, stderr: &str) -> Enablement {
    match stdout.lines().next().unwrap_or_default().trim() {
        "enabled" => Enablement::Enabled,
        "disabled" => Enablement::Disabled,
        "masked" | "masked-runtime" => Enablement::Masked,
        "not-found" => Enablement::NotFound,
        "" => {
            let stderr = stderr.trim();
            if stderr.contains("not been booted with systemd")
                || stderr.contains("Failed to connect to bus")
                || stderr.contains("Failed to connect to system scope bus")
            {
                Enablement::SystemdUnavailable
            } else if stderr.contains("No such file or directory")
                || stderr.contains("does not exist")
                || stderr.contains("not found")
            {
                Enablement::NotFound
            } else if stderr.is_empty() {
                Enablement::Unknown("systemctl printed nothing".to_string())
            } else {
                Enablement::Unknown(stderr.lines().next().unwrap_or(stderr).to_string())
            }
        }
        other => Enablement::Other(other.to_string()),
    }
}

/// Maps the output of `systemctl is-active <unit>` (`active`, `inactive`,
/// `failed`, ...): `None` when it printed no state.
pub fn active_state_from_output(stdout: &str) -> Option<String> {
    let state = stdout.lines().next().unwrap_or_default().trim();
    (!state.is_empty()).then(|| state.to_string())
}

/// Boot persistence of one unit: enablement plus the current active state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootStatus {
    /// The unit that was queried
    pub unit: String,
    /// `systemctl is-enabled`
    pub enablement: Enablement,
    /// `systemctl is-active`, if it reported a state
    pub active: Option<String>,
}

impl BootStatus {
    /// `Some(true)` if the unit loads the rules at boot, `Some(false)` if it
    /// certainly does not, `None` if DRFW cannot tell.
    pub fn loads_at_boot(&self) -> Option<bool> {
        match &self.enablement {
            Enablement::Enabled => Some(true),
            Enablement::Disabled | Enablement::Masked | Enablement::NotFound => Some(false),
            Enablement::Other(state) if state == "enabled-runtime" => Some(false),
            Enablement::Other(_) | Enablement::SystemdUnavailable | Enablement::Unknown(_) => None,
        }
    }

    /// Whether "Also enable at boot" makes sense: the unit exists, is not
    /// enabled and is not masked (enabling a masked unit fails).
    pub fn offers_enable(&self) -> bool {
        matches!(
            self.enablement,
            Enablement::Disabled | Enablement::Other(_) | Enablement::Unknown(_)
        )
    }

    /// Whether "Also enable at boot" starts checked: the unit is disabled.
    pub fn suggests_enable(&self) -> bool {
        self.enablement == Enablement::Disabled
    }

    /// One line for the user, e.g. "Loaded at boot by nftables.service" or
    /// "nftables.service is disabled: the rules will NOT load at boot".
    pub fn summary(&self) -> String {
        let unit = &self.unit;
        match &self.enablement {
            Enablement::Enabled if self.active.as_deref() == Some("failed") => format!(
                "Loaded at boot by {unit}, but its last start failed (see `systemctl status {unit}`)"
            ),
            Enablement::Enabled => format!("Loaded at boot by {unit}"),
            Enablement::Disabled => {
                format!("{unit} is disabled: the rules will NOT load at boot")
            }
            Enablement::Masked => format!("{unit} is masked: the rules will NOT load at boot"),
            Enablement::NotFound => {
                format!("{unit} is not installed: the rules will NOT load at boot")
            }
            Enablement::Other(state) if state == "enabled-runtime" => format!(
                "{unit} is enabled only until the next reboot: the rules will NOT load at boot"
            ),
            Enablement::Other(state) => {
                format!("{unit} is {state}: check that it loads {SYSTEM_NFT_PATH} at boot")
            }
            Enablement::SystemdUnavailable => format!(
                "systemd is not available: check how your system loads {SYSTEM_NFT_PATH} at boot"
            ),
            Enablement::Unknown(reason) => format!("Could not check {unit}: {reason}"),
        }
    }
}

/// Runs `systemctl <args>` unprivileged: `Ok(None)` on timeout.
async fn systemctl(args: &[&str]) -> std::io::Result<Option<std::process::Output>> {
    let child = tokio::process::Command::new("systemctl")
        .args(args)
        // English messages for `enablement_from_output`
        .env("LC_ALL", "C")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    match tokio::time::timeout(QUERY_TIMEOUT, child.wait_with_output()).await {
        Ok(output) => output.map(Some),
        Err(_) => Ok(None),
    }
}

/// Queries one unit (`systemctl is-enabled` and `is-active`, concurrently).
pub async fn query_unit(unit: &str) -> BootStatus {
    let (is_enabled, is_active) = (["is-enabled", unit], ["is-active", unit]);
    let (enabled, active) = tokio::join!(systemctl(&is_enabled), systemctl(&is_active));
    let enablement = match enabled {
        Ok(Some(output)) => enablement_from_output(
            &String::from_utf8_lossy(&output.stdout),
            &String::from_utf8_lossy(&output.stderr),
        ),
        Ok(None) => Enablement::Unknown("systemctl timed out".to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Enablement::SystemdUnavailable,
        Err(e) => Enablement::Unknown(format!("cannot run systemctl: {e}")),
    };
    let active = match active {
        Ok(Some(output)) => active_state_from_output(&String::from_utf8_lossy(&output.stdout)),
        _ => None,
    };
    BootStatus {
        unit: unit.to_string(),
        enablement,
        active,
    }
}

/// Whether the rules in [`SYSTEM_NFT_PATH`] load at boot.
///
/// Reports [`SYSTEM_NFT_SERVICE`], unless that one is not enabled while
/// [`BUNDLED_SERVICE`] (which loads the same file) is: then the bundled unit.
/// Never prompts and never fails; problems end up in [`Enablement`].
pub async fn query_boot_status() -> BootStatus {
    let primary = query_unit(SYSTEM_NFT_SERVICE).await;
    if primary.enablement == Enablement::Enabled || SYSTEM_NFT_SERVICE == BUNDLED_SERVICE {
        return primary;
    }
    let bundled = query_unit(BUNDLED_SERVICE).await;
    if bundled.enablement == Enablement::Enabled {
        bundled
    } else {
        primary
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(enablement: Enablement, active: Option<&str>) -> BootStatus {
        BootStatus {
            unit: "nftables.service".to_string(),
            enablement,
            active: active.map(ToString::to_string),
        }
    }

    #[test]
    fn test_enablement_states() {
        let cases = [
            ("enabled\n", Enablement::Enabled),
            ("disabled\n", Enablement::Disabled),
            ("masked\n", Enablement::Masked),
            ("masked-runtime\n", Enablement::Masked),
            ("not-found\n", Enablement::NotFound),
            ("static\n", Enablement::Other("static".into())),
            (
                "enabled-runtime\n",
                Enablement::Other("enabled-runtime".into()),
            ),
            ("  indirect  \n", Enablement::Other("indirect".into())),
        ];
        for (stdout, expected) in cases {
            assert_eq!(enablement_from_output(stdout, ""), expected, "{stdout:?}");
        }
    }

    #[test]
    fn test_enablement_from_stderr_only() {
        assert_eq!(
            enablement_from_output(
                "",
                "System has not been booted with systemd as init system (PID 1). Can't operate.\n"
            ),
            Enablement::SystemdUnavailable
        );
        assert_eq!(
            enablement_from_output("", "Failed to connect to bus: No such file or directory\n"),
            Enablement::SystemdUnavailable
        );
        // systemd < 236 for a missing unit
        assert_eq!(
            enablement_from_output(
                "",
                "Failed to get unit file state for x.service: No such file or directory\n"
            ),
            Enablement::NotFound
        );
        assert_eq!(
            enablement_from_output("", "Access denied\nmore\n"),
            Enablement::Unknown("Access denied".into())
        );
        assert!(matches!(
            enablement_from_output("", ""),
            Enablement::Unknown(_)
        ));
    }

    #[test]
    fn test_active_state() {
        assert_eq!(active_state_from_output("active\n"), Some("active".into()));
        assert_eq!(active_state_from_output("failed\n"), Some("failed".into()));
        assert_eq!(active_state_from_output(""), None);
    }

    #[test]
    fn test_loads_at_boot_and_enable_offer() {
        // (enablement, loads at boot, offer checkbox, checked by default)
        let cases = [
            (Enablement::Enabled, Some(true), false, false),
            (Enablement::Disabled, Some(false), true, true),
            (Enablement::Masked, Some(false), false, false),
            (Enablement::NotFound, Some(false), false, false),
            (
                Enablement::Other("enabled-runtime".into()),
                Some(false),
                true,
                false,
            ),
            (Enablement::Other("static".into()), None, true, false),
            (Enablement::SystemdUnavailable, None, false, false),
            (Enablement::Unknown("x".into()), None, true, false),
        ];
        for (enablement, loads, offers, suggests) in cases {
            let s = status(enablement.clone(), None);
            assert_eq!(s.loads_at_boot(), loads, "{enablement:?}");
            assert_eq!(s.offers_enable(), offers, "{enablement:?}");
            assert_eq!(s.suggests_enable(), suggests, "{enablement:?}");
        }
    }

    #[test]
    fn test_summaries() {
        assert_eq!(
            status(Enablement::Enabled, Some("active")).summary(),
            "Loaded at boot by nftables.service"
        );
        assert!(
            status(Enablement::Enabled, Some("failed"))
                .summary()
                .contains("last start failed")
        );
        assert_eq!(
            status(Enablement::Disabled, Some("inactive")).summary(),
            "nftables.service is disabled: the rules will NOT load at boot"
        );
        assert!(
            status(Enablement::Masked, None)
                .summary()
                .contains("masked")
        );
        assert!(
            status(Enablement::NotFound, None)
                .summary()
                .contains("not installed")
        );
        assert!(
            status(Enablement::SystemdUnavailable, None)
                .summary()
                .starts_with("systemd is not available")
        );
        assert!(
            status(Enablement::Other("static".into()), None)
                .summary()
                .contains(SYSTEM_NFT_PATH)
        );
    }
}
