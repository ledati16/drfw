//! DRFW - Dumb Rust Firewall
//!
//! A user-friendly GUI application for managing Linux firewall rules via nftables.
//!
//! # Features
//!
//! - Visual rule management with real-time preview
//! - Undo/redo support for all operations
//! - Rule grouping and tagging
//! - Auto-revert of unconfirmed changes, guarded on the root side
//! - Syntax-highlighted nftables configuration
//! - IPv4/IPv6 support
//! - Boot persistence management
//! - Audit logging for security operations
//!
//! # Architecture
//!
//! DRFW follows a modular architecture:
//! - `core`: Firewall rule logic and nftables integration
//! - `app`: GUI application state and event handling
//! - `command`: Undo/redo command pattern implementation
//! - `validators`: Input validation and sanitization
//! - `elevation`: Privilege escalation via pkexec
//! - `audit`: Security audit logging
//!
//! # Security
//!
//! - Runs as unprivileged user, elevates only for rule application
//! - All inputs validated before elevation
//! - Audit trail of all privileged operations
//! - Atomic rule application with a root-side auto-revert guard
//!
//! # Usage
//!
//! ```bash
//! # Run the GUI application
//! drfw
//!
//! # CLI commands
//! drfw list                            # List available profiles
//! drfw status                          # Active profile, pending revert, system config
//! drfw check my-profile                # Validate + unprivileged nft check, no changes
//! drfw apply my-profile                # Apply with 15s auto-revert (default)
//! drfw apply my-profile --confirm 60   # Apply with 60s auto-revert (5-120)
//! drfw apply my-profile --no-confirm   # Apply without auto-revert
//! drfw export my-profile --format nft  # Export as nftables config
//! ```
//!
//! `drfw apply` changes the running kernel ruleset only; it does not persist
//! across reboots. Use "Save to System" in the GUI for boot persistence.
//!
//! The auto-revert runs as a separate root process (see
//! `core::apply_guard`): if the terminal closes or the SSH connection drops
//! during the countdown, the rules still revert on time.

mod app;
mod audit;
mod command;
mod config;
mod core;
mod elevation;
mod fonts;
mod theme;
mod utils;
mod validators;

// Embed build-time information (git commit, dirty status, build timestamp)
shadow_rs::shadow!(build);

use clap::{Parser, Subcommand, ValueEnum};

/// Returns the version string with git info: "0.8.0 (a3f8c21)" or "0.8.0 (a3f8c21*)" if dirty
#[must_use]
pub fn version_string() -> String {
    let dirty_marker = if build::GIT_CLEAN { "" } else { "*" };
    format!(
        "{} ({}{})",
        build::PKG_VERSION,
        build::SHORT_COMMIT,
        dirty_marker
    )
}

/// Short version for clap (must be &'static str)
const fn short_version() -> &'static str {
    shadow_rs::formatcp!("{} ({})", build::PKG_VERSION, build::SHORT_COMMIT)
}

/// Returns a detailed version string for --version flag
const fn long_version() -> &'static str {
    shadow_rs::formatcp!(
        "{} ({})\ncommit: {}\nbranch: {}\nbuild:  {}",
        build::PKG_VERSION,
        build::SHORT_COMMIT,
        build::COMMIT_HASH,
        build::BRANCH,
        build::BUILD_TIME_3339
    )
}
use crossterm::ExecutableCommand;
use crossterm::style::{Color, ResetColor, SetForegroundColor};
use iced::Size;
use std::io::stdout;
use std::process::ExitCode;

/// What ended the countdown
#[derive(Debug, PartialEq, Eq)]
enum CountdownEnd {
    /// The user asked to keep the new rules
    Confirm,
    /// The user asked to restore the previous rules now
    Revert,
    /// The timer ran out; the root-side guard reverts on its own
    Expired,
    /// No interactive terminal to ask on
    NoTerminal(String),
}

/// Longest pause between countdown redraws/key polls.
const COUNTDOWN_POLL: std::time::Duration = std::time::Duration::from_millis(250);

/// What a keypress during the countdown asks for
#[derive(Debug, PartialEq, Eq)]
enum CountdownKey {
    /// Keep the new rules
    Confirm,
    /// Restore the previous ruleset immediately
    Revert,
    /// Not a control key; keep counting down
    Ignore,
}

/// Maps a keypress during the countdown to an action.
///
/// Raw mode delivers Ctrl-C as `Char('c')` with the `CONTROL` modifier instead of
/// a signal, so modifiers must be checked before treating `c` as "confirm": a user
/// hitting Ctrl-C (or Esc) wants to abort, which here means reverting.
fn classify_countdown_key(key: &crossterm::event::KeyEvent) -> CountdownKey {
    use crossterm::event::{KeyCode, KeyModifiers};

    let ctrl_or_alt = key
        .modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT);

    match key.code {
        KeyCode::Esc | KeyCode::Char('r' | 'R') => CountdownKey::Revert,
        KeyCode::Char('c' | 'C') if ctrl_or_alt => CountdownKey::Revert,
        KeyCode::Char('c' | 'C') | KeyCode::Enter if !ctrl_or_alt => CountdownKey::Confirm,
        _ => CountdownKey::Ignore,
    }
}

/// Checks if we're running as root via sudo or run0.
///
/// This is detected by checking if we're root AND the `SUDO_USER` environment
/// variable is set (both sudo and run0 v256+ set this variable).
fn is_running_via_sudo() -> bool {
    nix::unistd::getuid().is_root() && std::env::var("SUDO_USER").is_ok()
}

/// Interactive countdown with confirmation/revert controls
///
/// Displays the time left until `deadline` (measured with `Instant`, so slow
/// redraws or key repeats never stretch it) and polls for keypresses:
/// - 'c' or Enter: confirm
/// - 'r', Esc or Ctrl-C: revert now
/// - any other key: ignored
///
/// Blocking (crossterm polling); run it with `spawn_blocking`.
fn run_countdown(deadline: std::time::Instant) -> CountdownEnd {
    use crossterm::event::{self, Event, KeyEventKind};
    use std::io::Write;

    if let Err(e) = crossterm::terminal::enable_raw_mode() {
        return CountdownEnd::NoTerminal(e.to_string());
    }

    let mut shown = None;
    let end = loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let secs = countdown_display_secs(remaining);
        if secs == 0 {
            break CountdownEnd::Expired;
        }
        if shown != Some(secs) {
            shown = Some(secs);
            print!("\rAuto-revert in ");
            let _ = stdout().execute(SetForegroundColor(Color::Yellow));
            print!("{secs:3}s");
            let _ = stdout().execute(ResetColor);
            print!("  [c/Enter=confirm, r/Esc/Ctrl-C=revert now]   ");
            std::io::stdout().flush().ok();
        }

        if let Ok(true) = event::poll(remaining.min(COUNTDOWN_POLL))
            && let Ok(Event::Key(key)) = event::read()
            && key.kind != KeyEventKind::Release
        {
            match classify_countdown_key(&key) {
                CountdownKey::Confirm => break CountdownEnd::Confirm,
                CountdownKey::Revert => break CountdownEnd::Revert,
                CountdownKey::Ignore => {}
            }
        }
    };

    // Always restore terminal to normal mode
    let _ = crossterm::terminal::disable_raw_mode();
    print!("\r\x1b[K"); // Clear line
    std::io::stdout().flush().ok();
    end
}

/// Whole seconds shown for `remaining`, rounded up (N … 1, then 0 = expired).
fn countdown_display_secs(remaining: std::time::Duration) -> u64 {
    remaining.as_secs() + u64::from(remaining.subsec_nanos() > 0)
}

/// Prints a colored status mark followed by a message.
fn print_status(mark: &str, color: Color, message: &str) {
    let _ = stdout().execute(SetForegroundColor(color));
    print!("{mark}");
    let _ = stdout().execute(ResetColor);
    println!(" {message}");
}

/// Waits for the guard's verdict after `end`, prints it and writes the audit log.
async fn finish_guarded_apply(
    handle: &core::apply_guard::GuardHandle,
    end: CountdownEnd,
    enable_event_log: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use core::apply_guard::{GuardOutcome, OUTCOME_GRACE};

    let timeout_secs = handle.timeout().as_secs();
    let outcome = match end {
        CountdownEnd::Confirm => {
            handle.confirm()?;
            handle.wait_outcome(OUTCOME_GRACE).await
        }
        CountdownEnd::Revert => {
            println!("Reverting...");
            handle.revert_now()?;
            handle.wait_outcome(OUTCOME_GRACE).await
        }
        CountdownEnd::Expired => {
            println!("Timeout - waiting for the guard to revert...");
            audit::log_auto_revert_timed_out(enable_event_log, timeout_secs).await;
            handle.wait_for_timeout_outcome().await
        }
        CountdownEnd::NoTerminal(reason) => {
            eprintln!("Cannot ask for confirmation without a terminal ({reason}).");
            eprintln!("Reverting now; use --no-confirm for unattended applies.");
            handle.revert_now()?;
            handle.wait_outcome(OUTCOME_GRACE).await
        }
    };

    match outcome {
        Ok(GuardOutcome::Confirmed) => {
            audit::log_auto_revert_confirmed(enable_event_log, timeout_secs).await;
            print_status(
                "✓",
                Color::Green,
                "Changes confirmed (active until reboot; use Save to System to persist).",
            );
            Ok(())
        }
        Ok(GuardOutcome::Reverted) => {
            audit::log_revert(enable_event_log, true, None).await;
            print_status("✓", Color::Yellow, "Reverted to the previous rules.");
            Ok(())
        }
        Ok(GuardOutcome::Removed(err)) => {
            let msg = format!(
                "The previous rules could not be restored ({err}); the drfw table was removed instead, so drfw is not filtering anything now."
            );
            audit::log_revert(enable_event_log, true, Some(msg.clone())).await;
            print_status("!", Color::Yellow, &msg);
            Ok(())
        }
        Ok(GuardOutcome::RevertFailed(err)) => {
            let msg = format!("Revert FAILED; the new rules are STILL ACTIVE: {err}");
            audit::log_revert(enable_event_log, false, Some(msg.clone())).await;
            print_status("✗", Color::Red, &msg);
            Err(msg.into())
        }
        Ok(GuardOutcome::Superseded) => {
            print_status(
                "!",
                Color::Yellow,
                "Another apply replaced these rules before they were confirmed.",
            );
            Ok(())
        }
        Err(e) => {
            audit::log_revert(enable_event_log, false, Some(e.to_string())).await;
            print_status("✗", Color::Red, &e.to_string());
            Err(e.into())
        }
    }
}

#[derive(Parser)]
#[command(name = "drfw")]
#[command(version = short_version(), long_version = long_version())]
#[command(about = "Dumb Rust Firewall - A minimal nftables manager", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// List all available profiles
    List,
    /// Apply a firewall profile to the kernel
    ///
    /// SAFETY: By default, rules auto-revert after 15 seconds unless confirmed.
    /// The revert is armed as root, independently of this command: if this
    /// terminal closes, the SSH connection drops or drfw is killed during the
    /// countdown, the previous rules are still restored on time. Applying asks
    /// for authentication once; confirming or reverting needs none.
    /// Use --no-confirm to disable.
    Apply {
        /// Name of the profile to apply
        name: String,
        /// Auto-revert timeout in seconds (default: 15s, max: 120s)
        #[arg(short, long, value_name = "SECONDS", default_value = "15")]
        confirm: u64,
        /// Skip auto-revert confirmation (apply immediately without safety net)
        #[arg(long, conflicts_with = "confirm")]
        no_confirm: bool,
    },
    /// Show the active profile, a pending auto-revert and the boot config
    ///
    /// Reads only what an unprivileged user can read. The live kernel ruleset
    /// needs root to list: run `sudo nft list table inet drfw` for that.
    Status,
    /// Check a profile without applying it
    ///
    /// Validates every rule, then runs `nft --check` on the generated ruleset
    /// in a private namespace (no privileges, no password prompt). Nothing is
    /// changed. Exits with 0 if the profile can be applied, 1 otherwise.
    Check {
        /// Name of the profile to check
        name: String,
    },
    /// Export a profile to nftables or JSON format
    Export {
        /// Name of the profile to export
        name: String,
        /// Export format
        #[arg(short, long, value_enum, default_value_t = ExportFormat::Nft)]
        format: ExportFormat,
    },
}

/// Output format of `drfw export`
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ExportFormat {
    /// nftables text (`nft -f` file), the same text Save to System writes
    Nft,
    /// nftables JSON (`nft --json -f`), what Apply sends to the kernel
    Json,
}

fn main() -> ExitCode {
    let _ = crate::utils::ensure_dirs();
    let cli = Cli::parse();

    if let Some(command) = cli.command {
        // Create Tokio runtime only for CLI commands
        let runtime = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
        match runtime.block_on(handle_cli(command)) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("Error: {e}");
                ExitCode::FAILURE
            }
        }
    } else {
        // GUI runs in normal sync context (Iced has its own async runtime)
        launch_gui()
    }
}

async fn handle_cli(command: Commands) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Commands::List => {
            let profiles = core::profiles::list_profiles().await?;
            let config = config::load_config().await;
            println!("Available profiles (* = active):");
            for p in profiles {
                if p == config.active_profile {
                    println!("  * {p}");
                } else {
                    println!("    {p}");
                }
            }
        }
        Commands::Apply {
            name,
            confirm,
            no_confirm,
        } => {
            let ruleset = match core::profiles::load_profile(&name).await {
                Ok(r) => r,
                Err(core::profiles::ProfileError::NotFound(_)) if is_running_via_sudo() => {
                    eprintln!("Error: Profile '{name}' not found.");
                    eprintln!();
                    eprintln!("Hint: You're running as root via sudo/run0, which looks for");
                    eprintln!("      profiles in /root/.local/share/drfw/profiles/");
                    eprintln!();
                    eprintln!("      drfw elevates automatically - you don't need sudo.");
                    eprintln!("      Try: drfw apply {name}");
                    return Err("Profile not found".into());
                }
                Err(e) => return Err(e.into()),
            };
            // Invalid enabled rules must never reach nft (see core::validate)
            if let Err(report) = ruleset.validate_for_apply() {
                eprintln!("Profile '{name}' has rules that cannot be applied:");
                eprintln!("{report}");
                eprintln!("Fix them in the GUI (they are marked INVALID) and try again.");
                return Err("Validation failed".into());
            }
            let nft_json = ruleset.to_nftables_json();
            let rule_count = ruleset.rules.len();
            let enabled_count = ruleset.rules.iter().filter(|r| r.enabled).count();
            let enable_event_log = config::load_config().await.enable_event_log;

            // Verify first
            println!("Verifying profile '{name}'...");
            let verify_result = core::verify::verify_ruleset(nft_json.clone()).await?;
            if !verify_result.success {
                let _ = stdout().execute(SetForegroundColor(Color::Red));
                eprint!("✗");
                let _ = stdout().execute(ResetColor);
                eprintln!(" Verification failed:");
                for error in &verify_result.errors {
                    let _ = stdout().execute(SetForegroundColor(Color::Red));
                    eprintln!("  {error}");
                    let _ = stdout().execute(ResetColor);
                }
                return Err("Verification failed".into());
            }

            println!();
            println!("Applying ruleset...");
            let timeout_secs = if no_confirm { 0 } else { confirm.clamp(5, 120) };
            let result = core::apply_guard::apply_guarded(&nft_json, timeout_secs).await;
            audit::log_apply(
                enable_event_log,
                rule_count,
                enabled_count,
                result.is_ok(),
                result.as_ref().err().map(ToString::to_string),
            )
            .await;

            match result? {
                None => print_status(
                    "✓",
                    Color::Green,
                    "Rules applied (no auto-revert; active until reboot, use Save to System to persist).",
                ),
                Some(handle) => {
                    print_status("✓", Color::Green, "Firewall rules applied!");
                    println!(
                        "  They revert automatically in {timeout_secs}s unless confirmed, even if this terminal or SSH session is lost."
                    );
                    println!();
                    let deadline = handle.deadline();
                    let end = tokio::task::spawn_blocking(move || run_countdown(deadline))
                        .await
                        .unwrap_or_else(|e| CountdownEnd::NoTerminal(e.to_string()));
                    finish_guarded_apply(&handle, end, enable_event_log).await?;
                }
            }
        }
        Commands::Status => print_status_report().await,
        Commands::Check { name } => check_profile(&name).await?,
        Commands::Export { name, format } => {
            let ruleset = core::profiles::load_profile(&name).await?;
            match format {
                ExportFormat::Nft => println!("{}", ruleset.to_nft_text()),
                ExportFormat::Json => println!(
                    "{}",
                    serde_json::to_string_pretty(&ruleset.to_nftables_json())?
                ),
            }
        }
    }
    Ok(())
}

/// Width of the label column in `drfw status`
const STATUS_LABEL_WIDTH: usize = 16;

/// Prints one `label: value` line of `drfw status`.
fn status_line(label: &str, value: &str) {
    println!("{:<STATUS_LABEL_WIDTH$}{value}", format!("{label}:"));
}

/// Formats a file time in the local time zone (`YYYY-MM-DD HH:MM:SS`).
fn local_time(time: std::time::SystemTime) -> String {
    jiff::Timestamp::try_from(time).map_or_else(
        |_| "unknown time".to_string(),
        |t| {
            t.to_zoned_datetime(jiff::tz::TimeZone::system())
                .strftime("%Y-%m-%d %H:%M:%S")
                .to_string()
        },
    )
}

/// What `drfw status` says about the boot config (`drfw::SYSTEM_NFT_PATH`).
fn system_config_status(path: &str) -> String {
    use std::io::Read;

    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return format!("{path} does not exist (Save to System has not been used)");
        }
        Err(e) => return format!("{path} cannot be read: {e}"),
    };
    // The header is on the first two lines; never read a whole (huge) file
    let mut head = Vec::with_capacity(512);
    if let Err(e) = file.take(512).read_to_end(&mut head) {
        return format!("{path} cannot be read: {e}");
    }
    match core::nft_text::generated_by_drfw(&String::from_utf8_lossy(&head)) {
        Some(version) => format!("{path} was written by DRFW {version} (Save to System)"),
        None => format!("{path} was not written by DRFW"),
    }
}

/// `drfw status`: what an unprivileged user can know without asking for a
/// password. Never fails; each line reports its own problem.
async fn print_status_report() {
    let config = config::load_config().await;
    status_line("Active profile", &config.active_profile);

    match core::profiles::load_profile(&config.active_profile).await {
        Ok(ruleset) => {
            let enabled = ruleset.rules.iter().filter(|r| r.enabled).count();
            status_line(
                "Rules",
                &format!("{} ({enabled} enabled)", ruleset.rules.len()),
            );
            let invalid = match ruleset.validate() {
                Ok(()) => "0".to_string(),
                Err(report) if report.blocks_apply() => format!(
                    "{} (the profile cannot be applied; see `drfw check {}`)",
                    report.rules.len(),
                    config.active_profile
                ),
                Err(report) => format!("{} (disabled or not applied)", report.rules.len()),
            };
            status_line("Invalid rules", &invalid);
            let mode = match ruleset.advanced_security.egress_profile {
                core::firewall::EgressProfile::Desktop => "Desktop (outgoing traffic allowed)",
                core::firewall::EgressProfile::Server => "Server (outgoing traffic needs rules)",
            };
            status_line("Mode", mode);
        }
        Err(e) => status_line("Rules", &format!("profile cannot be loaded: {e}")),
    }

    let guard_dir = std::path::Path::new(elevation::GUARD_STATE_DIR);
    let guard = match core::apply_guard::pending_guard(guard_dir) {
        Ok(None) => "none pending".to_string(),
        Ok(Some(pending)) => format!(
            "PENDING since {}: the last apply reverts automatically unless it is confirmed",
            pending
                .armed_at
                .map_or_else(|| "an unknown time".to_string(), local_time)
        ),
        Err(e) => format!(
            "unknown ({}/active cannot be read: {e})",
            elevation::GUARD_STATE_DIR
        ),
    };
    status_line("Auto-revert", &guard);
    status_line("Boot config", &system_config_status(drfw::SYSTEM_NFT_PATH));
    status_line(
        "Kernel",
        "not checked (listing it needs root); run `sudo nft list table inet drfw` to inspect it",
    );
}

/// `drfw check`: validation plus the unprivileged nft check; changes nothing.
async fn check_profile(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let ruleset = core::profiles::load_profile(name).await?;
    let enabled = ruleset.rules.iter().filter(|r| r.enabled).count();
    let total = ruleset.rules.len();
    let noun = if total == 1 { "rule" } else { "rules" };
    println!("Checking profile '{name}' ({total} {noun}, {enabled} enabled)...");

    if let Err(report) = ruleset.validate() {
        if report.blocks_apply() {
            print_status(
                "✗",
                Color::Red,
                "The profile has rules that cannot be applied:",
            );
            eprintln!("{report}");
            return Err("Validation failed".into());
        }
        print_status(
            "!",
            Color::Yellow,
            "Some rules are invalid, but none of them would be applied:",
        );
        println!("{report}");
    } else {
        print_status("✓", Color::Green, "All rules are valid.");
    }

    let result = core::verify::verify_ruleset_unprivileged(&ruleset.to_nftables_json()).await?;
    if !result.success {
        print_status("✗", Color::Red, "nft rejected the generated ruleset:");
        for error in &result.errors {
            eprintln!("  {error}");
        }
        return Err("nft check failed".into());
    }
    print_status(
        "✓",
        Color::Green,
        "nft accepts the generated ruleset (checked without privileges; nothing was changed).",
    );
    Ok(())
}

fn launch_gui() -> ExitCode {
    // Set up logging to file
    if let Some(mut log_path) = crate::utils::get_state_dir() {
        log_path.push("drfw.log");
        // 0600, appended (not truncated per launch), rotated to drfw.log.1 past 5 MiB
        if let Ok(file) = crate::utils::open_private_log(&log_path, 5 * 1024 * 1024) {
            tracing_subscriber::fmt().with_writer(file).init();
        } else {
            tracing_subscriber::fmt::init();
        }
    } else {
        tracing_subscriber::fmt::init();
    }

    let result = iced::application(app::State::new, app::State::update, app::State::view)
        .subscription(app::State::subscription)
        .window(iced::window::Settings {
            size: Size::new(1000.0, 700.0),
            // Close requests are handled in `State::update` (pending saves are flushed first)
            exit_on_close_request: false,
            platform_specific: iced::window::settings::PlatformSpecific {
                application_id: "drfw".to_string(),
                ..Default::default()
            },
            ..Default::default()
        })
        .title("Dumb Rust Firewall")
        .theme(|_state: &app::State| iced::Theme::Dark)
        .run();

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn key(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, modifiers)
    }

    #[test]
    fn test_countdown_ctrl_c_reverts() {
        // Raw mode turns Ctrl-C into a 'c' keypress; it must NOT confirm
        assert_eq!(
            classify_countdown_key(&key(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            CountdownKey::Revert
        );
        assert_eq!(
            classify_countdown_key(&key(
                KeyCode::Char('C'),
                KeyModifiers::CONTROL | KeyModifiers::SHIFT
            )),
            CountdownKey::Revert
        );
    }

    #[test]
    fn test_countdown_esc_and_r_revert() {
        assert_eq!(
            classify_countdown_key(&key(KeyCode::Esc, KeyModifiers::NONE)),
            CountdownKey::Revert
        );
        assert_eq!(
            classify_countdown_key(&key(KeyCode::Char('r'), KeyModifiers::NONE)),
            CountdownKey::Revert
        );
        assert_eq!(
            classify_countdown_key(&key(KeyCode::Char('R'), KeyModifiers::SHIFT)),
            CountdownKey::Revert
        );
    }

    #[test]
    fn test_countdown_plain_c_and_enter_confirm() {
        assert_eq!(
            classify_countdown_key(&key(KeyCode::Char('c'), KeyModifiers::NONE)),
            CountdownKey::Confirm
        );
        assert_eq!(
            classify_countdown_key(&key(KeyCode::Char('C'), KeyModifiers::SHIFT)),
            CountdownKey::Confirm
        );
        assert_eq!(
            classify_countdown_key(&key(KeyCode::Enter, KeyModifiers::NONE)),
            CountdownKey::Confirm
        );
    }

    #[test]
    fn test_countdown_other_keys_ignored() {
        assert_eq!(
            classify_countdown_key(&key(KeyCode::Char('x'), KeyModifiers::NONE)),
            CountdownKey::Ignore
        );
        assert_eq!(
            classify_countdown_key(&key(KeyCode::Enter, KeyModifiers::CONTROL)),
            CountdownKey::Ignore
        );
    }

    #[test]
    fn test_countdown_display_secs_rounds_up() {
        use std::time::Duration;
        assert_eq!(countdown_display_secs(Duration::from_secs(15)), 15);
        assert_eq!(countdown_display_secs(Duration::from_millis(14_001)), 15);
        assert_eq!(countdown_display_secs(Duration::from_millis(999)), 1);
        assert_eq!(countdown_display_secs(Duration::from_millis(1)), 1);
        assert_eq!(countdown_display_secs(Duration::ZERO), 0);
    }

    #[test]
    fn test_cli_apply_examples_parse() {
        // Keep the module-level usage examples in sync with the real CLI
        for args in [
            &["drfw", "apply", "my-profile"][..],
            &["drfw", "apply", "my-profile", "--confirm", "60"],
            &["drfw", "apply", "my-profile", "--no-confirm"],
            &["drfw", "export", "my-profile", "--format", "nft"],
            &["drfw", "export", "my-profile", "--format", "json"],
            &["drfw", "export", "my-profile"],
            &["drfw", "check", "my-profile"],
            &["drfw", "list"],
            &["drfw", "status"],
        ] {
            assert!(
                Cli::try_parse_from(args).is_ok(),
                "failed to parse {args:?}"
            );
        }
        // A bare `--confirm` needs a value
        assert!(Cli::try_parse_from(["drfw", "apply", "my-profile", "--confirm"]).is_err());
        // Unknown export formats are rejected by clap, not at run time
        assert!(Cli::try_parse_from(["drfw", "export", "my-profile", "--format", "xml"]).is_err());
    }
}
