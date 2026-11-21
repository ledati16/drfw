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
//! This binary is only the command-line front end: it parses the arguments,
//! runs the CLI commands below and starts the GUI ([`drfw::run_gui`]) when no
//! subcommand is given. Everything else lives in the `drfw` library:
//! - `core`: Firewall rule logic and nftables integration
//! - `app` (private): GUI application state and event handling
//! - `command`: Undo/redo command pattern implementation
//! - `validators`: Input validation and sanitization
//! - `elevation`: Privilege escalation (`run0`, `sudo`, `pkexec`)
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
//! drfw status                          # Active profile, pending revert, boot config/service
//! drfw check my-profile                # Validate + unprivileged nft check, no changes
//! drfw apply my-profile                # Apply with 15s auto-revert (default)
//! drfw apply my-profile --confirm 60   # Apply with 60s auto-revert (5-120)
//! drfw apply my-profile --no-confirm   # Apply without auto-revert
//! drfw save my-profile                 # Save to System (boot config)
//! drfw save my-profile --enable-at-boot
//! drfw export my-profile --format nft  # Export as nftables config
//! ```
//!
//! `drfw apply` changes the running kernel ruleset only; it does not persist
//! across reboots. `drfw save` (or "Save to System" in the GUI) writes the
//! boot config.
//!
//! Exit codes are listed in [`EXIT_CODES_HELP`] (shown by `drfw --help`).
//!
//! The auto-revert runs as a separate root process (see
//! `core::apply_guard`): if the terminal closes or the SSH connection drops
//! during the countdown, the rules still revert on time.

use std::io::IsTerminal;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use crossterm::style::{Color, ResetColor, SetForegroundColor};
use drfw::build_info::{LONG_VERSION, SHORT_VERSION};
use drfw::core::verify::VerifyIssue;
use drfw::{audit, config, core, elevation};

/// Exit codes of the CLI. Codes 1 and 2 keep their usual meaning (failure,
/// usage error from clap); every code above 2 names an outcome a script must
/// not mistake for "nothing happened". 126 and up are left alone (shells use
/// them for "not executable", "not found" and signals).
mod exit_code {
    /// Failed; nothing was changed (validation, nft rejected, authentication, ...)
    pub const FAILED: u8 = 1;
    /// The guard could not restore the previous rules and removed the drfw
    /// table instead: drfw is not filtering anything now
    pub const UNFILTERED: u8 = 3;
    /// The revert failed: the new (unconfirmed) rules are still active
    pub const REVERT_FAILED: u8 = 4;
    /// Another apply replaced these rules before they were confirmed
    pub const SUPERSEDED: u8 = 5;
    /// The outcome is unknown: the new rules may be active
    pub const STATE_UNKNOWN: u8 = 6;
    /// `drfw save` refused: the rules are not the ones last applied and kept
    /// and there was no `--yes` (or the question was answered no)
    pub const NOT_CONFIRMED: u8 = 7;
    /// `drfw save` saved the file, but the boot service could not be enabled
    pub const NOT_ENABLED: u8 = 8;
    /// `drfw apply`/`drfw save` refused by the retention guard (most of the
    /// kept rules removed, Server mode or forward blocking turned on) without
    /// `--yes` (or the question was answered no); nothing was changed
    pub const RETENTION: u8 = 9;
}

/// Exit code table for `--help` and the README.
const EXIT_CODES_HELP: &str = "\
Exit codes:
  0  Success: applied, confirmed, reverted (by timeout or on request), saved
  1  Failed; nothing was changed (or `drfw check` found problems)
  2  Usage error
  3  apply: the previous rules could not be restored, so the drfw table was
     REMOVED: drfw is not filtering anything now
  4  apply: the revert FAILED: the new, unconfirmed rules are STILL ACTIVE
  5  apply: another apply replaced these rules before they were confirmed
  6  apply: the outcome is UNKNOWN: the new rules may be active
  7  save: not saved: the rules are not the ones last applied and
     confirmed with `drfw apply` (pass --yes to save anyway)
  8  save: saved, but the boot service could not be enabled
  9  apply/save: not done: the ruleset removes most of the rules last
     applied and kept, or turns on Server mode or forward blocking
     (pass --yes to go ahead)";

/// A CLI failure with its exit code (see [`exit_code`]). An empty message
/// means the details were already printed.
#[derive(Debug)]
struct CliFailure {
    code: u8,
    message: String,
}

impl std::fmt::Display for CliFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CliFailure {}

/// A [`CliFailure`] as the boxed error `handle_cli` returns.
fn failure(code: u8, message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(CliFailure {
        code,
        message: message.into(),
    })
}

/// The exit code for an error returned by `handle_cli`.
fn exit_code_of(error: &(dyn std::error::Error + 'static)) -> u8 {
    error
        .downcast_ref::<CliFailure>()
        .map_or(exit_code::FAILED, |f| f.code)
}

/// An output stream of the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stream {
    Stdout,
    Stderr,
}

impl Stream {
    /// Whether to color this stream: only when it is a terminal, so piped or
    /// redirected output never contains escape codes.
    fn colored(self) -> bool {
        match self {
            Self::Stdout => std::io::stdout().is_terminal(),
            Self::Stderr => std::io::stderr().is_terminal(),
        }
    }
}

/// `text` in `color` when `enabled`, otherwise `text` unchanged.
fn paint(text: &str, color: Color, enabled: bool) -> String {
    if enabled {
        format!("{}{text}{}", SetForegroundColor(color), ResetColor)
    } else {
        text.to_string()
    }
}

/// Indentation of nft's errors under the "rejected" line.
const ISSUE_INDENT: &str = "  ";
/// Indentation of an error's message continuation, source and caret lines.
const ISSUE_DETAIL_INDENT: &str = "      ";

/// Formats nft's errors for the terminal: `rule "<label>": <message>`, then
/// the offending line of the generated ruleset with nft's caret under it.
fn issue_lines(issues: &[VerifyIssue], color: bool) -> Vec<String> {
    if issues.is_empty() {
        return vec![format!("{ISSUE_INDENT}(nft gave no details)")];
    }
    let mut lines = Vec::with_capacity(issues.len() * 3);
    for issue in issues {
        let mut message = issue.message.lines();
        let first = message.next().unwrap_or_default();
        lines.push(match &issue.origin {
            Some(origin) => format!(
                "{ISSUE_INDENT}{}: {}",
                paint(&origin.to_string(), Color::Yellow, color),
                paint(first, Color::Red, color)
            ),
            None => format!("{ISSUE_INDENT}{}", paint(first, Color::Red, color)),
        });
        lines.extend(message.map(|l| format!("{ISSUE_DETAIL_INDENT}{l}")));
        if let (Some(source), Some(caret)) = (&issue.source_line, &issue.caret) {
            lines.push(format!("{ISSUE_DETAIL_INDENT}{source}"));
            lines.push(format!(
                "{ISSUE_DETAIL_INDENT}{}",
                paint(caret, Color::Red, color)
            ));
        }
    }
    lines
}

/// Prints nft's errors to stderr (see [`issue_lines`]).
fn print_issues(issues: &[VerifyIssue]) {
    for line in issue_lines(issues, Stream::Stderr.colored()) {
        eprintln!("{line}");
    }
}

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
    /// The guard finished on its own during the countdown (e.g. superseded
    /// by another apply)
    Finished(core::apply_guard::GuardOutcome),
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
/// `outcome` is asked on every tick: once the guard has finished on its own
/// (another apply superseded it), the countdown ends with that outcome.
///
/// Blocking (crossterm polling); run it with `spawn_blocking`.
fn run_countdown(
    deadline: std::time::Instant,
    outcome: impl Fn() -> Option<core::apply_guard::GuardOutcome>,
) -> CountdownEnd {
    use std::io::Write;

    use crossterm::event::{self, Event, KeyEventKind};

    if let Err(e) = crossterm::terminal::enable_raw_mode() {
        return CountdownEnd::NoTerminal(e.to_string());
    }

    let color = Stream::Stdout.colored();
    let mut shown = None;
    let end = loop {
        if let Some(outcome) = outcome() {
            break CountdownEnd::Finished(outcome);
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let secs = countdown_display_secs(remaining);
        if secs == 0 {
            break CountdownEnd::Expired;
        }
        if shown != Some(secs) {
            shown = Some(secs);
            print!(
                "\rAuto-revert in {}  [c/Enter=confirm, r/Esc/Ctrl-C=revert now]   ",
                paint(&format!("{secs:3}s"), Color::Yellow, color)
            );
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

/// Prints a status mark (colored on a terminal) followed by a message.
fn print_status(mark: &str, color: Color, message: &str) {
    println!("{} {message}", paint(mark, color, Stream::Stdout.colored()));
}

/// Waits for the guard's verdict after `end`, prints it and writes the audit log.
///
/// # Errors
///
/// A [`CliFailure`] with the exit code for every outcome but a confirmation or
/// a clean revert (see [`exit_code`]).
async fn finish_guarded_apply(
    handle: &core::apply_guard::GuardHandle,
    end: CountdownEnd,
    enable_event_log: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use drfw::core::apply_guard::{GuardOutcome, OUTCOME_GRACE};

    let timeout_secs = handle.timeout().as_secs();
    let token_failed = |e: drfw::core::apply_guard::GuardError| {
        failure(
            exit_code::STATE_UNKNOWN,
            format!("{e}. The rules revert on their own when the countdown ends."),
        )
    };
    let no_terminal = matches!(end, CountdownEnd::NoTerminal(_));
    let outcome = match end {
        CountdownEnd::Confirm => {
            handle.confirm().map_err(token_failed)?;
            handle.wait_outcome(OUTCOME_GRACE).await
        }
        CountdownEnd::Revert => {
            println!("Reverting...");
            handle.revert_now().map_err(token_failed)?;
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
            handle.revert_now().map_err(token_failed)?;
            handle.wait_outcome(OUTCOME_GRACE).await
        }
        CountdownEnd::Finished(outcome) => {
            // Read again through wait_outcome: it also cleans up the tokens
            handle.wait_outcome(OUTCOME_GRACE).await.or(Ok(outcome))
        }
    };

    match outcome {
        Ok(GuardOutcome::Confirmed) => {
            audit::log_auto_revert_confirmed(enable_event_log, timeout_secs).await;
            print_status(
                "✓",
                Color::Green,
                "Changes confirmed (active until reboot; run `drfw save` to persist).",
            );
            Ok(())
        }
        Ok(GuardOutcome::Reverted) => {
            audit::log_revert(enable_event_log, true, None).await;
            print_status("✓", Color::Yellow, "Reverted to the previous rules.");
            if no_terminal {
                return Err(failure(
                    exit_code::FAILED,
                    "the rules were not kept (no terminal to confirm on)",
                ));
            }
            Ok(())
        }
        Ok(GuardOutcome::Removed(err)) => {
            let msg = format!(
                "The previous rules could not be restored ({err}); the drfw table was removed instead, so drfw is not filtering anything now."
            );
            audit::log_revert(enable_event_log, true, Some(msg.clone())).await;
            print_status("!", Color::Yellow, &msg);
            Err(failure(exit_code::UNFILTERED, ""))
        }
        Ok(GuardOutcome::RevertFailed(err)) => {
            let msg = format!("Revert FAILED; the new rules are STILL ACTIVE: {err}");
            audit::log_revert(enable_event_log, false, Some(msg.clone())).await;
            print_status("✗", Color::Red, &msg);
            Err(failure(exit_code::REVERT_FAILED, ""))
        }
        Ok(GuardOutcome::Superseded) => {
            print_status(
                "!",
                Color::Yellow,
                "Another apply replaced these rules before they were confirmed.",
            );
            Err(failure(exit_code::SUPERSEDED, ""))
        }
        Err(e) => {
            audit::log_revert(enable_event_log, false, Some(e.to_string())).await;
            print_status("✗", Color::Red, &e.to_string());
            Err(failure(exit_code::STATE_UNKNOWN, ""))
        }
    }
}

#[derive(Parser)]
#[command(name = "drfw")]
#[command(version = SHORT_VERSION, long_version = LONG_VERSION)]
#[command(about = "Dumb Rust Firewall - A minimal nftables manager", long_about = None)]
#[command(after_help = EXIT_CODES_HELP)]
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
    ///
    /// A ruleset that removes most of the rules last applied and kept (at
    /// least 3 and 40 % of the enabled ones; disabled counts as removed), or
    /// turns on Server mode or forward blocking, needs --yes (or an answer on
    /// a terminal).
    #[command(after_help = EXIT_CODES_HELP)]
    Apply {
        /// Name of the profile to apply
        name: String,
        /// Auto-revert timeout in seconds (default: 15s, max: 120s)
        #[arg(short, long, value_name = "SECONDS", default_value = "15")]
        confirm: u64,
        /// Skip auto-revert confirmation (apply immediately without safety
        /// net); the rules count as kept at once
        #[arg(long, conflicts_with = "confirm")]
        no_confirm: bool,
        /// Apply even if it removes most of the rules last applied and kept,
        /// or turns on Server mode or forward blocking
        #[arg(short, long)]
        yes: bool,
    },
    /// Show the active profile, a pending auto-revert, the boot config and
    /// whether a systemd unit loads it at boot
    ///
    /// Reads only what an unprivileged user can read. The live kernel ruleset
    /// needs root to list: run `sudo nft list table inet drfw` for that.
    Status,
    /// Save a profile as the boot config (Save to System)
    ///
    /// Writes the profile to the system nftables config, checked with
    /// `nft -c` first (one authentication prompt). It does not change the
    /// running rules. The saved rules load at the next boot WITHOUT a
    /// dead-man switch, so a profile that is not the one last applied and
    /// kept with `drfw apply` (or the GUI) needs --yes (or an answer on a
    /// terminal). So does one that removes most of the kept rules, or turns
    /// on Server mode or forward blocking.
    #[command(after_help = EXIT_CODES_HELP)]
    Save {
        /// Name of the profile to save
        name: String,
        /// Also enable the boot service if it is not enabled (same prompt)
        #[arg(long)]
        enable_at_boot: bool,
        /// Save even if this exact ruleset is not the one last applied and
        /// kept on this machine, or the retention guard warns
        #[arg(short, long)]
        yes: bool,
    },
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
    /// Print the systemd unit `drfw.service` for this build (for packagers)
    ///
    /// Fills `contrib/drfw.service.in` with the paths this binary was compiled
    /// with (`DRFW_SYSTEM_NFT_PATH`, `DRFW_NFT_PATH`), so the packaged unit
    /// loads exactly the file Save to System writes.
    #[command(hide = true)]
    PrintServiceUnit,
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
    let cli = Cli::parse();

    // Runs at package time (often as a build user or under fakeroot): no
    // runtime, no data directories
    if matches!(cli.command, Some(Commands::PrintServiceUnit)) {
        print!("{}", drfw::distro::service_unit());
        return ExitCode::SUCCESS;
    }
    let _ = drfw::utils::ensure_dirs();

    if let Some(command) = cli.command {
        elevation::set_context(elevation::ElevationContext::Cli);
        // Create Tokio runtime only for CLI commands
        let runtime = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
        match runtime.block_on(handle_cli(command)) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                let message = e.to_string();
                if !message.is_empty() {
                    eprintln!("Error: {message}");
                }
                ExitCode::from(exit_code_of(e.as_ref()))
            }
        }
    } else {
        // GUI runs in normal sync context (Iced has its own async runtime)
        drfw::run_gui()
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
            yes,
        } => {
            let ruleset = load_applicable_profile(&name, "apply").await?;
            let nft_json = ruleset.to_nftables_json();
            let rule_count = ruleset.rules.len();
            let enabled_count = ruleset.rules.iter().filter(|r| r.enabled).count();
            let enable_event_log = config::load_config().await.enable_event_log;

            // Verify first
            println!("Verifying profile '{name}'...");
            let verify_result = core::verify::verify_ruleset(nft_json.clone()).await?;
            let verify_result = core::verify::locate_errors(&ruleset, verify_result).await;
            if !verify_result.success {
                eprintln!(
                    "{} nft rejected the generated ruleset:",
                    paint("✗", Color::Red, Stream::Stderr.colored())
                );
                print_issues(&verify_result.issues);
                return Err("Verification failed".into());
            }
            let record = core::confirmed::ConfirmedRecord::load().await;
            retention_guard(
                &ruleset,
                record.as_ref(),
                yes,
                ("Apply anyway?", "not applied"),
            )
            .await?;

            println!();
            println!("Applying ruleset...");
            let timeout_secs = if no_confirm { 0 } else { confirm.clamp(5, 120) };
            let result = core::apply_guard::apply_guarded(&nft_json, timeout_secs, &ruleset).await;
            audit::log_apply(
                enable_event_log,
                rule_count,
                enabled_count,
                result.is_ok(),
                result.as_ref().err().map(ToString::to_string),
            )
            .await;

            let guard = match result {
                Ok(guard) => guard,
                Err(e) if e.rules_may_be_active() => {
                    print_status("✗", Color::Red, &e.to_string());
                    eprintln!("Check with: sudo nft list table inet drfw");
                    return Err(failure(exit_code::STATE_UNKNOWN, ""));
                }
                Err(e) => return Err(e.into()),
            };
            match guard {
                None => print_status(
                    "✓",
                    Color::Green,
                    "Rules applied (no auto-revert; active until reboot, run `drfw save` to persist).",
                ),
                Some(handle) => {
                    print_status("✓", Color::Green, "Firewall rules applied!");
                    println!(
                        "  They revert automatically in {timeout_secs}s unless confirmed, even if this terminal or SSH session is lost."
                    );
                    println!();
                    let deadline = handle.deadline();
                    let watched = handle.clone();
                    let end = tokio::task::spawn_blocking(move || {
                        run_countdown(deadline, || watched.read_outcome())
                    })
                    .await
                    .unwrap_or_else(|e| CountdownEnd::NoTerminal(e.to_string()));
                    finish_guarded_apply(&handle, end, enable_event_log).await?;
                }
            }
        }
        Commands::Status => print_status_report().await,
        Commands::Save {
            name,
            enable_at_boot,
            yes,
        } => save_profile(&name, enable_at_boot, yes).await?,
        // Handled in main() before the runtime starts
        Commands::PrintServiceUnit => print!("{}", drfw::distro::service_unit()),
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

/// Width of the label column in `drfw status` ("Boot persistence:" + 1)
const STATUS_LABEL_WIDTH: usize = 18;

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
        "Boot persistence",
        &core::boot::query_boot_status().await.summary(),
    );
    status_line(
        "Kernel",
        "not checked (listing it needs root); run `sudo nft list table inet drfw` to inspect it",
    );
}

/// Loads profile `name` for `drfw <verb>` and refuses it if an applied rule
/// is invalid (invalid enabled rules must never reach nft; see
/// `core::validate`). Explains the `sudo` pitfall when the profile is missing.
async fn load_applicable_profile(
    name: &str,
    verb: &str,
) -> Result<core::firewall::FirewallRuleset, Box<dyn std::error::Error>> {
    let ruleset = match core::profiles::load_profile(name).await {
        Ok(r) => r,
        Err(core::profiles::ProfileError::NotFound(_)) if is_running_via_sudo() => {
            eprintln!("Error: Profile '{name}' not found.");
            eprintln!();
            eprintln!("Hint: You're running as root via sudo/run0, which looks for");
            eprintln!("      profiles in /root/.local/share/drfw/profiles/");
            eprintln!();
            eprintln!("      drfw elevates automatically - you don't need sudo.");
            eprintln!("      Try: drfw {verb} {name}");
            return Err("Profile not found".into());
        }
        Err(e) => return Err(e.into()),
    };
    if let Err(report) = ruleset.validate_for_apply() {
        eprintln!("Profile '{name}' has rules that cannot be applied:");
        eprintln!("{report}");
        eprintln!("Fix them in the GUI (they are marked INVALID) and try again.");
        return Err("Validation failed".into());
    }
    Ok(ruleset)
}

/// Where `drfw save` writes: [`drfw::SYSTEM_NFT_PATH`], or in test mode
/// (`DRFW_NFT_COMMAND` set, nothing elevated) `DRFW_TEST_SYSTEM_NFT_PATH`.
fn save_target() -> String {
    if elevation::test_nft_command().is_some()
        && let Some(path) = std::env::var("DRFW_TEST_SYSTEM_NFT_PATH")
            .ok()
            .filter(|p| !p.is_empty())
    {
        return path;
    }
    drfw::SYSTEM_NFT_PATH.to_string()
}

/// Asks `question [y/N]` on the terminal; true only for an explicit yes.
async fn ask_yes_no(question: &str) -> bool {
    use std::io::Write;
    print!("{question} [y/N] ");
    std::io::stdout().flush().ok();
    tokio::task::spawn_blocking(|| {
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer).is_ok()
            && matches!(answer.trim(), "y" | "Y" | "yes" | "YES" | "Yes")
    })
    .await
    .unwrap_or(false)
}

/// The retention guard for `drfw apply` and `drfw save` (see
/// `core::retention`): prints why `ruleset` is a big change compared with
/// the rules last applied and kept, then asks on a terminal unless `yes`.
/// `(question, refused)` are e.g. `("Apply anyway?", "not applied")`.
///
/// # Errors
///
/// [`exit_code::RETENTION`] when it warns, `yes` is not set and stdin is not
/// a terminal, or the answer is not yes.
async fn retention_guard(
    ruleset: &core::firewall::FirewallRuleset,
    record: Option<&core::confirmed::ConfirmedRecord>,
    yes: bool,
    (question, refused): (&str, &str),
) -> Result<(), Box<dyn std::error::Error>> {
    let kept = record.and_then(core::confirmed::ConfirmedRecord::ruleset);
    let Some(warning) = core::retention::RetentionWarning::check(kept, ruleset) else {
        return Ok(());
    };
    eprintln!(
        "{} This is a big change compared with the rules last applied and kept:",
        paint("WARNING:", Color::Red, Stream::Stderr.colored())
    );
    for line in &warning.lines {
        eprintln!("  {line}");
    }
    if yes {
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        return Err(failure(
            exit_code::RETENTION,
            format!("{refused}: pass --yes to go ahead"),
        ));
    }
    if !ask_yes_no(question).await {
        return Err(failure(exit_code::RETENTION, refused));
    }
    Ok(())
}

/// Why the save script failed, from its exit status and stderr.
fn save_error(output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    if let Some(auth) = elevation::auth_failure_from_exit(output.status.code(), &stderr) {
        return auth.to_string();
    }
    let message = stderr
        .lines()
        .map(|line| line.trim().trim_start_matches("drfw: "))
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("; ");
    if message.is_empty() {
        output.status.code().map_or_else(
            || "the save script was terminated by a signal".to_string(),
            |c| format!("the save script failed (exit code {c})"),
        )
    } else {
        message
    }
}

/// `drfw save`: Save to System from the command line, the same path as the
/// GUI (validation, the fixed save script with `nft -c` on the exact bytes,
/// optionally `systemctl enable` in the same prompt).
///
/// The saved rules load at the next boot without a dead-man switch, so a
/// ruleset that is not the one last applied and kept (the
/// `core::confirmed` record, compared byte for byte) needs `--yes` (or a yes
/// on the terminal). So does one the retention guard warns about.
///
/// # Errors
///
/// [`exit_code::NOT_CONFIRMED`] when refused for want of a confirmation,
/// [`exit_code::NOT_ENABLED`] when the file was saved but `--enable-at-boot`
/// could not enable the service, [`exit_code::FAILED`] otherwise.
async fn save_profile(
    name: &str,
    enable_at_boot: bool,
    yes: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use drfw::core::system_config::{
        EnableOutcome, backup_path_from_output, enable_outcome_from_output,
        write_config_file_and_enable,
    };

    let ruleset = load_applicable_profile(name, "save").await?;
    let target = save_target();
    let json = ruleset.to_nftables_json();
    let enable_event_log = config::load_config().await.enable_event_log;

    // Readable errors first (no prompt); the save script's `nft -c` on the
    // exact bytes stays the authoritative check
    match core::verify::verify_ruleset_unprivileged(&json).await {
        Ok(result) if !result.success => {
            let result = core::verify::locate_errors(&ruleset, result).await;
            print_status("✗", Color::Red, "nft rejected the generated ruleset:");
            print_issues(&result.issues);
            return Err("Verification failed; nothing was saved".into());
        }
        Ok(_) => {}
        Err(e) => eprintln!("Note: could not check the ruleset without privileges ({e})."),
    }

    let record = core::confirmed::ConfirmedRecord::load().await;
    // The CLI always saves the profile itself; it is "tested" when its JSON is
    // byte for byte the last ruleset applied and kept on this machine
    let confirmed = record.as_ref().filter(|r| r.matches(&json));
    let details = audit::SaveDetails {
        last_confirmed: false,
        untested: confirmed.is_none(),
    };
    if let Some(record) = confirmed {
        let how = match record.kind() {
            core::confirmed::RecordKind::Confirmed => "applied and confirmed",
            core::confirmed::RecordKind::Unguarded => "applied (without auto-revert) and kept",
        };
        print_status(
            "✓",
            Color::Green,
            &format!("This exact ruleset was {how} on this machine."),
        );
        if !record.from_this_boot() {
            println!(
                "  That was in an earlier session (before a reboot, or recorded by an older DRFW): it may not be what is running now."
            );
        }
    } else {
        let warn = Stream::Stderr.colored();
        eprintln!(
            "{} This ruleset is not the one last applied and confirmed on this machine (with `drfw apply` or the GUI).",
            paint("WARNING:", Color::Red, warn)
        );
        eprintln!(
            "  Saved rules take effect at the next boot WITHOUT a dead-man switch: if they lock"
        );
        eprintln!("  you out of this machine, only console access gets you back in.");
        eprintln!("  Recommended: `drfw apply {name}` first, confirm, then `drfw save {name}`.");
        if !yes {
            if !std::io::stdin().is_terminal() {
                return Err(failure(
                    exit_code::NOT_CONFIRMED,
                    "not saved: pass --yes to save rules that were not applied and confirmed",
                ));
            }
            if !ask_yes_no("Save anyway?").await {
                return Err(failure(exit_code::NOT_CONFIRMED, "not saved"));
            }
        }
    }
    retention_guard(
        &ruleset,
        record.as_ref(),
        yes,
        ("Save anyway?", "not saved"),
    )
    .await?;

    let before = core::boot::query_boot_status().await;
    let service = if enable_at_boot && before.loads_at_boot() != Some(true) {
        if before.offers_enable() {
            Some(drfw::SYSTEM_NFT_SERVICE)
        } else {
            eprintln!("Cannot enable at boot: {}", before.summary());
            None
        }
    } else {
        None
    };

    println!("Saving '{name}' to {target}...");
    let output = write_config_file_and_enable(&ruleset.to_nft_text(), &target, service).await;
    let output = match output {
        Ok(output) if output.status.success() => output,
        Ok(output) => {
            let error = save_error(&output);
            audit::log_save_to_system(
                enable_event_log,
                false,
                &target,
                details,
                Some(error.clone()),
            )
            .await;
            return Err(format!("Save failed; {target} was not changed: {error}").into());
        }
        Err(e) => {
            audit::log_save_to_system(
                enable_event_log,
                false,
                &target,
                details,
                Some(e.to_string()),
            )
            .await;
            return Err(format!("Save failed: {e}").into());
        }
    };
    audit::log_save_to_system(enable_event_log, true, &target, details, None).await;
    match backup_path_from_output(&output) {
        Some(backup) => print_status(
            "✓",
            Color::Green,
            &format!(
                "Saved to {target} (previous file kept as {})",
                backup.display()
            ),
        ),
        None => print_status("✓", Color::Green, &format!("Saved to {target}")),
    }

    let enable_failed = match enable_outcome_from_output(&output) {
        Some(EnableOutcome::Failed(error)) => {
            print_status(
                "✗",
                Color::Red,
                &format!("{} was not enabled: {error}", drfw::SYSTEM_NFT_SERVICE),
            );
            true
        }
        Some(EnableOutcome::Enabled) => false,
        // Asked, but not possible (masked, missing, no systemd): said above
        None => enable_at_boot && service.is_none() && before.loads_at_boot() != Some(true),
    };
    let after = core::boot::query_boot_status().await;
    if after.loads_at_boot() == Some(true) {
        print_status("✓", Color::Green, &after.summary());
    } else {
        print_status("!", Color::Yellow, &after.summary());
        if !enable_at_boot && after.offers_enable() {
            println!("  Run `drfw save {name} --enable-at-boot` to enable it.");
        }
    }
    if enable_failed {
        return Err(failure(
            exit_code::NOT_ENABLED,
            "saved, but the boot service could not be enabled",
        ));
    }
    Ok(())
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
    let result = core::verify::locate_errors(&ruleset, result).await;
    if !result.success {
        print_status("✗", Color::Red, "nft rejected the generated ruleset:");
        print_issues(&result.issues);
        return Err("nft check failed".into());
    }
    print_status(
        "✓",
        Color::Green,
        "nft accepts the generated ruleset (checked without privileges; nothing was changed).",
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    use super::*;

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

    /// Every non-zero code is distinct, avoids the shell's 126+ and is in the
    /// help text.
    #[test]
    fn test_exit_codes_are_distinct_and_documented() {
        let codes = [
            exit_code::FAILED,
            exit_code::UNFILTERED,
            exit_code::REVERT_FAILED,
            exit_code::SUPERSEDED,
            exit_code::STATE_UNKNOWN,
            exit_code::NOT_CONFIRMED,
            exit_code::NOT_ENABLED,
            exit_code::RETENTION,
        ];
        let unique: std::collections::HashSet<u8> = codes.into_iter().collect();
        assert_eq!(unique.len(), codes.len());
        for code in codes {
            assert!(code != 2 && code < 126, "{code}");
            assert!(EXIT_CODES_HELP.contains(&format!("\n  {code}  ")), "{code}");
        }
        assert_eq!(
            exit_code_of(failure(exit_code::SUPERSEDED, "").as_ref()),
            exit_code::SUPERSEDED
        );
        let plain: Box<dyn std::error::Error> = "boom".into();
        assert_eq!(exit_code_of(plain.as_ref()), exit_code::FAILED);
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

    fn located_issue() -> VerifyIssue {
        VerifyIssue {
            origin: Some(core::verify::ErrorOrigin::UserRule {
                id: uuid::Uuid::new_v4(),
                label: "web".into(),
            }),
            message: "syntax error\nexpected any of: accept".into(),
            source_line: Some("tcp dport 80 acept comment \"web\"".into()),
            caret: Some("             ^^^^^".into()),
        }
    }

    #[test]
    fn test_issue_lines_plain() {
        let lines = issue_lines(&[located_issue(), VerifyIssue::unlocated("raw")], false);
        assert_eq!(
            lines,
            [
                "  rule \"web\": syntax error",
                "      expected any of: accept",
                "      tcp dport 80 acept comment \"web\"",
                "                   ^^^^^",
                "  raw",
            ]
        );
        assert_eq!(issue_lines(&[], false), ["  (nft gave no details)"]);
    }

    /// Color only reaches the output when the stream is a terminal; the
    /// plain form is exactly the text.
    #[test]
    fn test_color_gating() {
        assert_eq!(paint("✗", Color::Red, false), "✗");
        let plain = issue_lines(&[located_issue()], false);
        assert!(plain.iter().all(|l| !l.contains('\x1b')), "{plain:?}");
        let colored = issue_lines(&[located_issue()], true);
        // Same text once escapes are stripped (crossterm honors NO_COLOR)
        let strip = |s: &str| {
            let mut out = String::new();
            let mut chars = s.chars();
            while let Some(c) = chars.next() {
                if c == '\x1b' {
                    for c in chars.by_ref() {
                        if c.is_ascii_alphabetic() {
                            break;
                        }
                    }
                } else {
                    out.push(c);
                }
            }
            out
        };
        let stripped: Vec<String> = colored.iter().map(|l| strip(l)).collect();
        assert_eq!(stripped, plain);
    }

    #[test]
    fn test_cli_apply_examples_parse() {
        // Keep the module-level usage examples in sync with the real CLI
        for args in [
            &["drfw", "apply", "my-profile"][..],
            &["drfw", "apply", "my-profile", "--confirm", "60"],
            &["drfw", "apply", "my-profile", "--no-confirm"],
            &["drfw", "apply", "my-profile", "--no-confirm", "--yes"],
            &["drfw", "apply", "my-profile", "-y"],
            &["drfw", "export", "my-profile", "--format", "nft"],
            &["drfw", "export", "my-profile", "--format", "json"],
            &["drfw", "export", "my-profile"],
            &["drfw", "check", "my-profile"],
            &["drfw", "save", "my-profile"],
            &["drfw", "save", "my-profile", "--enable-at-boot"],
            &["drfw", "save", "my-profile", "--enable-at-boot", "--yes"],
            &["drfw", "save", "my-profile", "-y"],
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
