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
//! drfw exposure                        # Who can reach the listening services
//! drfw exposure my-profile --json
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

// `print!`/`println!` for this file: like std's, but a closed stdout
// (`drfw status | head`) silently ends the output instead of panicking
// (exit 101). SIGPIPE stays ignored (Rust's default): drfw writes to the
// stdin of nft and of the elevation tool, and a child that exits early must
// be an error to report, not a signal that kills drfw mid-apply.
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::write_stdout(format_args!($($arg)*))
    };
}
macro_rules! println {
    () => {
        $crate::write_stdout(format_args!("\n"))
    };
    ($($arg:tt)*) => {
        $crate::write_stdout(format_args!("{}\n", format_args!($($arg)*)))
    };
}

/// Writes `args` to stdout for [`print!`] and [`println!`]. Once stdout is a
/// closed pipe, all further output is dropped and the command finishes as
/// usual (with its own exit code).
///
/// # Panics
///
/// On any other write error, like `std::println!`.
fn write_stdout(args: std::fmt::Arguments<'_>) {
    use std::io::Write as _;
    use std::sync::atomic::{AtomicBool, Ordering};

    static CLOSED: AtomicBool = AtomicBool::new(false);
    if CLOSED.load(Ordering::Relaxed) {
        return;
    }
    if let Err(e) = std::io::stdout().lock().write_fmt(args) {
        assert!(
            e.kind() == std::io::ErrorKind::BrokenPipe,
            "failed printing to stdout: {e}"
        );
        CLOSED.store(true, Ordering::Relaxed);
    }
}

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
    pub const NOT_KEPT: u8 = 7;
    /// `drfw save` saved the file, but the boot service could not be enabled
    pub const NOT_ENABLED: u8 = 8;
    /// `drfw apply`/`drfw save` refused by the retention guard (most of the
    /// kept rules removed, Server Mode or "Block forwarded traffic" turned on) or the
    /// SSH lockout check (new connections from a current SSH session's
    /// client would be blocked) without `--yes` (or the question was
    /// answered no); nothing was changed
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
     kept (confirmed, or applied with --no-confirm) with `drfw apply`
     or the GUI (pass --yes to save anyway)
  8  save: saved, but the boot service could not be enabled
  9  apply/save: not done: the ruleset removes most of the rules last
     applied and kept, turns on Server Mode or \"Block forwarded traffic\", or would
     block new SSH connections from a current session's client
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
    // Keys typed before the countdown (an extra Enter after the sudo or run0
    // password) must not confirm it: discard the terminal's pending input
    // and anything crossterm has buffered already
    let _ = nix::sys::termios::tcflush(std::io::stdin(), nix::sys::termios::FlushArg::TCIFLUSH);
    while let Ok(true) = event::poll(std::time::Duration::ZERO) {
        if event::read().is_err() {
            break;
        }
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
#[command(
    about = "DRFW (Dumb Rust Firewall): a safe, transparent nftables firewall for Linux, with a GUI and CLI",
    long_about = None
)]
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
    /// least 3 and 40 % of the enabled ones; disabled counts as removed),
    /// turns on Server Mode or "Block forwarded traffic", or would block (or may
    /// block) new SSH connections from the client of a current SSH session,
    /// needs --yes (or an answer on a terminal). Open sessions survive any
    /// apply; the check is about reconnecting.
    #[command(after_help = EXIT_CODES_HELP)]
    Apply {
        /// Name of the profile to apply
        name: String,
        /// Auto-revert timeout in seconds, 5 to 120
        #[arg(
            short,
            long,
            value_name = "SECONDS",
            default_value = "15",
            value_parser = clap::value_parser!(u64).range(5..=120)
        )]
        confirm: u64,
        /// Skip auto-revert confirmation (apply immediately without safety
        /// net); the rules count as kept at once
        #[arg(long, conflicts_with = "confirm")]
        no_confirm: bool,
        /// Apply even if it removes most of the rules last applied and kept,
        /// turns on Server Mode or "Block forwarded traffic", or could lock out SSH
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
    /// terminal). So does one that removes most of the kept rules, turns on
    /// Server Mode or "Block forwarded traffic", or would block new SSH connections
    /// from the client of a current SSH session.
    #[command(after_help = EXIT_CODES_HELP)]
    Save {
        /// Name of the profile to save
        name: String,
        /// Also enable the boot service if it is not enabled (same prompt)
        #[arg(long)]
        enable_at_boot: bool,
        /// Save even if this exact ruleset is not the one last applied and
        /// kept on this machine, or the retention guard or the SSH lockout
        /// check warns
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
    /// Show who can reach the services listening on this computer
    ///
    /// Lists the listening TCP/UDP sockets (read from /proc, no privileges)
    /// and, for each, who could open a new connection to it under a
    /// profile's rules (default: the active profile) and the rule that
    /// decides. The processes of other users' sockets need root to name and
    /// show as "unknown". The rules are the profile's, not necessarily the
    /// ones running now (listing those needs root). Also says whether the
    /// clients of current SSH sessions could reconnect.
    Exposure {
        /// Name of the profile to evaluate (default: the active profile)
        name: Option<String>,
        /// Print JSON (for scripts) instead of a table
        #[arg(long)]
        json: bool,
    },
    /// Print the systemd unit `drfw.service` for this build (for packagers)
    ///
    /// Fills `contrib/drfw.service.in` with the paths this binary was compiled
    /// with (`DRFW_SYSTEM_NFT_PATH`, `DRFW_NFT_PATH`), so the packaged unit
    /// loads exactly the file Save to System writes.
    #[command(hide = true)]
    PrintServiceUnit,
    /// Print the polkit action `org.drfw.helper` for this build (for packagers)
    ///
    /// Fills `contrib/org.drfw.helper.policy.in` with the helper path this
    /// binary was compiled with (`DRFW_HELPER_PATH`), so the installed action
    /// names exactly the helper DRFW elevates.
    #[command(hide = true)]
    PrintPolkitPolicy,
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
    match cli.command {
        Some(Commands::PrintServiceUnit) => {
            print!("{}", drfw::distro::service_unit());
            return ExitCode::SUCCESS;
        }
        Some(Commands::PrintPolkitPolicy) => {
            print!("{}", drfw::distro::polkit_policy());
            return ExitCode::SUCCESS;
        }
        _ => {}
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
            let sessions = current_ssh_sessions().await;
            confirmation_guard(
                &ruleset,
                record.as_ref(),
                &sessions,
                yes,
                ("Apply anyway?", "not applied"),
            )
            .await?;

            println!();
            println!("Applying ruleset...");
            let timeout_secs = if no_confirm { 0 } else { confirm };
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
        Commands::PrintPolkitPolicy => print!("{}", drfw::distro::polkit_policy()),
        Commands::Check { name } => check_profile(&name).await?,
        Commands::Exposure { name, json } => print_exposure(name, json).await?,
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

/// The "Forwarding:" line of `drfw status`: off, blocked by the profile, or
/// the forwarding notice ([`core::host_facts::FORWARDING_WARNING`]).
fn forwarding_status(
    forwarding: core::host_facts::ForwardingState,
    ruleset: &core::firewall::FirewallRuleset,
) -> String {
    if let Some(warning) = core::host_facts::forwarding_warning(forwarding, ruleset) {
        warning.to_string()
    } else if forwarding.any() {
        "IP forwarding is on; this profile blocks forwarded traffic unless a Forwarded rule \
         allows it"
            .to_string()
    } else {
        "IP forwarding is off".to_string()
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
            status_line(
                "Forwarding",
                &forwarding_status(core::host_facts::forwarding_enabled(), &ruleset),
            );
            let sessions = current_ssh_sessions().await;
            print_ssh_status(&ruleset, &sessions);
        }
        Err(e) => status_line("Rules", &format!("profile cannot be loaded: {e}")),
    }

    let guard_dir = std::path::Path::new(elevation::GUARD_STATE_DIR);
    let guard = match core::apply_guard::pending_guard(guard_dir) {
        Ok(None) => "none pending".to_string(),
        Ok(Some(pending)) => pending_guard_status(
            &pending
                .armed_at
                .map_or_else(|| "an unknown time".to_string(), local_time),
            pending.watcher,
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

/// The `Auto-revert` line of `drfw status` for a pending guard armed `since`.
fn pending_guard_status(since: &str, watcher: core::apply_guard::WatcherState) -> String {
    use core::apply_guard::WatcherState;
    match watcher {
        WatcherState::Running => format!(
            "PENDING since {since}: the last apply reverts automatically unless it is confirmed"
        ),
        WatcherState::Gone => format!(
            "LOST since {since}: the last apply was never confirmed, but its revert guard \
             ended without reverting; its rules stay active. Apply again to keep or replace them"
        ),
        WatcherState::Unknown => format!(
            "PENDING since {since}: the last apply reverts automatically unless it is confirmed \
             (whether its revert guard still runs could not be checked)"
        ),
    }
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

/// The SSH sessions into this computer (`SSH_CONNECTION` and `/proc`; see
/// `core::lockout`).
async fn current_ssh_sessions() -> Vec<core::lockout::SshSession> {
    let env = core::lockout::session_from_env();
    let fallback = env.clone();
    tokio::task::spawn_blocking(move || core::lockout::detect_sessions(env))
        .await
        .unwrap_or_else(|_| fallback.into_iter().collect())
}

/// The confirmation for `drfw apply` and `drfw save`: the retention guard
/// (`core::retention`: `ruleset` is a big change compared with the rules
/// last applied and kept) and the SSH lockout check (`core::lockout`: new
/// connections from a current session's client would be blocked). Prints
/// every warning, then asks once on a terminal unless `yes`. The lockout
/// check's notes (new SSH connections only limited by a rate or connection
/// limit) are printed without a question.
/// `(question, refused)` are e.g. `("Apply anyway?", "not applied")`.
///
/// # Errors
///
/// [`exit_code::RETENTION`] when it warns, `yes` is not set and stdin is not
/// a terminal, or the answer is not yes.
async fn confirmation_guard(
    ruleset: &core::firewall::FirewallRuleset,
    record: Option<&core::confirmed::ConfirmedRecord>,
    sessions: &[core::lockout::SshSession],
    yes: bool,
    (question, refused): (&str, &str),
) -> Result<(), Box<dyn std::error::Error>> {
    let kept = record.and_then(core::confirmed::ConfirmedRecord::ruleset);
    let retention = core::retention::RetentionWarning::check(kept, ruleset);
    let lockout = core::lockout::LockoutWarning::check(ruleset, sessions);
    let warn = Stream::Stderr.colored();
    if let Some(warning) = &retention {
        eprintln!(
            "{} This is a big change compared with the rules last applied and kept:",
            paint("WARNING:", Color::Red, warn)
        );
        for line in &warning.lines {
            eprintln!("  {line}");
        }
    }
    let mut needs_confirmation = retention.is_some();
    if let Some(warning) = &lockout {
        if warning.needs_confirmation() {
            needs_confirmation = true;
            eprintln!(
                "{} {}",
                paint("WARNING:", Color::Red, warn),
                core::lockout::LockoutWarning::HEADING
            );
            for line in &warning.lines {
                eprintln!("  {line}");
            }
        }
        if !warning.notes.is_empty() {
            eprintln!(
                "{} {}",
                paint("Note:", Color::Yellow, warn),
                core::lockout::LockoutWarning::NOTE_HEADING
            );
            for line in &warning.notes {
                eprintln!("  {line}");
            }
        }
    }
    if !needs_confirmation || yes {
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
/// [`exit_code::NOT_KEPT`] when refused for want of a confirmation,
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
            core::confirmed::RecordKind::Confirmed => "applied and kept (confirmed)",
            core::confirmed::RecordKind::Unguarded => "applied and kept (without auto-revert)",
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
            "{} This ruleset is not the one last applied and kept on this machine (with `drfw apply` or the GUI).",
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
                    exit_code::NOT_KEPT,
                    "not saved: pass --yes to save rules that were not applied and kept",
                ));
            }
            if !ask_yes_no("Save anyway?").await {
                return Err(failure(exit_code::NOT_KEPT, "not saved"));
            }
        }
    }
    let sessions = current_ssh_sessions().await;
    confirmation_guard(
        &ruleset,
        record.as_ref(),
        &sessions,
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
    let payload = core::root_payload::SavePayload::of_ruleset(&ruleset);
    let output = write_config_file_and_enable(&payload, &target, service).await;
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

/// The "SSH" lines of `drfw status`: for each SSH session, whether its
/// client could open a new connection under `ruleset` (the active profile).
fn print_ssh_status(
    ruleset: &core::firewall::FirewallRuleset,
    sessions: &[core::lockout::SshSession],
) {
    let checks = core::lockout::check_sessions(ruleset, sessions);
    if checks.is_empty() {
        status_line("SSH", "no SSH session into this computer found");
        return;
    }
    let color = Stream::Stdout.colored();
    for (i, check) in checks.iter().enumerate() {
        let text = check.summary();
        let text = if check.access.needs_confirmation() {
            paint(&text, Color::Red, color)
        } else {
            text
        };
        if i == 0 {
            status_line("SSH", &text);
        } else {
            println!("{:STATUS_LABEL_WIDTH$}{text}", "");
        }
    }
}

/// Marker of sockets every address can reach on any interface (`drfw
/// exposure`): text, not color alone.
const OPEN_MARKER: &str = "OPEN TO EVERYONE";

/// `"any"` when every address can connect on any interface, `"interfaces"`
/// when only on [`core::exposure::SocketExposure::open_on_interfaces`],
/// `None` otherwise (`scope` of `drfw exposure --json`).
fn open_scope_json(exposure: &core::exposure::SocketExposure) -> Option<&'static str> {
    if exposure.open_to_everyone {
        Some("any")
    } else if exposure.open_on_interfaces.is_empty() {
        None
    } else {
        Some("interfaces")
    }
}

/// Lowercase name of a transport for `--json`.
const fn transport_json(transport: core::evaluate::Transport) -> &'static str {
    match transport {
        core::evaluate::Transport::Tcp => "tcp",
        core::evaluate::Transport::Udp => "udp",
    }
}

/// Lowercase name of an address family for `--json`.
const fn family_json(family: core::evaluate::IpFamily) -> &'static str {
    match family {
        core::evaluate::IpFamily::V4 => "ipv4",
        core::evaluate::IpFamily::V6 => "ipv6",
    }
}

/// The `drfw exposure --json` document: the profile, one object per socket
/// and one per SSH session check.
fn exposure_json(
    profile: &str,
    rows: &[core::exposure::ExposureRow],
    checks: &[core::lockout::SessionCheck],
    notes: &ExposureNotes,
) -> serde_json::Value {
    let sockets: Vec<serde_json::Value> = rows
        .iter()
        .map(|row| {
            let socket = &row.socket;
            let exposure = &row.exposure;
            serde_json::json!({
                "transport": transport_json(socket.transport),
                "port": socket.port,
                "families": socket.families.iter().map(|&f| family_json(f)).collect::<Vec<_>>(),
                "bind": socket.bind.to_string(),
                "bind_display": socket.bind_display,
                "local_only": exposure.local_only,
                "uid": socket.uid,
                "process": socket.process_display,
                "processes": socket.processes.iter().map(|p| serde_json::json!({
                    "pid": p.pid,
                    "name": p.name,
                })).collect::<Vec<_>>(),
                "reachable_from": exposure.summary,
                "open_to_everyone": exposure.open_to_everyone,
                "scope": open_scope_json(exposure),
                "interfaces": exposure.open_on_interfaces,
                "nobody": exposure.nobody,
                "published_by_docker": exposure.docker_published,
                "docker_forward_filtered": exposure.docker_forward_filtered,
                "local_discovery": exposure.local_discovery,
                "decided_by": (!exposure.decided_by_display.is_empty())
                    .then_some(&exposure.decided_by_display),
                "decided_by_rule_id": exposure
                    .decided_by
                    .as_ref()
                    .and_then(core::evaluate::Decider::rule_id)
                    .map(|id| id.to_string()),
            })
        })
        .collect();
    let sessions: Vec<serde_json::Value> = checks
        .iter()
        .map(|check| {
            let session = &check.session;
            serde_json::json!({
                "client": session.client.to_string(),
                "client_port": session.client_port,
                "server": session.server.to_string(),
                "server_port": session.server_port,
                "source": session.source.as_str(),
                "interface": session.interface,
                "new_connections": check.access.as_str(),
                "outcome": check.outcome,
            })
        })
        .collect();
    serde_json::json!({
        "profile": profile,
        "sockets": sockets,
        "ssh_sessions": sessions,
        "forwarding": {
            "ipv4": notes.forwarding.ipv4,
            "ipv6": notes.forwarding.ipv6,
            "filtered": notes.forwarding_warning.is_none(),
        },
        "notes": notes.lines(),
    })
}

/// What `drfw exposure` says besides the rows: the forwarding notice and the
/// container-network note, when they apply.
struct ExposureNotes {
    forwarding: core::host_facts::ForwardingState,
    forwarding_warning: Option<&'static str>,
    containers: Option<&'static str>,
}

impl ExposureNotes {
    fn new(
        forwarding: core::host_facts::ForwardingState,
        containers: &core::host_facts::ContainerFacts,
        ruleset: &core::firewall::FirewallRuleset,
    ) -> Self {
        Self {
            forwarding,
            forwarding_warning: core::host_facts::forwarding_warning(forwarding, ruleset),
            containers: containers.note_for(ruleset.advanced_security.block_forwarding),
        }
    }

    /// The notes that apply, in print order.
    fn lines(&self) -> Vec<&'static str> {
        self.forwarding_warning
            .into_iter()
            .chain(self.containers)
            .collect()
    }
}

/// The `drfw exposure` table: one line per socket (columns padded to the
/// widest cell), the open-to-everyone ones first and marked with
/// [`OPEN_MARKER`] (in red on a terminal), then those open to everyone on
/// some interfaces only, marked "OPEN ON <interfaces>" (in yellow).
fn exposure_table(rows: &[core::exposure::ExposureRow], color: bool) -> Vec<String> {
    const HEADERS: [&str; 6] = [
        "PORT",
        "FAMILY",
        "PROCESS",
        "BIND",
        "REACHABLE FROM",
        "DECIDED BY",
    ];
    let cells: Vec<[String; 6]> = rows
        .iter()
        .map(|row| {
            let reach = if row.exposure.local_only {
                "local only".to_string()
            } else if row.exposure.docker_published {
                row.exposure.summary.clone()
            } else if row.exposure.open_to_everyone {
                format!("{OPEN_MARKER}: {}", row.exposure.summary)
            } else if let Some(badge) = row.exposure.open_on_badge() {
                format!("{badge}: {}", row.exposure.summary)
            } else {
                row.exposure.summary.clone()
            };
            [
                format!(
                    "{} {}",
                    row.socket.transport.display_name(),
                    row.socket.port
                ),
                row.socket.family_display.to_string(),
                row.socket.process_display.clone(),
                row.socket.bind_display.clone(),
                reach,
                row.exposure.decided_by_display.clone(),
            ]
        })
        .collect();
    let mut widths = HEADERS.map(str::len);
    for row in &cells {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    let line = |cells: &[String]| -> String {
        let mut out = String::new();
        for (i, (cell, width)) in cells.iter().zip(widths).enumerate() {
            if i + 1 == cells.len() {
                out.push_str(cell);
            } else {
                let pad = width - cell.chars().count() + 2;
                let cell = if let Some(rest) = cell.strip_prefix(OPEN_MARKER) {
                    format!("{}{rest}", paint(OPEN_MARKER, Color::Red, color))
                } else if cell.starts_with(core::exposure::OPEN_ON_BADGE_PREFIX)
                    && let Some((marker, rest)) = cell.split_once(':')
                {
                    format!("{}:{rest}", paint(marker, Color::Yellow, color))
                } else {
                    cell.clone()
                };
                out.push_str(&cell);
                out.extend(std::iter::repeat_n(' ', pad));
            }
        }
        out.trim_end().to_string()
    };
    let mut lines = Vec::with_capacity(cells.len() + 1);
    lines.push(line(&HEADERS.map(str::to_string)));
    lines.extend(cells.iter().map(|row| line(row)));
    lines
}

/// `drfw exposure`: the listening sockets and who can reach them under the
/// rules of profile `name` (default: the active profile), plus the SSH
/// session check. Reads `/proc` only; changes nothing.
///
/// # Errors
///
/// The profile cannot be loaded, or the sockets cannot be read.
async fn print_exposure(
    name: Option<String>,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::fmt::Write as _;

    let name = match name {
        Some(name) => name,
        None => config::load_config().await.active_profile,
    };
    let ruleset = core::profiles::load_profile(&name).await?;
    let env = core::lockout::session_from_env();
    let (scan, sessions, forwarding, containers) = tokio::task::spawn_blocking(move || {
        core::exposure::scan_host().map(|scan| {
            let found = core::lockout::sessions_from_scan(&scan);
            let sessions =
                core::lockout::with_interfaces(core::lockout::merge_sessions(env, found));
            (
                scan,
                sessions,
                core::host_facts::forwarding_enabled(),
                core::host_facts::ContainerFacts::read(),
            )
        })
    })
    .await?
    .map_err(|e| format!("cannot read the listening sockets: {e}"))?;
    let mut rows = core::exposure::exposure_rows(&ruleset, &scan.sockets);
    let published = core::exposure::mark_docker_published(&mut rows, &containers);
    let checks = core::lockout::check_sessions(&ruleset, &sessions);
    let notes = ExposureNotes::new(forwarding, &containers, &ruleset);

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&exposure_json(&name, &rows, &checks, &notes))?
        );
        return Ok(());
    }

    let color = Stream::Stdout.colored();
    println!(
        "Who can open a new connection under the rules of profile '{name}' \
         (open connections are always accepted):"
    );
    println!();
    if rows.is_empty() {
        println!("No listening sockets found.");
    } else {
        for line in exposure_table(&rows, color) {
            println!("{line}");
        }
        let open = rows.iter().filter(|r| r.exposure.open_to_everyone).count();
        let open_on = rows
            .iter()
            .filter(|r| !r.exposure.open_on_interfaces.is_empty())
            .count();
        let noun = if rows.len() == 1 { "socket" } else { "sockets" };
        println!();
        let mut summary = format!("{} listening {noun}, {open} open to everyone", rows.len());
        if open_on > 0 {
            let _ = write!(
                summary,
                ", {open_on} open to everyone on some interfaces only"
            );
        }
        if published > 0 {
            let _ = write!(summary, ", {published} published by Docker");
            if ruleset.advanced_security.block_forwarding {
                summary.push_str(" (decided by your Forwarded rules)");
            }
        }
        println!("{summary}.");
    }
    for note in notes.lines() {
        println!("{note}");
    }
    for check in &checks {
        let text = format!("SSH: {}", check.summary());
        if check.access.needs_confirmation() {
            println!("{}", paint(&text, Color::Red, color));
        } else {
            println!("{text}");
        }
    }
    if scan
        .sockets
        .iter()
        .any(|s| s.processes.is_empty() && s.uid != nix::unistd::getuid().as_raw())
    {
        println!(
            "Processes of other users' sockets need root to name; DRFW does not use it for this."
        );
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
            exit_code::NOT_KEPT,
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

    fn exposure_fixture() -> Vec<core::exposure::ExposureRow> {
        exposure_fixture_with(None)
    }

    /// The fixture's rows; with `tailnet`, a rule accepting all TCP on that
    /// interface follows the SSH rule.
    fn exposure_fixture_with(tailnet: Option<&str>) -> Vec<core::exposure::ExposureRow> {
        use drfw::core::evaluate::Transport;
        use drfw::core::exposure::{ListeningSocket, ProcessInfo, build_socket_list};

        let socket = |port, local: &str, inode| ListeningSocket {
            transport: Transport::Tcp,
            ipv6_socket: false,
            local: local.parse().unwrap(),
            port,
            uid: 1000,
            inode,
        };
        let mut owners = std::collections::HashMap::new();
        owners.insert(
            1,
            vec![ProcessInfo {
                pid: 7,
                name: "sshd".into(),
            }],
        );
        let sockets = build_socket_list(
            vec![
                socket(22, "0.0.0.0", 1),
                socket(631, "127.0.0.1", 2),
                socket(8080, "0.0.0.0", 3),
            ],
            &owners,
            1000,
            false,
            |_| None,
        );
        let mut ruleset = core::firewall::FirewallRuleset::new();
        let mut ssh = core::firewall::Rule::with_caches(
            uuid::Uuid::new_v4(),
            "SSH".into(),
            core::firewall::Protocol::Tcp,
            vec![core::firewall::PortEntry::Single(22)],
            vec![],
            None,
            core::firewall::Chain::Input,
            true,
            jiff::Timestamp::now(),
            vec![],
        );
        ssh.rebuild_caches();
        ruleset.rules.push(ssh);
        if let Some(interface) = tailnet {
            let mut rule = core::firewall::Rule::with_caches(
                uuid::Uuid::new_v4(),
                "Tailnet".into(),
                core::firewall::Protocol::Tcp,
                vec![],
                vec![],
                Some(interface.to_string()),
                core::firewall::Chain::Input,
                true,
                jiff::Timestamp::now(),
                vec![],
            );
            rule.rebuild_caches();
            ruleset.rules.push(rule);
        }
        core::exposure::exposure_rows(&ruleset, &sockets)
    }

    /// Everyone on one interface is marked as such, in text and JSON, and
    /// listed after the sockets open on any interface.
    #[test]
    fn test_exposure_marks_interface_scoped_sockets() {
        let rows = exposure_fixture_with(Some("tailscale0"));
        let lines = exposure_table(&rows, false);
        assert!(lines[1].starts_with("TCP 22"), "{lines:?}");
        assert!(lines[1].contains("OPEN TO EVERYONE: everyone"), "{lines:?}");
        assert!(lines[2].starts_with("TCP 8080"), "{lines:?}");
        assert!(
            lines[2].contains("OPEN ON tailscale0: everyone on tailscale0"),
            "{lines:?}"
        );
        assert!(!lines[2].contains("OPEN TO EVERYONE"), "{lines:?}");
        let colored = exposure_table(&rows, true);
        assert!(colored[2].contains('\x1b') || std::env::var_os("NO_COLOR").is_some());

        let ruleset = core::firewall::FirewallRuleset::new();
        let notes = ExposureNotes::new(
            core::host_facts::ForwardingState::default(),
            &core::host_facts::ContainerFacts::default(),
            &ruleset,
        );
        let json = exposure_json(
            "p",
            &rows,
            &core::lockout::check_sessions(&ruleset, &[]),
            &notes,
        );
        let ssh = &json["sockets"][0];
        assert_eq!(ssh["scope"], "any");
        assert_eq!(ssh["interfaces"], serde_json::json!([]));
        let web = &json["sockets"][1];
        assert_eq!(web["port"], 8080);
        assert_eq!(web["open_to_everyone"], false);
        assert_eq!(web["scope"], "interfaces");
        assert_eq!(web["interfaces"], serde_json::json!(["tailscale0"]));
        assert_eq!(web["reachable_from"], "everyone on tailscale0");
        let local = json["sockets"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["port"] == 631)
            .unwrap();
        assert!(local["scope"].is_null());
    }

    #[test]
    fn test_exposure_table_marks_open_sockets_with_text() {
        let lines = exposure_table(&exposure_fixture(), false);
        assert_eq!(lines.len(), 4);
        assert!(lines[0].starts_with("PORT"), "{lines:?}");
        assert!(lines[0].contains("REACHABLE FROM"), "{lines:?}");
        // Open first, marked in text; columns line up
        assert!(lines[1].starts_with("TCP 22"), "{lines:?}");
        assert!(lines[1].contains("OPEN TO EVERYONE: everyone"), "{lines:?}");
        assert!(lines[1].ends_with("rule \"SSH\""), "{lines:?}");
        let column = lines[0].find("PROCESS").unwrap();
        assert_eq!(lines[1].find("sshd"), Some(column), "{lines:?}");
        let local = lines.iter().find(|l| l.starts_with("TCP 631")).unwrap();
        assert!(
            local.contains("local only") && !local.contains("OPEN"),
            "{local}"
        );
        assert!(
            lines.iter().all(|l| !l.contains('\x1b')),
            "no color off a terminal"
        );
        let colored = exposure_table(&exposure_fixture(), true);
        assert!(colored[1].contains('\x1b') || std::env::var_os("NO_COLOR").is_some());
    }

    #[test]
    fn test_exposure_json_shape() {
        let session = core::lockout::parse_ssh_connection("10.0.0.5 50000 10.0.0.1 2222").unwrap();
        let rows = exposure_fixture();
        let ruleset = core::firewall::FirewallRuleset::new();
        let checks = core::lockout::check_sessions(&ruleset, &[session]);
        let notes = ExposureNotes::new(
            core::host_facts::ForwardingState {
                ipv4: true,
                ipv6: false,
            },
            &core::host_facts::ContainerFacts {
                published: Vec::new(),
                bridges: true,
            },
            &ruleset,
        );
        let json = exposure_json("web", &rows, &checks, &notes);
        assert_eq!(json["profile"], "web");
        assert_eq!(json["forwarding"]["ipv4"], true);
        assert_eq!(json["forwarding"]["filtered"], false);
        assert_eq!(
            json["notes"],
            serde_json::json!([
                core::host_facts::FORWARDING_WARNING,
                core::host_facts::CONTAINER_NETWORKS_NOTE
            ])
        );
        assert_eq!(json["sockets"][0]["published_by_docker"], false);
        let ssh = &json["sockets"][0];
        assert_eq!(ssh["transport"], "tcp");
        assert_eq!(ssh["port"], 22);
        assert_eq!(ssh["families"], serde_json::json!(["ipv4"]));
        assert_eq!(ssh["bind"], "0.0.0.0");
        assert_eq!(ssh["process"], "sshd");
        assert_eq!(ssh["processes"][0]["pid"], 7);
        assert_eq!(ssh["open_to_everyone"], true);
        assert_eq!(ssh["reachable_from"], "everyone");
        assert_eq!(ssh["decided_by"], "rule \"SSH\"");
        assert!(ssh["decided_by_rule_id"].is_string());
        let local = json["sockets"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["port"] == 631)
            .unwrap();
        assert_eq!(local["local_only"], true);
        assert!(local["decided_by"].is_null());
        let session = &json["ssh_sessions"][0];
        assert_eq!(session["client"], "10.0.0.5");
        assert_eq!(session["server_port"], 2222);
        assert_eq!(session["source"], "environment");
        assert_eq!(session["new_connections"], "blocked");
    }

    /// With local network discovery on, the mDNS socket reads "local network
    /// (discovery)" (not open) in the table and the JSON, and an ordinary
    /// UDP socket stays "nobody".
    #[test]
    fn test_exposure_local_discovery_in_table_and_json() {
        use drfw::core::evaluate::Transport;
        use drfw::core::exposure::{LOCAL_DISCOVERY, ListeningSocket, build_socket_list};

        let socket = |port, inode| ListeningSocket {
            transport: Transport::Udp,
            ipv6_socket: false,
            local: "0.0.0.0".parse().unwrap(),
            port,
            uid: 1000,
            inode,
        };
        let sockets = build_socket_list(
            vec![socket(5353, 1), socket(40000, 2)],
            &std::collections::HashMap::new(),
            1000,
            false,
            |_| None,
        );
        let mut ruleset = core::firewall::FirewallRuleset::new();
        ruleset.advanced_security.local_discovery = true;
        let rows = core::exposure::exposure_rows(&ruleset, &sockets);
        let lines = exposure_table(&rows, false);
        let mdns = lines.iter().find(|l| l.starts_with("UDP 5353")).unwrap();
        assert!(
            mdns.contains(LOCAL_DISCOVERY) && !mdns.contains("OPEN"),
            "{mdns}"
        );
        assert!(mdns.ends_with("built-in rule \"allow mdns\""), "{mdns}");
        let other = lines.iter().find(|l| l.starts_with("UDP 40000")).unwrap();
        assert!(other.contains("nobody"), "{other}");

        let notes = ExposureNotes::new(
            core::host_facts::ForwardingState::default(),
            &core::host_facts::ContainerFacts::default(),
            &ruleset,
        );
        let json = exposure_json("p", &rows, &[], &notes);
        let find = |port: u16| {
            json["sockets"]
                .as_array()
                .unwrap()
                .iter()
                .find(|s| s["port"] == port)
                .unwrap()
                .clone()
        };
        let mdns = find(5353);
        assert_eq!(mdns["reachable_from"], LOCAL_DISCOVERY);
        assert_eq!(mdns["local_discovery"], true);
        assert_eq!(mdns["nobody"], false);
        assert_eq!(mdns["open_to_everyone"], false);
        assert!(mdns["scope"].is_null());
        let other = find(40000);
        assert_eq!(other["local_discovery"], false);
        assert_eq!(other["nobody"], true);
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
            &["drfw", "exposure"],
            &["drfw", "exposure", "my-profile"],
            &["drfw", "exposure", "--json"],
            &["drfw", "exposure", "my-profile", "--json"],
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
