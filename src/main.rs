//! DRFW - Dumb Rust Firewall
//!
//! A user-friendly GUI application for managing Linux firewall rules via nftables.
//!
//! # Features
//!
//! - Visual rule management with real-time preview
//! - Undo/redo support for all operations
//! - Rule grouping and tagging
//! - Snapshot and restore functionality
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
//! - Atomic rule application with automatic snapshots
//!
//! # Usage
//!
//! ```bash
//! # Run the GUI application
//! drfw
//!
//! # CLI commands
//! drfw list                          # List available profiles
//! drfw status                        # Show active profile
//! drfw apply my-profile              # Apply profile (permanent)
//! drfw apply my-profile --confirm    # Apply with 15s auto-revert
//! drfw apply my-profile --confirm 60 # Apply with 60s auto-revert
//! drfw export my-profile --format nft  # Export as nftables config
//! ```

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

use clap::{Parser, Subcommand};

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

/// Result of the countdown confirmation process
enum ConfirmResult {
    Confirmed,
    Reverted,
    Error(String),
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
/// Displays a countdown timer and polls for keypresses:
/// - 'c' or Enter: Confirm changes immediately
/// - 'r': Revert changes immediately
/// - Any other key or timeout: Auto-revert
async fn countdown_confirmation(timeout_secs: u64, snapshot: &serde_json::Value) -> ConfirmResult {
    use crossterm::event::{self, Event, KeyCode};
    use std::io::Write;

    // Enable raw mode for immediate keypress detection
    if let Err(e) = crossterm::terminal::enable_raw_mode() {
        return ConfirmResult::Error(format!("Failed to enable raw mode: {e}"));
    }

    let result = async {
        for remaining in (1..=timeout_secs).rev() {
            // Countdown with only the timer colored
            print!("\rAuto-revert in ");
            let _ = stdout().execute(SetForegroundColor(Color::Yellow));
            print!("{remaining:2}s");
            let _ = stdout().execute(ResetColor);
            print!("  [c/Enter=confirm, r=revert now]   ");
            std::io::stdout().flush().ok();

            // Poll for keypresses for 1 second
            if let Ok(true) = event::poll(std::time::Duration::from_secs(1))
                && let Ok(Event::Key(key)) = event::read()
            {
                match key.code {
                    KeyCode::Char('c' | 'C') | KeyCode::Enter => {
                        return ConfirmResult::Confirmed;
                    }
                    KeyCode::Char('r' | 'R') => {
                        print!("\r\x1b[K"); // Clear line
                        println!("Reverting...");
                        match core::nft_json::restore_snapshot(snapshot).await {
                            Ok(()) => return ConfirmResult::Reverted,
                            Err(e) => return ConfirmResult::Error(format!("Revert failed: {e}")),
                        }
                    }
                    _ => {
                        // Any other key ignored, continue countdown
                    }
                }
            }
        }

        // Timeout expired - auto-revert
        print!("\r\x1b[K"); // Clear line
        println!("Timeout - reverting...");
        match core::nft_json::restore_snapshot(snapshot).await {
            Ok(()) => ConfirmResult::Reverted,
            Err(e) => ConfirmResult::Error(format!("Auto-revert failed: {e}")),
        }
    }
    .await;

    // Always restore terminal to normal mode
    let _ = crossterm::terminal::disable_raw_mode();
    result
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
    /// This prevents accidental lockouts. Use --no-confirm to disable.
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
    /// Show current active profile and kernel status
    Status,
    /// Export a profile to nftables or JSON format
    Export {
        /// Name of the profile to export
        name: String,
        /// Export format (nft or json)
        #[arg(short, long, default_value = "nft")]
        format: String,
    },
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
            let nft_json = ruleset.to_nftables_json();

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
            let snapshot = core::nft_json::apply_with_snapshot(nft_json).await?;
            let _ = core::nft_json::save_snapshot_to_disk(&snapshot);

            if no_confirm {
                // Skip auto-revert (power user mode)
                let _ = stdout().execute(SetForegroundColor(Color::Green));
                print!("✓");
                let _ = stdout().execute(ResetColor);
                println!(" Rules applied permanently (no auto-revert).");
            } else {
                // Safe by default: use auto-revert
                let timeout_secs = confirm.clamp(5, 120);

                let _ = stdout().execute(SetForegroundColor(Color::Green));
                print!("✓");
                let _ = stdout().execute(ResetColor);
                println!(" Firewall rules applied!");
                println!();

                match countdown_confirmation(timeout_secs, &snapshot).await {
                    ConfirmResult::Confirmed => {
                        println!();
                        let _ = stdout().execute(SetForegroundColor(Color::Green));
                        print!("✓");
                        let _ = stdout().execute(ResetColor);
                        println!(" Changes confirmed and saved.");
                    }
                    ConfirmResult::Reverted => {
                        println!();
                        let _ = stdout().execute(SetForegroundColor(Color::Yellow));
                        print!("✓");
                        let _ = stdout().execute(ResetColor);
                        println!(" Reverted to previous state.");
                    }
                    ConfirmResult::Error(e) => {
                        println!();
                        let _ = stdout().execute(SetForegroundColor(Color::Red));
                        print!("✗");
                        let _ = stdout().execute(ResetColor);
                        println!(" Error during confirmation: {e}");
                        println!("Attempting emergency revert...");
                        core::nft_json::restore_snapshot(&snapshot).await?;
                        let _ = stdout().execute(SetForegroundColor(Color::Green));
                        print!("✓");
                        let _ = stdout().execute(ResetColor);
                        println!(" Emergency revert complete.");
                    }
                }
            }
        }
        Commands::Status => {
            let config = config::load_config().await;
            println!("Active profile: {}", config.active_profile);
            if let Ok(ruleset) = core::profiles::load_profile(&config.active_profile).await {
                println!("Rules: {}", ruleset.rules.len());
                println!(
                    "Advanced Security: {}",
                    if ruleset.advanced_security
                        == crate::core::firewall::AdvancedSecuritySettings::default()
                    {
                        "Default"
                    } else {
                        "Custom"
                    }
                );
            }
        }
        Commands::Export { name, format } => {
            let ruleset = core::profiles::load_profile(&name).await?;
            match format.as_str() {
                "nft" => println!("{}", ruleset.to_nft_text()),
                "json" => println!(
                    "{}",
                    serde_json::to_string_pretty(&ruleset.to_nftables_json())?
                ),
                _ => return Err("Invalid format. Use 'nft' or 'json'.".into()),
            }
        }
    }
    Ok(())
}

fn launch_gui() -> ExitCode {
    // Set up logging to file
    if let Some(mut log_path) = crate::utils::get_state_dir() {
        log_path.push("drfw.log");
        if let Ok(file) = std::fs::File::create(log_path) {
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
