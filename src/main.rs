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

use clap::{Parser, Subcommand};
use iced::Size;
use std::process::ExitCode;

/// Result of the countdown confirmation process
enum ConfirmResult {
    Confirmed,
    Reverted,
    Error(String),
}

/// Interactive countdown with confirmation/revert controls
///
/// Displays a countdown timer and polls for keypresses:
/// - 'c' or Enter: Confirm changes immediately
/// - 'r': Revert changes immediately
/// - Any other key or timeout: Auto-revert
async fn countdown_confirmation(
    timeout_secs: u64,
    snapshot: &serde_json::Value,
) -> ConfirmResult {
    use crossterm::event::{self, Event, KeyCode};
    use std::io::Write;

    // Enable raw mode for immediate keypress detection
    if let Err(e) = crossterm::terminal::enable_raw_mode() {
        return ConfirmResult::Error(format!("Failed to enable raw mode: {e}"));
    }

    let result = async {
        for remaining in (1..=timeout_secs).rev() {
            print!(
                "\rAuto-revert in {:3}s  [c/Enter=confirm, r=revert now]   ",
                remaining
            );
            std::io::stdout().flush().ok();

            // Poll for keypresses for 1 second
            if let Ok(true) = event::poll(std::time::Duration::from_secs(1))
                && let Ok(Event::Key(key)) = event::read()
            {
                match key.code {
                    KeyCode::Char('c') | KeyCode::Char('C') | KeyCode::Enter => {
                        return ConfirmResult::Confirmed;
                    }
                    KeyCode::Char('r') | KeyCode::Char('R') => {
                        print!("\r\x1b[K");  // Clear line
                        println!("Reverting...");
                        match core::nft_json::restore_snapshot(snapshot).await {
                            Ok(()) => return ConfirmResult::Reverted,
                            Err(e) => {
                                return ConfirmResult::Error(format!("Revert failed: {e}"))
                            }
                        }
                    }
                    _ => {
                        // Any other key ignored, continue countdown
                    }
                }
            }
        }

        // Timeout expired - auto-revert
        print!("\r\x1b[K");  // Clear line
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
    Apply {
        /// Name of the profile to apply
        name: String,
        /// Enable auto-revert with confirmation timeout (seconds, default: 15, max: 300)
        #[arg(short, long, value_name = "SECONDS")]
        confirm: Option<u64>,
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
        Commands::Apply { name, confirm } => {
            let ruleset = core::profiles::load_profile(&name).await?;
            let nft_json = ruleset.to_nftables_json();

            // Verify first
            println!("Verifying profile '{name}'...");
            let verify_result = core::verify::verify_ruleset(nft_json.clone()).await?;
            if !verify_result.success {
                return Err(
                    format!("Verification failed:\n{}", verify_result.errors.join("\n")).into(),
                );
            }

            // Elevation check
            let is_root = nix::unistd::getuid().is_root();
            if !is_root {
                println!("Note: Not running as root. Will use sudo/pkexec for apply.");
            }

            println!("Applying ruleset...");
            let snapshot = core::nft_json::apply_with_snapshot(nft_json).await?;
            let _ = core::nft_json::save_snapshot_to_disk(&snapshot);

            if let Some(timeout_secs) = confirm {
                // Clamp timeout to reasonable range (1-300 seconds / 5 minutes)
                let timeout_secs = timeout_secs.clamp(1, 300);

                println!("✓ Firewall rules applied!");
                println!();

                match countdown_confirmation(timeout_secs, &snapshot).await {
                    ConfirmResult::Confirmed => {
                        println!("\n✓ Changes confirmed and saved.");
                    }
                    ConfirmResult::Reverted => {
                        println!("\n✓ Reverted to previous state.");
                    }
                    ConfirmResult::Error(e) => {
                        eprintln!("\n✗ Error during confirmation: {e}");
                        eprintln!("Attempting emergency revert...");
                        core::nft_json::restore_snapshot(&snapshot).await?;
                        println!("✓ Emergency revert complete.");
                    }
                }
            } else {
                println!("✓ Rules applied to kernel.");
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
