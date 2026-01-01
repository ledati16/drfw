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
        /// Enable 15-second auto-revert safety window
        #[arg(short, long)]
        test: bool,
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
            let profiles = core::profiles::list_profiles()?;
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
        Commands::Apply { name, test } => {
            let ruleset = core::profiles::load_profile(&name)?;
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
                println!("Note: Not running as root. Will use sudo for apply.");
            }

            println!("Applying ruleset...");
            let snapshot = core::nft_json::apply_with_snapshot(nft_json).await?;
            let _ = core::nft_json::save_snapshot_to_disk(&snapshot);

            if test {
                println!("Success! Rules applied. AUTO-REVERT ENABLED (15 seconds).");
                println!("Press Enter to confirm and stay, or wait for revert...");

                let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);
                std::thread::spawn(move || {
                    let mut input = String::new();
                    let _ = std::io::stdin().read_line(&mut input);
                    let _ = tx.blocking_send(());
                });

                tokio::select! {
                    _ = rx.recv() => {
                        println!("Changes confirmed.");
                    }
                    _ = tokio::time::sleep(std::time::Duration::from_secs(15)) => {
                        println!("\nTimeout reached. Reverting to snapshot...");
                        core::nft_json::restore_snapshot(&snapshot).await?;
                        println!("Revert complete.");
                    }
                }
            } else {
                println!("Success! Rules applied to kernel.");
            }
        }
        Commands::Status => {
            let config = config::load_config().await;
            println!("Active profile: {}", config.active_profile);
            if let Ok(ruleset) = core::profiles::load_profile(&config.active_profile) {
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
            let ruleset = core::profiles::load_profile(&name)?;
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
