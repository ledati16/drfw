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

use iced::Size;

fn main() -> iced::Result {
    let _ = crate::utils::ensure_dirs();

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

    iced::application(app::State::new, app::State::update, app::State::view)
        .subscription(app::State::subscription)
        .window(iced::window::Settings {
            size: Size::new(1000.0, 700.0),
            ..Default::default()
        })
        .title("Dumb Rust Firewall")
        .theme(|_state: &app::State| iced::Theme::Dark)
        .run()
}
