//! DRFW - Dumb Rust Firewall
//!
//! A safe, transparent nftables firewall for Linux, with a GUI and CLI.
//!
//! All of DRFW lives in this library; the `drfw` binary (`src/main.rs`) is the
//! command-line front end and calls [`run_gui`] when no subcommand is given.
//!
//! # Architecture
//!
//! - [`core`] - Core firewall logic, rule management, and nftables interaction
//! - `app` (private) - The iced GUI: state, message handlers and views; started by [`run_gui`]
//! - [`build_info`] - Version strings with the git commit and build time
//! - [`command`] - Undo/redo command pattern
//! - [`elevation`] - Privilege escalation (`run0`, `sudo`, `pkexec`)
//! - [`audit`] - Security audit logging for all privileged operations
//! - [`validators`] - Input validation and sanitization
//! - [`config`] - Configuration persistence
//! - [`distro`] - Compile-time paths and service name for distro packagers
//! - [`fonts`] - Font discovery for the GUI's font pickers
//! - [`theme`] - GUI color themes (`AppTheme`, presets)
//! - [`utils`] - Utility functions (XDG directories, etc.)
//!
//! # Safety Features
//!
//! - One validator ([`core::validate`]) gates every apply and Save to System
//! - Pre-apply verification with `nft --check` (unprivileged when possible)
//! - Root-side dead-man switch: unconfirmed applies revert even if DRFW dies
//! - Input sanitization and validation
//! - Atomic file operations with secure permissions

mod app;
pub mod audit;
pub mod build_info;
pub mod command;
pub mod config;
pub mod core;
pub mod distro;
pub mod elevation;
pub mod fonts;
pub mod theme;
pub mod utils;
pub mod validators;

// Re-export commonly used types
pub use core::error::{Error, Result};
pub use core::firewall::{FirewallRuleset, Protocol, Rule};

pub use app::run_gui;
// Compile-time configuration for distro packagers (see `distro`)
pub use distro::{SYSTEM_NFT_PATH, SYSTEM_NFT_SERVICE};
