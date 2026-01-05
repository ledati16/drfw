//! DRFW - Dumb Rust Firewall
//!
//! A graphical nftables firewall manager with a focus on safety and usability.
//!
//! # Architecture
//!
//! - [`core`] - Core firewall logic, rule management, and nftables interaction
//! - [`audit`] - Security audit logging for all privileged operations
//! - [`validators`] - Input validation and sanitization
//! - [`config`] - Configuration persistence
//! - [`utils`] - Utility functions (XDG directories, etc.)
//!
//! # Safety Features
//!
//! - Pre-apply verification with `nft --check`
//! - 15-second dead-man switch for auto-rollback
//! - Emergency default ruleset fallback
//! - SHA-256 snapshot checksums
//! - Input sanitization and validation
//! - Atomic file operations with secure permissions

// Allow pedantic clippy warnings that are not worth fixing for this codebase
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::needless_lifetimes)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::missing_errors_doc)]

pub mod audit;
pub mod command;
pub mod config;
pub mod core;
pub mod elevation;
pub mod fonts;
pub mod theme;
pub mod utils;
pub mod validators;

// Re-export commonly used types
pub use core::error::{Error, Result};
pub use core::firewall::{FirewallRuleset, Protocol, Rule};

// ============================================================================
// Compile-time configurable paths for distro packagers
// ============================================================================
//
// These can be overridden at build time by setting environment variables:
//
//   DRFW_SYSTEM_NFT_PATH=/etc/sysconfig/nftables.conf cargo build --release
//   DRFW_SYSTEM_NFT_SERVICE=firewalld.service cargo build --release
//
// Defaults:
//   - DRFW_SYSTEM_NFT_PATH: /etc/nftables.conf (Debian, Ubuntu, Arch, openSUSE)
//   - DRFW_SYSTEM_NFT_SERVICE: nftables.service
//
// Fedora/RHEL packagers should set:
//   DRFW_SYSTEM_NFT_PATH=/etc/sysconfig/nftables.conf

/// Path to system nftables configuration file.
///
/// Override at compile time: `DRFW_SYSTEM_NFT_PATH=/custom/path cargo build`
pub const SYSTEM_NFT_PATH: &str = match option_env!("DRFW_SYSTEM_NFT_PATH") {
    Some(path) => path,
    None => "/etc/nftables.conf",
};

/// Systemd service name for nftables persistence.
///
/// Override at compile time: `DRFW_SYSTEM_NFT_SERVICE=custom.service cargo build`
pub const SYSTEM_NFT_SERVICE: &str = match option_env!("DRFW_SYSTEM_NFT_SERVICE") {
    Some(svc) => svc,
    None => "nftables.service",
};
