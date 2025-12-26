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
pub mod theme;
pub mod utils;
pub mod validators;

// Re-export commonly used types
pub use core::error::{Error, Result};
pub use core::firewall::{FirewallRuleset, Protocol, Rule};
