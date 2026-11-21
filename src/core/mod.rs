//! Core firewall management functionality
//!
//! This module contains the core types and logic for managing nftables firewall rules.
//! It provides:
//!
//! - [`firewall`]: Data structures for representing firewall rules and rulesets
//! - [`apply_guard`]: Applying rules with a root-side auto-revert guard
//! - [`boot`]: Whether a systemd unit loads the saved rules at boot
//! - [`nft_text`]: Renders the generated JSON commands as an `nft -f` file
//! - [`nft_errors`]: Readable nft errors, mapped back to the rules that caused them
//! - [`system_config`]: Safe, verified writes of the system nftables configuration
//! - [`verify`]: Ruleset validation and syntax checking
//! - [`error`]: Error types for firewall operations
//! - [`profiles`]: Firewall profile management
//! - [`rule_constraints`]: Business rules for valid field combinations
//! - [`validate`]: Rule and ruleset validation (shared by the form, loader and apply)

pub mod apply_guard;
pub mod boot;
pub mod error;
pub mod firewall;
pub mod nft_errors;
pub mod nft_text;
pub mod profiles;
pub mod rule_constraints;
pub mod system_config;
pub mod validate;
pub mod verify;

#[cfg(test)]
pub mod test_helpers;

#[cfg(test)]
mod tests;
