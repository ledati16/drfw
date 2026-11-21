//! Core firewall management functionality
//!
//! This module contains the core types and logic for managing nftables firewall rules.
//! It provides:
//!
//! - [`firewall`]: Data structures for representing firewall rules and rulesets
//! - [`apply_guard`]: Applying rules with a root-side auto-revert guard
//! - [`boot`]: Whether a systemd unit loads the saved rules at boot
//! - [`confirmed`]: The record of the last ruleset applied and kept
//! - [`evaluate`]: What the generated input chain does with a new connection
//! - [`exposure`]: Listening sockets and who can reach them through the rules
//! - [`host_facts`]: IP forwarding and Docker published ports, read from `/proc`
//! - [`lockout`]: Whether new rules would keep you from reconnecting over SSH
//! - [`nft_text`]: Renders the generated JSON commands as an `nft -f` file
//! - [`nft_errors`]: Readable nft errors, mapped back to the rules that caused them
//! - [`system_config`]: Safe, verified writes of the system nftables configuration
//! - [`verify`]: Ruleset validation and syntax checking
//! - [`error`]: Error types for firewall operations
//! - [`profiles`]: Firewall profile management
//! - [`rule_constraints`]: Business rules for valid field combinations
//! - [`templates`]: Ready-made rules for common setups (Server Mode, VMs, Tailscale)
//! - [`validate`]: Rule and ruleset validation (shared by the form, loader and apply)
//! - [`retention`]: Confirmation before dropping most of the kept rules

pub(crate) mod addr_set;
pub mod apply_guard;
pub mod boot;
pub mod confirmed;
pub mod error;
pub mod evaluate;
pub mod exposure;
pub mod firewall;
pub mod host_facts;
pub mod lockout;
pub mod nft_errors;
pub mod nft_text;
pub mod profiles;
pub mod retention;
pub mod rule_constraints;
pub mod system_config;
pub mod templates;
pub mod validate;
pub mod verify;

#[cfg(test)]
pub mod test_helpers;

#[cfg(test)]
mod tests;
