//! Core firewall management functionality
//!
//! This module contains the core types and logic for managing nftables firewall rules.
//! It provides:
//!
//! - [`firewall`]: Data structures for representing firewall rules and rulesets
//! - [`nft_json`]: JSON-based nftables rule application and snapshot management
//! - [`verify`]: Ruleset validation and syntax checking
//! - [`error`]: Error types for firewall operations
//! - [`profiles`]: Firewall profile management
//! - [`rule_constraints`]: Business rules for valid field combinations

pub mod error;
pub mod firewall;
pub mod nft_json;
pub mod profiles;
pub mod rule_constraints;
pub mod verify;

#[cfg(test)]
pub mod test_helpers;

#[cfg(test)]
mod tests;
