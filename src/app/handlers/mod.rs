//! Message handlers organized by domain
//!
//! This module contains all message handlers extracted from the monolithic
//! update() method, organized by functional domain for better maintainability.

pub mod apply;
pub mod export;
pub mod profiles;
pub mod rules;
pub mod settings;
pub mod ui_state;

#[cfg(test)]
pub mod test_utils;

// Re-export all handlers for clean imports in app/mod.rs
pub(crate) use apply::*;
pub(crate) use export::*;
#[allow(unused_imports)]
pub(crate) use profiles::*;
pub(crate) use rules::*;
pub(crate) use settings::*;
pub(crate) use ui_state::*;
