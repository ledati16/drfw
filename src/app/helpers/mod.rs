//! Helper utilities for the app layer
//!
//! This module contains pure functions that perform data transformations,
//! formatting, filtering, and calculations without mutating application state.

pub mod caching;
pub mod filtering;
pub mod formatting;

// Re-export commonly used functions for convenience
pub use caching::{calculate_max_content_width, calculate_max_content_width_from_refs};
pub use filtering::{fuzzy_filter_fonts, fuzzy_filter_themes};
pub use formatting::truncate_path_smart;
