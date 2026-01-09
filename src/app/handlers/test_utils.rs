//! Shared test utilities for handler modules
//!
//! Provides common test helpers to avoid duplication across handler test suites.
//!
//! **Note:** For Rule creation helpers, use `crate::core::test_helpers` instead.
//! This module focuses on app-level State creation for handler tests.

/// Creates a test State without accessing the user's filesystem.
///
/// This uses `State::new_for_testing()` which avoids:
/// - Reading the user's config file
/// - Creating/accessing the user's profiles directory
/// - Loading the user's profile data
///
/// Use this for all handler unit tests to ensure test isolation.
#[cfg(test)]
pub fn create_test_state() -> crate::app::State {
    crate::app::State::new_for_testing()
}
