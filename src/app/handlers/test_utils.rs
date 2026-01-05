//! Shared test utilities for handler modules
//!
//! Provides common test helpers to avoid duplication across handler test suites.
//!
//! **Note:** For Rule creation helpers, use `crate::core::test_helpers` instead.
//! This module focuses on app-level State creation for handler tests.

#[cfg(test)]
pub fn create_test_state() -> crate::app::State {
    crate::app::State::new().0
}
