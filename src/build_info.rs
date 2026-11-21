//! Build information: crate version, git commit, branch and build time.
//!
//! `build.rs` generates the constants with `shadow-rs` into `OUT_DIR/shadow.rs`;
//! this module turns them into the version strings shown by `drfw --version`
//! and in the GUI footer. All of them are `const`, so nothing is formatted at
//! run time.

/// The generated `shadow-rs` constants, kept private: only the strings below
/// are part of the API.
mod generated {
    shadow_rs::shadow!(build);
}

use generated::build;

/// `*` when the working tree had uncommitted changes at build time.
const DIRTY_MARKER: &str = if build::GIT_CLEAN { "" } else { "*" };

/// Version with the git commit, marked when built from a dirty tree:
/// `"0.9.0 (a3f8c21)"` or `"0.9.0 (a3f8c21*)"`.
pub const VERSION: &str = shadow_rs::formatcp!(
    "{} ({}{})",
    build::PKG_VERSION,
    build::SHORT_COMMIT,
    DIRTY_MARKER
);

/// Short version for `drfw -V`: `"0.9.0 (a3f8c21)"`.
pub const SHORT_VERSION: &str =
    shadow_rs::formatcp!("{} ({})", build::PKG_VERSION, build::SHORT_COMMIT);

/// Detailed version for `drfw --version`: version, full commit hash, branch
/// and build time (RFC 3339).
pub const LONG_VERSION: &str = shadow_rs::formatcp!(
    "{} ({})\ncommit: {}\nbranch: {}\nbuild:  {}",
    build::PKG_VERSION,
    build::SHORT_COMMIT,
    build::COMMIT_HASH,
    build::BRANCH,
    build::BUILD_TIME_3339
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_versions_start_with_the_package_version() {
        let pkg = env!("CARGO_PKG_VERSION");
        for version in [VERSION, SHORT_VERSION, LONG_VERSION] {
            assert!(version.starts_with(pkg), "{version:?}");
        }
        assert!(LONG_VERSION.contains("\ncommit: "));
        assert!(LONG_VERSION.contains("\nbranch: "));
        assert!(LONG_VERSION.contains("\nbuild:  "));
    }
}
