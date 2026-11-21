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

/// Built from a git checkout: a release tarball (or any source without
/// `.git`) has no commit, and the versions then omit it.
const HAS_COMMIT: bool = !build::SHORT_COMMIT.is_empty();

/// `" (a3f8c21)"`, `" (a3f8c21*)"` from a dirty tree, empty without a commit.
const COMMIT_SUFFIX: &str = if HAS_COMMIT {
    shadow_rs::formatcp!(" ({}{})", build::SHORT_COMMIT, DIRTY_MARKER)
} else {
    ""
};

/// [`COMMIT_SUFFIX`] without the dirty marker.
const SHORT_COMMIT_SUFFIX: &str = if HAS_COMMIT {
    shadow_rs::formatcp!(" ({})", build::SHORT_COMMIT)
} else {
    ""
};

/// `value`, or `"unknown"` when the build had no git metadata.
const fn or_unknown(value: &'static str) -> &'static str {
    if value.is_empty() { "unknown" } else { value }
}

/// Version with the git commit, marked when built from a dirty tree:
/// `"1.0.0 (a3f8c21)"` or `"1.0.0 (a3f8c21*)"`; `"1.0.0"` without git.
pub const VERSION: &str = shadow_rs::formatcp!("{}{}", build::PKG_VERSION, COMMIT_SUFFIX);

/// Short version for `drfw -V`: `"1.0.0 (a3f8c21)"`, `"1.0.0"` without git.
pub const SHORT_VERSION: &str =
    shadow_rs::formatcp!("{}{}", build::PKG_VERSION, SHORT_COMMIT_SUFFIX);

/// Detailed version for `drfw --version`: version, full commit hash, branch
/// and build time (RFC 3339); commit and branch are "unknown" without git.
pub const LONG_VERSION: &str = shadow_rs::formatcp!(
    "{}{}\ncommit: {}\nbranch: {}\nbuild:  {}",
    build::PKG_VERSION,
    SHORT_COMMIT_SUFFIX,
    or_unknown(build::COMMIT_HASH),
    or_unknown(build::BRANCH),
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
        assert!(!SHORT_VERSION.contains("()"), "{SHORT_VERSION:?}");
        assert_eq!(or_unknown(""), "unknown");
        assert_eq!(or_unknown("main"), "main");
    }
}
