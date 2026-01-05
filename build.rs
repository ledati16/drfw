//! Build script for DRFW
//!
//! Handles compile-time configuration for distro packagers.

fn main() {
    // Re-run build if these environment variables change
    println!("cargo:rerun-if-env-changed=DRFW_SYSTEM_NFT_PATH");
    println!("cargo:rerun-if-env-changed=DRFW_SYSTEM_NFT_SERVICE");
}
