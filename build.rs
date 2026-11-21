//! Build script for DRFW
//!
//! Handles compile-time configuration for distro packagers and embeds
//! build-time information (git commit, dirty status, build timestamp).

fn main() {
    // Re-run build if these environment variables change (read by src/distro.rs)
    println!("cargo:rerun-if-env-changed=DRFW_SYSTEM_NFT_PATH");
    println!("cargo:rerun-if-env-changed=DRFW_SYSTEM_NFT_SERVICE");
    println!("cargo:rerun-if-env-changed=DRFW_NFT_PATH");
    println!("cargo:rerun-if-env-changed=DRFW_HELPER_PATH");

    // Embed git commit, build time, and dirty status
    shadow_rs::ShadowBuilder::builder()
        .build()
        .expect("Failed to generate build info");
}
