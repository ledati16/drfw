//! `drfw-helper`: DRFW's root helper (see [`drfw::helper`])
//!
//! Installed at `DRFW_HELPER_PATH` (default `/usr/lib/drfw/drfw-helper`) and
//! started only through `pkexec`, `sudo` or `run0`. It validates its request
//! and replaces itself with the fixed script or `nft`; it refuses anything
//! else with exit status 1.

fn main() -> std::process::ExitCode {
    drfw::helper::main()
}
