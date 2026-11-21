//! Compile-time configuration for distribution packagers
//!
//! Three environment variables, read when DRFW is **built** (not at run time),
//! adapt it to a distribution's layout:
//!
//! | Variable | Default | Used for |
//! |----------|---------|----------|
//! | `DRFW_SYSTEM_NFT_PATH` | `/etc/nftables.conf` | File written by Save to System ([`SYSTEM_NFT_PATH`]) |
//! | `DRFW_SYSTEM_NFT_SERVICE` | `nftables.service` | Unit that loads that file at boot ([`SYSTEM_NFT_SERVICE`]) |
//! | `DRFW_NFT_PATH` | unset | Absolute `nft` path ([`NFT_PATH`]) |
//!
//! ```bash
//! DRFW_SYSTEM_NFT_PATH=/etc/sysconfig/nftables.conf DRFW_NFT_PATH=/usr/sbin/nft \
//!     cargo build --release
//! ```
//!
//! An empty value counts as unset. Every value is checked at compile time: a
//! path must be absolute and use only the characters the root scripts in
//! [`crate::elevation`] accept (`A-Z a-z 0-9 / . _ @ + -`, no `.` or `..`
//! component), and the service must be a systemd unit name ending in
//! `.service`. A bad value fails the build with a message naming the variable.
//! `build.rs` re-runs the build when any of the three changes.
//!
//! [`service_unit`] fills the same values into `contrib/drfw.service.in`
//! (`drfw print-service-unit`), so the packaged `drfw.service` always loads the
//! file this binary writes.

/// Treats an empty compile-time variable as unset.
const fn non_empty(value: Option<&'static str>) -> Option<&'static str> {
    match value {
        Some(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}

/// Path of the system nftables configuration that Save to System replaces.
///
/// Override at compile time: `DRFW_SYSTEM_NFT_PATH=/custom/path cargo build`.
/// Fedora/RHEL use `/etc/sysconfig/nftables.conf`.
pub const SYSTEM_NFT_PATH: &str = match non_empty(option_env!("DRFW_SYSTEM_NFT_PATH")) {
    Some(path) => path,
    None => "/etc/nftables.conf",
};

/// systemd unit that loads [`SYSTEM_NFT_PATH`] at boot.
///
/// Override at compile time: `DRFW_SYSTEM_NFT_SERVICE=drfw.service cargo build`.
/// DRFW reports whether it is enabled (see [`crate::core::boot`]) and can
/// enable it as part of Save to System.
pub const SYSTEM_NFT_SERVICE: &str = match non_empty(option_env!("DRFW_SYSTEM_NFT_SERVICE")) {
    Some(service) => service,
    None => "nftables.service",
};

/// Absolute `nft` path chosen by the packager (`DRFW_NFT_PATH`), if any.
///
/// When set, it is the only `nft` the unprivileged check tries, and it is
/// passed to the elevated scripts and to `pkexec`/`sudo`/`run0` instead of a
/// bare `nft` (which they resolve through root's `PATH`). Set it where `nft`
/// is not in `/usr/sbin`, `/sbin` or `/usr/bin` (e.g. NixOS), or to match a
/// polkit rule that names one exact path.
pub const NFT_PATH: Option<&str> = non_empty(option_env!("DRFW_NFT_PATH"));

/// What elevated commands run as `nft`: [`NFT_PATH`], else plain `nft`.
pub const NFT_COMMAND: &str = match NFT_PATH {
    Some(path) => path,
    None => "nft",
};

/// `nft` path written into the generated systemd unit: [`NFT_PATH`], else
/// `/usr/sbin/nft`, which exists on Debian, Fedora and openSUSE and, through
/// the `/usr/sbin` -> `/usr/bin` symlink, on Arch.
pub const UNIT_NFT_PATH: &str = match NFT_PATH {
    Some(path) => path,
    None => "/usr/sbin/nft",
};

/// Name of DRFW's own unit (`contrib/drfw.service.in`). It loads
/// [`SYSTEM_NFT_PATH`] too, so the boot check also accepts it.
pub const BUNDLED_SERVICE: &str = "drfw.service";

/// Template of [`BUNDLED_SERVICE`], with `@SYSTEM_NFT_PATH@` and `@NFT_PATH@`.
pub const SERVICE_TEMPLATE: &str = include_str!("../contrib/drfw.service.in");

/// True for the characters the root scripts allow in a path argument
/// (their `safe_path`: `[A-Za-z0-9/._@+-]`).
pub const fn is_safe_path_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'@' | b'+' | b'-')
}

/// True if `path` is an absolute file path the root scripts accept: starts
/// with `/`, uses only [`is_safe_path_byte`] characters, has no empty, `.` or
/// `..` component and does not end with `/`.
///
/// ```
/// use drfw::distro::is_valid_absolute_path;
///
/// assert!(is_valid_absolute_path("/etc/sysconfig/nftables.conf"));
/// assert!(!is_valid_absolute_path("etc/nftables.conf"));
/// assert!(!is_valid_absolute_path("/etc/../tmp/x"));
/// ```
pub const fn is_valid_absolute_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    if bytes.len() < 2 || bytes[0] != b'/' || bytes[bytes.len() - 1] == b'/' {
        return false;
    }
    // Index after the last '/', i.e. the start of the current component
    let mut start = 1;
    let mut i = 1;
    while i <= bytes.len() {
        if i == bytes.len() || bytes[i] == b'/' {
            let len = i - start;
            let dot = len == 1 && bytes[start] == b'.';
            let dot_dot = len == 2 && bytes[start] == b'.' && bytes[start + 1] == b'.';
            if len == 0 || dot || dot_dot {
                return false;
            }
            start = i + 1;
        } else if !is_safe_path_byte(bytes[i]) {
            return false;
        }
        i += 1;
    }
    true
}

/// Longest unit name systemd accepts (`UNIT_NAME_MAX` - 1).
const MAX_UNIT_NAME_LEN: usize = 255;

/// The suffix every [`is_valid_service_name`] name ends with.
const SERVICE_SUFFIX: &[u8] = b".service";

/// True if `name` looks like a systemd service unit name: `[A-Za-z0-9:_.@-]+`
/// followed by `.service`, at most 255 bytes, not starting with `-` (it would
/// read as an option) or `.`. The save script applies the same check.
///
/// ```
/// use drfw::distro::is_valid_service_name;
///
/// assert!(is_valid_service_name("nftables.service"));
/// assert!(!is_valid_service_name("nftables"));
/// assert!(!is_valid_service_name("-x.service"));
/// ```
pub const fn is_valid_service_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.len() <= SERVICE_SUFFIX.len() || bytes.len() > MAX_UNIT_NAME_LEN {
        return false;
    }
    if bytes[0] == b'-' || bytes[0] == b'.' {
        return false;
    }
    let prefix_len = bytes.len() - SERVICE_SUFFIX.len();
    let mut i = 0;
    while i < SERVICE_SUFFIX.len() {
        if bytes[prefix_len + i] != SERVICE_SUFFIX[i] {
            return false;
        }
        i += 1;
    }
    let mut i = 0;
    while i < prefix_len {
        let b = bytes[i];
        if !(b.is_ascii_alphanumeric() || matches!(b, b':' | b'_' | b'.' | b'@' | b'-')) {
            return false;
        }
        i += 1;
    }
    true
}

const _: () = assert!(
    is_valid_absolute_path(SYSTEM_NFT_PATH),
    "DRFW_SYSTEM_NFT_PATH must be an absolute file path made of A-Z a-z 0-9 / . _ @ + - \
     (no '.' or '..' components, no trailing '/'), e.g. /etc/nftables.conf"
);

const _: () = assert!(
    is_valid_service_name(SYSTEM_NFT_SERVICE),
    "DRFW_SYSTEM_NFT_SERVICE must be a systemd unit name made of A-Z a-z 0-9 : _ . @ - \
     ending in .service, e.g. nftables.service"
);

const _: () = assert!(
    match NFT_PATH {
        Some(path) => is_valid_absolute_path(path),
        None => true,
    },
    "DRFW_NFT_PATH must be an absolute file path made of A-Z a-z 0-9 / . _ @ + - \
     (no '.' or '..' components, no trailing '/'), e.g. /usr/sbin/nft"
);

const _: () = assert!(
    crate::elevation::const_contains(SERVICE_TEMPLATE, "@SYSTEM_NFT_PATH@")
        && crate::elevation::const_contains(SERVICE_TEMPLATE, "@NFT_PATH@"),
    "contrib/drfw.service.in lost a placeholder"
);

/// The systemd unit for [`BUNDLED_SERVICE`] with this build's paths filled in
/// (`drfw print-service-unit`).
///
/// Packagers install this output instead of the template, so the unit loads
/// exactly [`SYSTEM_NFT_PATH`] with [`UNIT_NFT_PATH`]. Both values passed the
/// compile-time checks above, so they contain no spaces, `%` specifiers or
/// `$` expansions that systemd would interpret.
pub fn service_unit() -> String {
    SERVICE_TEMPLATE
        .replace("@SYSTEM_NFT_PATH@", SYSTEM_NFT_PATH)
        .replace("@NFT_PATH@", UNIT_NFT_PATH)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_absolute_paths() {
        for path in [
            "/etc/nftables.conf",
            "/etc/sysconfig/nftables.conf",
            "/etc/drfw/rules.nft",
            "/run/current-system/sw/bin/nft",
            "/nix/store/abc123-nftables-1.1.1/bin/nft",
            "/opt/a+b/x@y_z-1.2/.hidden",
            "/x",
        ] {
            assert!(is_valid_absolute_path(path), "{path}");
        }
    }

    #[test]
    fn test_invalid_absolute_paths() {
        for path in [
            "",
            "/",
            "relative/path",
            "nft",
            "./nft",
            "/etc/",
            "/etc//nftables.conf",
            "/etc/./nftables.conf",
            "/etc/../tmp/x",
            "/..",
            "/etc/nft tables.conf",
            "/etc/nftables$x",
            "/etc/%n.conf",
            "/etc/nftables;rm",
            "/etc/\"q\"",
            "/etc/nf\ttables",
            "/etc/nftables.conf\n",
            "/etc/nftablés.conf",
        ] {
            assert!(!is_valid_absolute_path(path), "{path:?}");
        }
    }

    #[test]
    fn test_safe_path_bytes_match_the_script_allowlist() {
        // The scripts use `*[!A-Za-z0-9/._@+-]*`
        let allowed: Vec<u8> = (0..=u8::MAX).filter(|b| is_safe_path_byte(*b)).collect();
        let mut expected: Vec<u8> = (b'A'..=b'Z')
            .chain(b'a'..=b'z')
            .chain(b'0'..=b'9')
            .chain(*b"/._@+-")
            .collect();
        expected.sort_unstable();
        assert_eq!(allowed, expected);
    }

    #[test]
    fn test_valid_service_names() {
        for name in [
            "nftables.service",
            "drfw.service",
            "firewall@eth0.service",
            "a.service",
            "x-y_z:1.2.service",
        ] {
            assert!(is_valid_service_name(name), "{name}");
        }
        let longest = format!("{}.service", "a".repeat(MAX_UNIT_NAME_LEN - 8));
        assert!(is_valid_service_name(&longest));
    }

    #[test]
    fn test_invalid_service_names() {
        let too_long = format!("{}.service", "a".repeat(MAX_UNIT_NAME_LEN - 7));
        for name in [
            "",
            ".service",
            "nftables",
            "nftables.socket",
            "nftables.service.d",
            "-nftables.service",
            ".nftables.service",
            "nft tables.service",
            "nft$x.service",
            "nft/x.service",
            "nft;x.service",
            "nftables.servicE",
            too_long.as_str(),
        ] {
            assert!(!is_valid_service_name(name), "{name:?}");
        }
    }

    #[test]
    fn test_compiled_values_are_valid() {
        assert!(is_valid_absolute_path(SYSTEM_NFT_PATH));
        assert!(is_valid_service_name(SYSTEM_NFT_SERVICE));
        assert!(is_valid_service_name(BUNDLED_SERVICE));
        assert!(is_valid_absolute_path(UNIT_NFT_PATH));
        assert!(NFT_COMMAND == "nft" || is_valid_absolute_path(NFT_COMMAND));
    }

    #[test]
    fn test_non_empty() {
        assert_eq!(non_empty(None), None);
        assert_eq!(non_empty(Some("")), None);
        assert_eq!(non_empty(Some("/x")), Some("/x"));
    }

    #[test]
    fn test_service_unit_fills_in_the_compiled_paths() {
        let unit = service_unit();
        assert!(!unit.contains("@SYSTEM_NFT_PATH@") && !unit.contains("@NFT_PATH@"));
        let line = |key: &str| {
            unit.lines()
                .find(|l| l.starts_with(key))
                .unwrap_or_else(|| panic!("no {key} line in\n{unit}"))
                .to_string()
        };
        assert_eq!(
            line("ExecStart="),
            format!("ExecStart={UNIT_NFT_PATH} -f {SYSTEM_NFT_PATH}")
        );
        assert_eq!(
            line("ExecReload="),
            format!("ExecReload={UNIT_NFT_PATH} -f {SYSTEM_NFT_PATH}")
        );
        assert_eq!(
            line("ExecStop="),
            format!("ExecStop=-{UNIT_NFT_PATH} delete table inet drfw")
        );
        // The semantics of the unit DRFW has always shipped
        for expected in [
            "Type=oneshot",
            "RemainAfterExit=yes",
            "Conflicts=nftables.service",
            "WantedBy=multi-user.target",
        ] {
            assert!(unit.lines().any(|l| l == expected), "{expected}\n{unit}");
        }
    }
}
