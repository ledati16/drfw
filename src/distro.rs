//! Compile-time configuration for distribution packagers
//!
//! Four environment variables, read when DRFW is **built** (not at run time),
//! adapt it to a distribution's layout:
//!
//! | Variable | Default | Used for |
//! |----------|---------|----------|
//! | `DRFW_SYSTEM_NFT_PATH` | `/etc/nftables.conf` | File written by Save to System ([`SYSTEM_NFT_PATH`]) |
//! | `DRFW_SYSTEM_NFT_SERVICE` | `nftables.service` | Unit that loads that file at boot ([`SYSTEM_NFT_SERVICE`]) |
//! | `DRFW_NFT_PATH` | unset | Absolute `nft` path ([`NFT_PATH`]) |
//! | `DRFW_HELPER_PATH` | `/usr/lib/drfw/drfw-helper` | Where the root helper is installed ([`HELPER_PATH`]) |
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
//! `build.rs` re-runs the build when any of them changes.
//!
//! [`service_unit`] fills the same values into `contrib/drfw.service.in`
//! (`drfw print-service-unit`), so the packaged `drfw.service` always loads the
//! file this binary writes. [`polkit_policy`] fills [`HELPER_PATH`] into
//! `contrib/org.drfw.helper.policy.in` (`drfw print-polkit-policy`), so the
//! polkit action always names the helper this binary runs.

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
/// is not in `/usr/sbin`, `/sbin` or `/usr/bin` (e.g. NixOS), or to pin the
/// exact binary root runs.
pub const NFT_PATH: Option<&str> = non_empty(option_env!("DRFW_NFT_PATH"));

/// Where DRFW looks for `nft` when it runs it itself, without privileges
/// (the `unshare -rn nft` check), and [`NFT_PATH`] is unset: `nft` usually
/// lives in sbin, which is not on every user's `PATH` (Debian).
pub const NFT_SEARCH_PATHS: [&str; 3] = ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"];

/// The `nft` DRFW runs itself without privileges: [`NFT_PATH`] if set, else
/// the first of [`NFT_SEARCH_PATHS`] that exists, else plain `nft` (looked
/// up in `PATH`). The real-nft tests probe and use the same binary.
pub fn unprivileged_nft() -> &'static str {
    NFT_PATH.unwrap_or_else(|| {
        NFT_SEARCH_PATHS
            .into_iter()
            .find(|path| std::path::Path::new(path).is_file())
            .unwrap_or("nft")
    })
}

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

/// Where the root helper `drfw-helper` is installed (`DRFW_HELPER_PATH`).
///
/// DRFW elevates this program (`pkexec <helper> apply ...`) instead of
/// `/bin/sh` when it exists there, is a regular file owned by root and nothing
/// on the way is group- or world-writable (see [`crate::elevation`]); the
/// polkit action `org.drfw.helper` ([`polkit_policy`]) names the same path.
/// Override at compile time: `DRFW_HELPER_PATH=/usr/libexec/drfw/drfw-helper`.
pub const HELPER_PATH: &str = match non_empty(option_env!("DRFW_HELPER_PATH")) {
    Some(path) => path,
    None => "/usr/lib/drfw/drfw-helper",
};

/// Id of the polkit action for [`HELPER_PATH`].
pub const POLKIT_ACTION_ID: &str = "org.drfw.helper";

/// Template of the polkit action file, with `@HELPER_PATH@`.
pub const POLKIT_POLICY_TEMPLATE: &str = include_str!("../contrib/org.drfw.helper.policy.in");

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

/// True if the root scripts accept `path` as a path argument (their
/// `safe_path`): it starts with `/`, uses only [`is_safe_path_byte`]
/// characters and has no `..` component.
///
/// Looser than [`is_valid_absolute_path`], which implies it: empty and `.`
/// components and a trailing `/` pass, since runtime directories (such as
/// `$XDG_RUNTIME_DIR`) may be spelled that way.
///
/// ```
/// use drfw::distro::is_script_path;
///
/// assert!(is_script_path("/run/user/1000/"));
/// assert!(!is_script_path("/run/user/../0"));
/// assert!(!is_script_path("/home/John Doe"));
/// ```
pub fn is_script_path(path: &str) -> bool {
    path.starts_with('/')
        && path.bytes().all(is_safe_path_byte)
        && !path.split('/').any(|component| component == "..")
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
    is_valid_absolute_path(HELPER_PATH),
    "DRFW_HELPER_PATH must be an absolute file path made of A-Z a-z 0-9 / . _ @ + - \
     (no '.' or '..' components, no trailing '/'), e.g. /usr/lib/drfw/drfw-helper"
);

const _: () = assert!(
    crate::elevation::const_contains(POLKIT_POLICY_TEMPLATE, "@HELPER_PATH@")
        && crate::elevation::const_contains(
            POLKIT_POLICY_TEMPLATE,
            "<action id=\"org.drfw.helper\">"
        ),
    "contrib/org.drfw.helper.policy.in lost its placeholder or action id"
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

/// The polkit action file for [`HELPER_PATH`] (`drfw print-polkit-policy`).
///
/// Packagers install this output as
/// `/usr/share/polkit-1/actions/org.drfw.helper.policy`, so the action's
/// `org.freedesktop.policykit.exec.path` is always the helper this binary
/// elevates. The path passed the compile-time check above, so it holds no
/// character that XML would interpret.
pub fn polkit_policy() -> String {
    POLKIT_POLICY_TEMPLATE.replace("@HELPER_PATH@", HELPER_PATH)
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
        assert!(is_valid_absolute_path(HELPER_PATH));
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

    /// Checks that `xml` is well-formed in the subset polkit policies use
    /// (declaration, doctype, comments, elements without attributes other
    /// than quoted `key="value"` pairs, text without `<`/`&`): every element
    /// is closed in order and there is exactly one root.
    fn check_well_formed(xml: &str) -> Result<(), String> {
        let mut rest = xml
            .strip_prefix("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
            .ok_or("no XML declaration")?;
        let mut stack: Vec<&str> = Vec::new();
        let mut roots = 0;
        while let Some(start) = rest.find('<') {
            let text = &rest[..start];
            if text.contains('&') || text.contains('>') {
                return Err(format!("bad text {text:?}"));
            }
            if stack.is_empty() && !text.trim().is_empty() {
                return Err(format!("text outside the root: {text:?}"));
            }
            rest = &rest[start..];
            if let Some(after) = rest.strip_prefix("<!--") {
                let end = after.find("-->").ok_or("unclosed comment")?;
                if after[..end].contains("--") {
                    return Err("'--' inside a comment".into());
                }
                rest = &after[end + 3..];
                continue;
            }
            let end = rest.find('>').ok_or("unclosed tag")?;
            let tag = &rest[1..end];
            rest = &rest[end + 1..];
            if tag.starts_with("!DOCTYPE") {
                if roots > 0 || !stack.is_empty() {
                    return Err("doctype after the root".into());
                }
                continue;
            }
            if let Some(name) = tag.strip_prefix('/') {
                match stack.pop() {
                    Some(open) if open == name => {}
                    other => return Err(format!("</{name}> closes {other:?}")),
                }
                continue;
            }
            let name = tag.split_whitespace().next().ok_or("empty tag")?;
            if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return Err(format!("bad element name {name:?}"));
            }
            // Attributes: key="value" pairs only
            let attrs = tag[name.len()..].trim();
            if !attrs.is_empty() {
                let mut attrs = attrs;
                while !attrs.is_empty() {
                    let (key, value) = attrs.split_once("=\"").ok_or("bad attribute")?;
                    if key.trim().is_empty() || key.trim().contains(' ') {
                        return Err(format!("bad attribute name {key:?}"));
                    }
                    let (value, after) = value.split_once('"').ok_or("unterminated value")?;
                    if value.contains(['<', '&']) {
                        return Err(format!("bad attribute value {value:?}"));
                    }
                    attrs = after.trim_start();
                }
            }
            if stack.is_empty() {
                roots += 1;
            }
            stack.push(name);
        }
        if !rest.trim().is_empty() {
            return Err(format!("trailing text {rest:?}"));
        }
        if !stack.is_empty() || roots != 1 {
            return Err(format!("open elements {stack:?}, {roots} roots"));
        }
        Ok(())
    }

    #[test]
    fn test_well_formed_checker_rejects_broken_xml() {
        let head = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";
        for bad in [
            "<a>",
            "<a></b>",
            "<a><b></a></b>",
            "<a></a><b></b>",
            "<a>x & y</a>",
            "<a><!-- x -- y --></a>",
            "<a k=\"v></a>",
            "x<a></a>",
        ] {
            assert!(check_well_formed(&format!("{head}{bad}")).is_err(), "{bad}");
        }
        assert!(check_well_formed(&format!("{head}<a k=\"v\"><b>t</b></a>")).is_ok());
    }

    /// The text between `<tag>` and `</tag>` (first occurrence).
    fn element<'a>(xml: &'a str, tag: &str) -> &'a str {
        let open = format!("<{tag}>");
        let start = xml
            .find(&open)
            .unwrap_or_else(|| panic!("no <{tag}> in\n{xml}"))
            + open.len();
        let end = xml[start..]
            .find(&format!("</{tag}>"))
            .unwrap_or_else(|| panic!("no </{tag}>"));
        &xml[start..start + end]
    }

    #[test]
    fn test_polkit_policy_names_the_compiled_helper() {
        let policy = polkit_policy();
        check_well_formed(&policy).unwrap_or_else(|e| panic!("{e}\n{policy}"));
        assert!(!policy.contains("@HELPER_PATH@"));
        assert!(policy.contains(&format!("<action id=\"{POLKIT_ACTION_ID}\">")));
        // Exactly one action, and its exec path is this build's helper
        assert_eq!(policy.matches("<action ").count(), 1);
        assert_eq!(
            policy
                .matches(&format!(
                    "<annotate key=\"org.freedesktop.policykit.exec.path\">{HELPER_PATH}</annotate>"
                ))
                .count(),
            1
        );
        assert_eq!(policy.matches("<annotate ").count(), 1);
        // The defaults: remembered (~5 min) only for an active local session
        let defaults = element(&policy, "defaults");
        assert_eq!(element(defaults, "allow_any"), "auth_admin");
        assert_eq!(element(defaults, "allow_inactive"), "auth_admin");
        assert_eq!(element(defaults, "allow_active"), "auth_admin_keep");
        assert_eq!(
            element(&policy, "message"),
            "Authentication is required to change the firewall rules"
        );
        assert_eq!(element(&policy, "icon_name"), "drfw");
    }
}
