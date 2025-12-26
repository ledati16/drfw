use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Core error types for DRFW
#[derive(Debug, Error)]
pub enum Error {
    /// I/O operation failed
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// nftables command execution failed
    #[error("nftables error: {message}")]
    Nftables {
        message: String,
        stderr: Option<String>,
        exit_code: Option<i32>,
    },

    /// Input validation failed
    #[error("Validation error in {field}: {message}")]
    #[allow(dead_code)]
    Validation { field: String, message: String },

    /// Snapshot operation failed
    #[error("Snapshot error: {0}")]
    Snapshot(#[from] SnapshotError),

    /// Privilege escalation failed
    #[error("Elevation error: {0}")]
    #[allow(dead_code)]
    Elevation(String),

    /// Internal logic error
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Snapshot-specific errors
#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum SnapshotError {
    #[error("Snapshot corrupted: invalid structure")]
    Corrupted,

    #[error("Snapshot checksum mismatch: expected {expected}, got {actual}")]
    ChecksumMismatch { expected: String, actual: String },

    #[error("Snapshot not found: {0}")]
    NotFound(String),

    #[error("Snapshot format version mismatch: found v{found}, expected v{expected}")]
    VersionMismatch { found: u32, expected: u32 },

    #[error("Snapshot is empty")]
    Empty,

    #[error("Snapshot restore failed: {0}")]
    RestoreFailed(String),
}

impl Error {
    /// Returns a user-friendly error message (legacy method, use `ErrorTranslation::translate` instead)
    ///
    /// Translates technical errors into messages that end users can understand
    /// and potentially act upon.
    #[allow(dead_code)]
    pub fn user_message(&self) -> String {
        ErrorTranslation::translate(self).user_message
    }

    /// Translates nftables-specific errors to user-friendly messages (legacy)
    #[allow(dead_code)]
    fn translate_nftables_error(msg: &str) -> String {
        NftablesErrorPattern::match_error(msg).user_message
    }
}

/// Represents a translated error with helpful context
#[derive(Debug, Clone)]
pub struct ErrorTranslation {
    pub user_message: String,
    pub suggestions: Vec<String>,
    #[allow(dead_code)]
    pub help_url: Option<String>,
}

impl ErrorTranslation {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            user_message: message.into(),
            suggestions: Vec::new(),
            help_url: None,
        }
    }

    pub fn with_suggestion(mut self, suggestion: impl Into<String>) -> Self {
        self.suggestions.push(suggestion.into());
        self
    }

    #[allow(dead_code)]
    pub fn with_help(mut self, url: impl Into<String>) -> Self {
        self.help_url = Some(url.into());
        self
    }

    /// Translate an Error into user-friendly message with suggestions
    pub fn translate(err: &Error) -> Self {
        match err {
            Error::Nftables { message, .. } => NftablesErrorPattern::match_error(message),

            Error::Validation { field, message } => Self::new(format!("{field}: {message}"))
                .with_suggestion(format!("Check the '{field}' field and correct the value"))
                .with_help("https://nftables.org/manpage/nft.txt"),

            Error::Elevation(msg) => Self::new(format!("Permission error: {msg}"))
                .with_suggestion(
                    "Ensure pkexec is installed and configured: sudo apt install policykit-1",
                )
                .with_suggestion("Check that your user is in the 'sudo' or 'wheel' group")
                .with_suggestion("Try running: pkexec --version")
                .with_help("https://wiki.archlinux.org/title/Polkit"),

            Error::Snapshot(SnapshotError::Corrupted) => {
                Self::new("Snapshot file is corrupted and cannot be restored")
                    .with_suggestion("Revert manually: sudo nft flush ruleset")
                    .with_suggestion("Apply a new configuration to replace the corrupted snapshot")
                    .with_suggestion("Check disk space: df -h ~/.local/state/drfw/")
            }

            Error::Snapshot(SnapshotError::ChecksumMismatch { expected, actual }) => {
                Self::new("Snapshot integrity check failed - possible tampering detected")
                    .with_suggestion(format!("Expected checksum: {expected}"))
                    .with_suggestion(format!("Actual checksum: {actual}"))
                    .with_suggestion("The file may have been tampered with or corrupted")
                    .with_suggestion(
                        "Do not restore this snapshot - create a new configuration instead",
                    )
            }

            Error::Snapshot(SnapshotError::NotFound(path)) => {
                Self::new(format!("Snapshot not found: {path}"))
                    .with_suggestion("The snapshot file may have been deleted or moved")
                    .with_suggestion(
                        "Check if the file exists: ls -la ~/.local/state/drfw/snapshots/",
                    )
                    .with_suggestion("Create a new snapshot by applying your current configuration")
            }

            Error::Snapshot(SnapshotError::VersionMismatch { found, expected }) => Self::new(
                format!("Snapshot version mismatch (found v{found}, expected v{expected})"),
            )
            .with_suggestion("This snapshot was created by a different version of DRFW")
            .with_suggestion("Update DRFW to the version that created this snapshot")
            .with_suggestion("Or create a new snapshot with your current DRFW version"),

            Error::Snapshot(SnapshotError::Empty) => {
                Self::new("Snapshot is empty - no rules to restore")
                    .with_suggestion("This snapshot contains no firewall rules")
                    .with_suggestion("Create a new snapshot with actual rules configured")
                    .with_suggestion("Or use the emergency default ruleset for basic protection")
            }

            Error::Snapshot(SnapshotError::RestoreFailed(msg)) => {
                Self::new(format!("Failed to restore snapshot: {msg}"))
                    .with_suggestion("Check nftables logs: sudo journalctl -u nftables")
                    .with_suggestion(
                        "Verify nftables service is running: sudo systemctl status nftables",
                    )
                    .with_suggestion("Try applying the emergency default ruleset instead")
            }

            Error::Serialization(e) => {
                Self::new(format!("Failed to process configuration data: {e}"))
                    .with_suggestion("The configuration file may be corrupted")
                    .with_suggestion(
                        "Delete the corrupted file: rm ~/.local/share/drfw/config.toml",
                    )
                    .with_suggestion("DRFW will create a new configuration on next launch")
                    .with_suggestion("Check disk space: df -h")
            }

            Error::Internal(msg) => Self::new(format!("Internal error: {msg}"))
                .with_suggestion("This is a bug in DRFW - please report it")
                .with_suggestion("GitHub: https://github.com/anthropics/drfw/issues")
                .with_suggestion("Include the error message and steps to reproduce"),

            Error::Io(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                Self::new("Permission denied - cannot access file or directory")
                    .with_suggestion("Ensure you have the necessary privileges")
                    .with_suggestion("Check file permissions: ls -la ~/.local/share/drfw/")
                    .with_suggestion("Fix permissions: chmod 700 ~/.local/share/drfw/")
                    .with_help("https://wiki.archlinux.org/title/File_permissions_and_attributes")
            }

            Error::Io(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Self::new("Required file or command not found")
                    .with_suggestion("Install nftables: sudo apt install nftables")
                    .with_suggestion("Verify nftables is in PATH: which nft")
                    .with_suggestion("Check if DRFW directories exist: ls ~/.local/share/drfw/")
            }

            Error::Io(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                Self::new("File or directory already exists")
                    .with_suggestion("A file with this name already exists")
                    .with_suggestion("Choose a different name or delete the existing file")
            }

            Error::Io(e) => Self::new(format!("File system error: {e}"))
                .with_suggestion("Check disk space: df -h")
                .with_suggestion("Verify file system is writable")
                .with_suggestion("Check system logs: sudo journalctl -xe"),
        }
    }
}

/// Database of nftables error patterns and their translations
struct NftablesErrorPattern;

impl NftablesErrorPattern {
    #[allow(clippy::too_many_lines)]
    fn match_error(msg: &str) -> ErrorTranslation {
        let lower = msg.to_lowercase();

        // Permission errors
        if lower.contains("permission denied") || lower.contains("operation not permitted") {
            return ErrorTranslation::new("Insufficient permissions to modify firewall rules")
                .with_suggestion("Ensure pkexec is configured correctly")
                .with_suggestion("Verify nftables service is accessible: systemctl status nftables")
                .with_suggestion("Check if CAP_NET_ADMIN capability is available")
                .with_help("https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes");
        }

        // Cache initialization failed (common with insufficient permissions)
        if lower.contains("cache initialization failed") {
            return ErrorTranslation::new(
                "Failed to initialize nftables cache - insufficient privileges",
            )
            .with_suggestion("This usually means you need elevated privileges")
            .with_suggestion("DRFW will prompt for elevation when applying rules")
            .with_suggestion("Ensure pkexec is installed: sudo apt install policykit-1")
            .with_help("https://wiki.archlinux.org/title/Polkit");
        }

        // Missing nftables
        if lower.contains("no such file") || lower.contains("command not found") {
            return ErrorTranslation::new("nftables is not installed or not found in PATH")
                .with_suggestion("Install nftables: sudo apt install nftables  (Debian/Ubuntu)")
                .with_suggestion("Or: sudo dnf install nftables  (Fedora/RHEL)")
                .with_suggestion("Or: sudo pacman -S nftables  (Arch)")
                .with_help("https://wiki.nftables.org/wiki-nftables/index.php/Main_Page");
        }

        // Syntax errors
        if lower.contains("could not process rule") || lower.contains("syntax error") {
            return ErrorTranslation::new("Invalid firewall rule syntax")
                .with_suggestion("Check your rule configuration for typos")
                .with_suggestion("Verify port numbers are between 1 and 65535")
                .with_suggestion("Ensure IP addresses and network masks are valid")
                .with_help(
                    "https://wiki.nftables.org/wiki-nftables/index.php/Simple_rule_management",
                );
        }

        // Invalid expression type (common with protocol mismatches)
        if lower.contains("unknown expression type") || lower.contains("invalid expression") {
            return ErrorTranslation::new("Invalid rule expression - protocol or match type error")
                .with_suggestion("Ensure protocol matches the match type (e.g., TCP/UDP for ports)")
                .with_suggestion("Check that ICMP rules don't specify port numbers")
                .with_suggestion("Verify you're using correct nftables syntax")
                .with_help("https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes");
        }

        // Parsing errors
        if lower.contains("parsing") && lower.contains("failed") {
            return ErrorTranslation::new("Failed to parse firewall rule")
                .with_suggestion("The rule syntax is malformed")
                .with_suggestion("Check for missing quotes, brackets, or commas")
                .with_suggestion("Verify JSON structure if using JSON format");
        }

        // Table doesn't exist
        if lower.contains("table") && lower.contains("does not exist") {
            return ErrorTranslation::new("Firewall table does not exist")
                .with_suggestion("The 'drfw' table may not have been created yet")
                .with_suggestion("Try applying your rules to create the table")
                .with_help("https://wiki.nftables.org/wiki-nftables/index.php/Configuring_tables");
        }

        // Chain errors
        if lower.contains("chain")
            && (lower.contains("does not exist") || lower.contains("not found"))
        {
            return ErrorTranslation::new("Firewall chain not found")
                .with_suggestion("Ensure the chain exists before adding rules to it")
                .with_suggestion("Apply the base configuration first")
                .with_help("https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains");
        }

        // Port range errors
        if lower.contains("invalid port") || (lower.contains("port") && lower.contains("range")) {
            return ErrorTranslation::new("Invalid port or port range")
                .with_suggestion("Port numbers must be between 1 and 65535")
                .with_suggestion("For port ranges, ensure start ≤ end")
                .with_suggestion("Example valid ranges: 22, 80-443, 8000-9000");
        }

        // Invalid IP address
        if lower.contains("invalid")
            && (lower.contains("ip") || lower.contains("address") || lower.contains("network"))
        {
            return ErrorTranslation::new("Invalid IP address or network")
                .with_suggestion("Use proper IP format: 192.168.1.1 or 192.168.1.0/24")
                .with_suggestion("For IPv6: 2001:db8::1 or 2001:db8::/32")
                .with_suggestion("Check CIDR notation: /24 for IPv4, /64 for IPv6")
                .with_help("https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing");
        }

        // Invalid LHS of relational (protocol mismatch)
        if lower.contains("invalid lhs of relational") {
            return ErrorTranslation::new("Protocol mismatch - trying to match incompatible field")
                .with_suggestion("Don't use port matching with ICMP or 'Any' protocol")
                .with_suggestion("Use TCP or UDP protocol when matching ports")
                .with_suggestion("For ICMP, use type/code matching instead");
        }

        // Invalid interface
        if lower.contains("interface")
            && (lower.contains("invalid") || lower.contains("does not exist"))
        {
            return ErrorTranslation::new("Network interface not found or invalid")
                .with_suggestion("Check available interfaces: ip link show")
                .with_suggestion("Common interfaces: eth0, wlan0, enp0s3, docker0")
                .with_suggestion("Interface names are case-sensitive and max 15 chars")
                .with_help("https://wiki.archlinux.org/title/Network_configuration");
        }

        // Resource busy
        if lower.contains("resource busy") || lower.contains("device or resource busy") {
            return ErrorTranslation::new("Firewall resource is busy")
                .with_suggestion("Another process may be modifying nftables")
                .with_suggestion("Wait a moment and try again")
                .with_suggestion(
                    "Check for conflicting firewall managers: sudo systemctl status firewalld ufw",
                );
        }

        // Conflicting rules
        if lower.contains("conflict") || lower.contains("already exists") {
            return ErrorTranslation::new("Conflicting firewall rule or table")
                .with_suggestion("A similar rule or table already exists")
                .with_suggestion("Try flushing the table first (this will remove all rules)")
                .with_suggestion("Or modify the existing rule instead of creating a new one");
        }

        // Timeout errors
        if lower.contains("timeout") || lower.contains("timed out") {
            return ErrorTranslation::new("Operation timed out")
                .with_suggestion("The firewall operation took too long")
                .with_suggestion("Check system load: uptime")
                .with_suggestion("Try again when the system is less busy");
        }

        // Netlink errors
        if lower.contains("netlink") {
            return ErrorTranslation::new("Communication error with kernel netlink interface")
                .with_suggestion("The kernel's netlink interface is not responding")
                .with_suggestion("Check kernel modules: lsmod | grep nf_tables")
                .with_suggestion("Load nf_tables module: sudo modprobe nf_tables")
                .with_help("https://wiki.nftables.org/wiki-nftables/index.php/Troubleshooting");
        }

        // Generic fallback
        ErrorTranslation::new(format!("Firewall error: {msg}"))
            .with_suggestion("Check the detailed error message for more information")
            .with_suggestion("Verify nftables is working: sudo nft list ruleset")
            .with_help("https://wiki.nftables.org/wiki-nftables/index.php/Troubleshooting")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorInfo {
    pub message: String,
    pub details: Option<String>,
    pub suggestions: Vec<String>,
    pub help_url: Option<String>,
}

impl ErrorInfo {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            details: None,
            suggestions: Vec::new(),
            help_url: None,
        }
    }

    #[allow(dead_code)]
    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }

    #[allow(dead_code)]
    pub fn with_suggestion(mut self, suggestion: impl Into<String>) -> Self {
        self.suggestions.push(suggestion.into());
        self
    }

    #[allow(dead_code)]
    pub fn with_suggestions(mut self, suggestions: Vec<String>) -> Self {
        self.suggestions = suggestions;
        self
    }

    #[allow(dead_code)]
    pub fn with_help_url(mut self, url: impl Into<String>) -> Self {
        self.help_url = Some(url.into());
        self
    }

    /// Create from an Error with user-friendly message and suggestions
    #[allow(dead_code)]
    pub fn from_error(err: &Error) -> Self {
        let translated = ErrorTranslation::translate(err);
        Self {
            message: translated.user_message,
            details: Some(err.to_string()),
            suggestions: translated.suggestions,
            help_url: translated.help_url,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nftables_error_translation() {
        let err = Error::Nftables {
            message: "Permission denied".to_string(),
            stderr: None,
            exit_code: Some(1),
        };
        let msg = err.user_message();
        assert!(msg.contains("Insufficient permissions"));

        // Test with full translation
        let translation = ErrorTranslation::translate(&err);
        assert!(!translation.suggestions.is_empty());
        assert!(translation.suggestions.iter().any(|s| s.contains("pkexec")));
    }

    #[test]
    fn test_validation_error_message() {
        let err = Error::Validation {
            field: "port".to_string(),
            message: "must be between 1 and 65535".to_string(),
        };
        assert_eq!(err.user_message(), "port: must be between 1 and 65535");

        // Test suggestions
        let translation = ErrorTranslation::translate(&err);
        assert!(!translation.suggestions.is_empty());
    }

    #[test]
    fn test_snapshot_corrupted_message() {
        let err = Error::Snapshot(SnapshotError::Corrupted);
        let msg = err.user_message();
        assert!(msg.contains("corrupted"));

        // Check suggestions contain fix instructions
        let translation = ErrorTranslation::translate(&err);
        assert!(
            translation
                .suggestions
                .iter()
                .any(|s| s.contains("Revert manually"))
        );
    }

    #[test]
    fn test_elevation_error_message() {
        let err = Error::Elevation("pkexec failed".to_string());
        let msg = err.user_message();
        assert!(msg.contains("Permission error"));
        assert!(msg.contains("pkexec"));

        // Check suggestions
        let translation = ErrorTranslation::translate(&err);
        assert!(!translation.suggestions.is_empty());
    }

    #[test]
    fn test_nftables_missing_command() {
        let translation = NftablesErrorPattern::match_error("command not found: nft");
        assert!(translation.user_message.contains("not installed"));
        assert!(translation.suggestions.len() >= 3); // Multiple distro options
    }

    #[test]
    fn test_nftables_syntax_error() {
        let translation = NftablesErrorPattern::match_error("could not process rule: syntax error");
        assert!(translation.user_message.contains("Invalid"));
        assert!(
            translation
                .suggestions
                .iter()
                .any(|s| s.contains("port numbers"))
        );
    }

    #[test]
    fn test_nftables_invalid_port() {
        let translation = NftablesErrorPattern::match_error("invalid port 70000");
        assert!(translation.user_message.contains("port"));
        assert!(translation.suggestions.iter().any(|s| s.contains("65535")));
    }

    #[test]
    fn test_cache_initialization_error() {
        let translation = NftablesErrorPattern::match_error("cache initialization failed");
        assert!(translation.user_message.contains("cache"));
        assert!(translation.user_message.contains("privileges"));
        assert!(translation.suggestions.iter().any(|s| s.contains("pkexec")));
        assert!(translation.help_url.is_some());
    }

    #[test]
    fn test_invalid_expression_type() {
        let translation = NftablesErrorPattern::match_error("Unknown expression type");
        assert!(translation.user_message.contains("expression"));
        assert!(translation.suggestions.iter().any(|s| s.contains("ICMP")));
    }

    #[test]
    fn test_invalid_lhs_relational() {
        let translation = NftablesErrorPattern::match_error("Invalid LHS of relational");
        assert!(translation.user_message.contains("Protocol mismatch"));
        assert!(
            translation
                .suggestions
                .iter()
                .any(|s| s.contains("TCP or UDP"))
        );
    }

    #[test]
    fn test_netlink_error() {
        let translation = NftablesErrorPattern::match_error("netlink error occurred");
        assert!(translation.user_message.contains("netlink"));
        assert!(
            translation
                .suggestions
                .iter()
                .any(|s| s.contains("modprobe"))
        );
        assert!(translation.help_url.is_some());
    }

    #[test]
    fn test_serialization_error() {
        use std::io;
        let io_err = io::Error::new(io::ErrorKind::InvalidData, "bad json");
        let json_err = serde_json::Error::io(io_err);
        let err = Error::Serialization(json_err);

        let translation = ErrorTranslation::translate(&err);
        assert!(translation.user_message.contains("configuration data"));
        assert!(
            translation
                .suggestions
                .iter()
                .any(|s| s.contains("corrupted"))
        );
    }

    #[test]
    fn test_internal_error() {
        let err = Error::Internal("unexpected null pointer".to_string());
        let translation = ErrorTranslation::translate(&err);
        assert!(translation.user_message.contains("Internal error"));
        assert!(translation.suggestions.iter().any(|s| s.contains("bug")));
        assert!(translation.suggestions.iter().any(|s| s.contains("GitHub")));
    }

    #[test]
    fn test_snapshot_not_found() {
        let err = Error::Snapshot(SnapshotError::NotFound("/path/to/missing".to_string()));
        let translation = ErrorTranslation::translate(&err);
        assert!(translation.user_message.contains("not found"));
        assert!(
            translation
                .suggestions
                .iter()
                .any(|s| s.contains("deleted"))
        );
    }

    #[test]
    fn test_snapshot_version_mismatch() {
        let err = Error::Snapshot(SnapshotError::VersionMismatch {
            found: 1,
            expected: 2,
        });
        let translation = ErrorTranslation::translate(&err);
        assert!(translation.user_message.contains("version mismatch"));
        assert!(translation.user_message.contains("v1"));
        assert!(translation.user_message.contains("v2"));
    }

    #[test]
    fn test_io_already_exists() {
        use std::io;
        let io_err = io::Error::new(io::ErrorKind::AlreadyExists, "file exists");
        let err = Error::Io(io_err);

        let translation = ErrorTranslation::translate(&err);
        assert!(translation.user_message.contains("already exists"));
        assert!(
            translation
                .suggestions
                .iter()
                .any(|s| s.contains("different name"))
        );
    }

    #[test]
    fn test_help_urls_provided() {
        // Test that important errors have help URLs
        let err = Error::Validation {
            field: "test".to_string(),
            message: "invalid".to_string(),
        };
        let translation = ErrorTranslation::translate(&err);
        assert!(translation.help_url.is_some());

        let err2 = Error::Elevation("test".to_string());
        let translation2 = ErrorTranslation::translate(&err2);
        assert!(translation2.help_url.is_some());
    }
}
