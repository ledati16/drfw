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
    /// Returns a user-friendly error message (legacy method, use ErrorTranslation::translate instead)
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
            Error::Validation { field, message } => Self::new(format!("{}: {}", field, message))
                .with_suggestion(format!("Check the '{}' field and correct the value", field)),
            Error::Elevation(msg) => Self::new(format!("Permission error: {}", msg))
                .with_suggestion(
                    "Ensure pkexec is installed and configured: sudo apt install policykit-1",
                )
                .with_suggestion("Check that your user is in the 'sudo' or 'wheel' group")
                .with_suggestion("Try running: pkexec --version"),
            Error::Snapshot(SnapshotError::Corrupted) => {
                Self::new("Snapshot file is corrupted and cannot be restored")
                    .with_suggestion("Revert manually: sudo nft flush ruleset")
                    .with_suggestion("Apply a new configuration to replace the corrupted snapshot")
            }
            Error::Snapshot(SnapshotError::ChecksumMismatch { expected, actual }) => {
                Self::new("Snapshot integrity check failed")
                    .with_suggestion(format!("Expected checksum: {}", expected))
                    .with_suggestion(format!("Actual checksum: {}", actual))
                    .with_suggestion("The file may have been tampered with or corrupted")
            }
            Error::Io(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                Self::new("Permission denied")
                    .with_suggestion("Ensure you have the necessary privileges")
                    .with_suggestion("Check file permissions: ls -la ~/.local/share/drfw/")
            }
            Error::Io(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Self::new("Required file or command not found")
                    .with_suggestion("Install nftables: sudo apt install nftables")
                    .with_suggestion("Verify nftables is in PATH: which nft")
            }
            _ => Self::new(err.to_string()),
        }
    }
}

/// Database of nftables error patterns and their translations
struct NftablesErrorPattern;

impl NftablesErrorPattern {
    fn match_error(msg: &str) -> ErrorTranslation {
        let lower = msg.to_lowercase();

        // Permission errors
        if lower.contains("permission denied") || lower.contains("operation not permitted") {
            return ErrorTranslation::new("Insufficient permissions to modify firewall rules")
                .with_suggestion("Ensure pkexec is configured correctly")
                .with_suggestion("Verify nftables service is accessible: systemctl status nftables")
                .with_suggestion("Check if CAP_NET_ADMIN capability is available");
        }

        // Missing nftables
        if lower.contains("no such file") || lower.contains("command not found") {
            return ErrorTranslation::new("nftables is not installed or not found in PATH")
                .with_suggestion("Install nftables: sudo apt install nftables  (Debian/Ubuntu)")
                .with_suggestion("Or: sudo dnf install nftables  (Fedora/RHEL)")
                .with_suggestion("Or: sudo pacman -S nftables  (Arch)");
        }

        // Syntax errors
        if lower.contains("could not process rule") || lower.contains("syntax error") {
            return ErrorTranslation::new("Invalid firewall rule syntax")
                .with_suggestion("Check your rule configuration for typos")
                .with_suggestion("Verify port numbers are between 1 and 65535")
                .with_suggestion("Ensure IP addresses and network masks are valid");
        }

        // Table doesn't exist
        if lower.contains("table") && lower.contains("does not exist") {
            return ErrorTranslation::new("Firewall table does not exist")
                .with_suggestion("The 'drfw' table may not have been created yet")
                .with_suggestion("Try applying your rules to create the table");
        }

        // Chain errors
        if lower.contains("chain")
            && (lower.contains("does not exist") || lower.contains("not found"))
        {
            return ErrorTranslation::new("Firewall chain not found")
                .with_suggestion("Ensure the chain exists before adding rules to it")
                .with_suggestion("Apply the base configuration first");
        }

        // Port range errors
        if lower.contains("invalid port") || lower.contains("port") && lower.contains("range") {
            return ErrorTranslation::new("Invalid port or port range")
                .with_suggestion("Port numbers must be between 1 and 65535")
                .with_suggestion("For port ranges, ensure start < end")
                .with_suggestion("Example: 8000-9000");
        }

        // Invalid IP address
        if lower.contains("invalid")
            && (lower.contains("ip") || lower.contains("address") || lower.contains("network"))
        {
            return ErrorTranslation::new("Invalid IP address or network")
                .with_suggestion("Use proper IP format: 192.168.1.1 or 192.168.1.0/24")
                .with_suggestion("For IPv6: 2001:db8::1 or 2001:db8::/32")
                .with_suggestion("Check CIDR notation: /24 for IPv4, /64 for IPv6");
        }

        // Invalid interface
        if lower.contains("interface")
            && (lower.contains("invalid") || lower.contains("does not exist"))
        {
            return ErrorTranslation::new("Network interface not found or invalid")
                .with_suggestion("Check available interfaces: ip link show")
                .with_suggestion("Common interfaces: eth0, wlan0, enp0s3, docker0")
                .with_suggestion("Interface names are case-sensitive");
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

        // Generic fallback
        ErrorTranslation::new(format!("Firewall error: {}", msg))
            .with_suggestion("Check the detailed error message for more information")
            .with_suggestion("Verify nftables is working: sudo nft list ruleset")
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
}
