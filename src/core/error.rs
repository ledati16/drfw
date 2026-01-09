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
    #[allow(dead_code)] // Constructed in tests to verify translation
    Validation { field: String, message: String },

    /// Snapshot operation failed
    #[error("Snapshot error: {0}")]
    Snapshot(#[from] SnapshotError),

    /// Privilege escalation failed
    #[error("Elevation error: {0}")]
    #[allow(dead_code)] // Constructed in tests to verify translation
    Elevation(String),

    /// Internal logic error
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Snapshot-specific errors
#[derive(Debug, Error)]
#[allow(dead_code)] // Constructed in tests to verify translation messages
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

/// Represents a translated error with helpful context
#[derive(Debug, Clone)]
pub struct ErrorTranslation {
    pub user_message: String,
    pub suggestions: Vec<String>,
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

    pub fn with_help(mut self, url: impl Into<String>) -> Self {
        self.help_url = Some(url.into());
        self
    }
}

/// Database of nftables error patterns and their translations
pub struct NftablesErrorPattern;

impl NftablesErrorPattern {
    /// Matches an error message against known patterns and returns a user-friendly translation.
    pub fn match_error(msg: &str) -> ErrorTranslation {
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

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

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
}
