//! Input validation and sanitization functions for DRFW
//!
//! This module provides centralized validation for all user inputs to prevent
//! injection attacks and ensure data integrity.

/// Sanitizes a label for safe use in nftables comments.
///
/// Removes control characters, quotes, and shell metacharacters.
/// Limits length to 64 bytes (ASCII characters only) as per specification.
///
/// SECURITY: Uses `is_ascii_alphanumeric()` to prevent Unicode-based bypasses
/// and ensure labels stay within system limits (64 bytes max).
///
/// # Examples
///
/// ```
/// use drfw::validators::sanitize_label;
///
/// let safe = sanitize_label("Normal Label");
/// assert_eq!(safe, "Normal Label");
///
/// let unsafe_label = "Test\nNewline\"Quote";
/// let safe = sanitize_label(unsafe_label);
/// assert!(!safe.contains('\n'));
/// assert!(!safe.contains('"'));
/// ```
pub fn sanitize_label(input: &str) -> String {
    input
        .chars()
        .filter(|c| {
            // SECURITY: Use ASCII-only to prevent Unicode bypasses and multi-byte issues
            c.is_ascii_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.' | ':')
        })
        .take(64)
        .collect()
}

/// Validates and sanitizes a rule label.
///
/// # Errors
///
/// Returns `Err` if:
/// - Label exceeds 64 characters
/// - Label becomes empty after sanitization (all invalid chars)
#[allow(dead_code)]
pub fn validate_label(input: &str) -> Result<String, String> {
    if input.len() > 64 {
        return Err("Label too long (max 64 characters)".to_string());
    }

    let sanitized = sanitize_label(input);

    if sanitized.is_empty() && !input.is_empty() {
        return Err("Label contains only invalid characters".to_string());
    }

    Ok(sanitized)
}

/// Validates a single port number.
///
/// # Errors
///
/// Returns `Err` if port is 0 (reserved).
pub fn validate_port(port: u16) -> Result<u16, String> {
    if port == 0 {
        Err("Port must be between 1 and 65535".to_string())
    } else {
        Ok(port)
    }
}

/// Validates a port range.
///
/// # Errors
///
/// Returns `Err` if:
/// - Either port is 0
/// - Start port is greater than end port
pub fn validate_port_range(start: u16, end: u16) -> Result<(u16, u16), String> {
    validate_port(start)?;
    validate_port(end)?;

    if start > end {
        Err("Start port must be less than or equal to end port".to_string())
    } else {
        Ok((start, end))
    }
}

/// Validates a network interface name.
///
/// Linux kernel interface name rules:
/// - Max 15 characters (IFNAMSIZ - 1)
/// - Alphanumeric, dot, dash, underscore only
/// - Cannot be "." or ".."
///
/// # Errors
///
/// Returns `Err` if interface name violates kernel constraints.
pub fn validate_interface(name: &str) -> Result<String, String> {
    if name.is_empty() {
        return Ok(String::new());
    }

    if name.len() > 15 {
        return Err("Interface name too long (max 15 characters)".to_string());
    }

    if name == "." || name == ".." {
        return Err("Invalid interface name".to_string());
    }

    // Check for valid characters (ASCII alphanumeric only, plus dot, dash, underscore)
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        return Err("Interface name contains invalid characters".to_string());
    }

    Ok(name.to_string())
}

/// Validates a rate limit value.
///
/// Returns Ok(Some(warning)) for high but acceptable values.
/// Returns Err for values that exceed kernel/system limits.
///
/// # Errors
///
/// Returns `Err` if rate exceeds reasonable maximum for the given time unit.
pub fn validate_rate_limit(
    count: u32,
    unit: crate::core::firewall::TimeUnit,
) -> Result<Option<String>, String> {
    use crate::core::firewall::TimeUnit;

    let (max, warn) = match unit {
        TimeUnit::Second => (10_000, 1_000),
        TimeUnit::Minute => (100_000, 10_000),
        TimeUnit::Hour => (1_000_000, 100_000),
        TimeUnit::Day => (10_000_000, 1_000_000),
    };

    if count > max {
        return Err(format!("Rate limit exceeds max {}/{}", max, unit.as_str()));
    }

    if count > warn {
        return Ok(Some(format!(
            "High rate ({}/{}) - typical: 10-{}",
            count,
            unit.as_str(),
            warn / 10
        )));
    }

    Ok(None)
}

/// Validates connection limit.
///
/// Returns Ok(Some(warning)) for high but acceptable values.
/// Returns Err for values exceeding kernel maximum (65535).
///
/// # Errors
///
/// Returns `Err` if limit exceeds kernel maximum (65535).
pub fn validate_connection_limit(limit: u32) -> Result<Option<String>, String> {
    if limit == 0 {
        return Ok(None); // 0 = disabled
    }

    if limit > 65_535 {
        return Err("Connection limit exceeds kernel max (65535)".to_string());
    }

    if limit > 10_000 {
        return Ok(Some(format!(
            "High connection limit ({}) - typical: 10-1000",
            limit
        )));
    }

    Ok(None)
}

/// Validates ICMP rate limit for advanced security settings.
///
/// ICMP traffic is typically low-volume, so limits are more restrictive.
///
/// # Errors
///
/// Returns `Err` if rate exceeds 1000/sec (ICMP should be low-volume).
#[allow(dead_code)]
pub fn validate_icmp_rate_limit(rate: u32) -> Result<Option<String>, String> {
    if rate == 0 {
        return Ok(None); // Disabled
    }

    if rate > 1000 {
        return Err("ICMP rate exceeds max (1000/sec) - ICMP is low-volume".to_string());
    }

    if rate > 100 {
        return Ok(Some(format!(
            "ICMP rate ({}/sec) is high - typical: 10 pps",
            rate
        )));
    }

    Ok(None)
}

/// Validates log rate per minute.
///
/// High log rates can flood system logs and impact performance.
///
/// # Errors
///
/// Returns `Err` if:
/// - Rate is 0 (logs must be rate-limited if enabled)
/// - Rate exceeds 1000/min (will flood logs)
#[allow(dead_code)]
pub fn validate_log_rate(rate: u32) -> Result<Option<String>, String> {
    if rate == 0 {
        return Err("Log rate must be at least 1/min".to_string());
    }

    if rate > 1000 {
        return Err("Log rate exceeds max (1000/min) - will flood logs".to_string());
    }

    if rate > 60 {
        return Ok(Some(format!(
            "High log rate ({}/min) - default: 5/min",
            rate
        )));
    }

    Ok(None)
}

/// Validates and sanitizes a log prefix.
///
/// Log prefixes appear in kernel logs and must be safe for syslog.
///
/// # Errors
///
/// Returns `Err` if:
/// - Prefix is empty
/// - Prefix exceeds 64 characters
/// - All characters are invalid (becomes empty after sanitization)
#[allow(dead_code)]
pub fn validate_log_prefix(prefix: &str) -> Result<String, String> {
    if prefix.is_empty() {
        return Err("Log prefix cannot be empty".to_string());
    }

    if prefix.len() > 64 {
        return Err("Log prefix too long (max 64 chars)".to_string());
    }

    let sanitized: String = prefix
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '-' | '_' | ':' | '.'))
        .collect();

    if sanitized.is_empty() {
        return Err("Log prefix contains only invalid characters".to_string());
    }

    Ok(sanitized)
}

/// Checks if a port is well-known and returns informational message.
///
/// This is informational only and does not block saving.
pub fn check_well_known_port(port: u16) -> Option<String> {
    if port <= 1024 {
        let name = match port {
            22 => "SSH",
            80 => "HTTP",
            443 => "HTTPS",
            53 => "DNS",
            25 => "SMTP",
            21 => "FTP",
            3389 => "RDP",
            _ => return Some(format!("Privileged port {} (requires admin)", port)),
        };
        Some(format!("Port {}: {}", port, name))
    } else {
        None
    }
}

/// Checks if an IP is in a reserved range and returns informational warning.
///
/// This is informational only and does not block saving.
/// Helps users understand if they're targeting private/special ranges.
pub fn check_reserved_ip(ip: ipnetwork::IpNetwork) -> Option<String> {
    use std::net::IpAddr;

    match ip.ip() {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();

            // RFC 1918 private ranges
            if octets[0] == 10
                || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 168)
            {
                return Some("Private IP range (RFC 1918) - usually safe for LAN".to_string());
            }

            // Loopback
            if octets[0] == 127 {
                return Some(
                    "Loopback range (127.x) - loopback rules already exist".to_string(),
                );
            }

            // Link-local
            if octets[0] == 169 && octets[1] == 254 {
                return Some("Link-local range (169.254.x.x) - APIPA addresses".to_string());
            }

            None
        }
        IpAddr::V6(ipv6) => {
            if ipv6.is_loopback() {
                return Some("IPv6 loopback (::1) - loopback rules already exist".to_string());
            }

            if ipv6.segments()[0] & 0xffc0 == 0xfe80 {
                return Some("IPv6 link-local (fe80::/10) - local network only".to_string());
            }

            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_label_normal() {
        assert_eq!(sanitize_label("Normal Label"), "Normal Label");
        assert_eq!(sanitize_label("SSH Access"), "SSH Access");
        assert_eq!(sanitize_label("Rule_123"), "Rule_123");
    }

    #[test]
    fn test_sanitize_label_removes_control_chars() {
        assert_eq!(sanitize_label("Test\nNewline"), "TestNewline");
        assert_eq!(sanitize_label("Test\rCarriage"), "TestCarriage");
        assert_eq!(sanitize_label("Test\0Null"), "TestNull");
        assert_eq!(sanitize_label("Test\tTab"), "TestTab");
    }

    #[test]
    fn test_sanitize_label_removes_quotes() {
        assert_eq!(sanitize_label("Test\"Quote"), "TestQuote");
        assert_eq!(sanitize_label("Test'Single"), "TestSingle");
    }

    #[test]
    fn test_sanitize_label_removes_shell_metacharacters() {
        assert_eq!(sanitize_label("Test$Dollar"), "TestDollar");
        assert_eq!(sanitize_label("Test`Backtick"), "TestBacktick");
        assert_eq!(sanitize_label("Test|Pipe"), "TestPipe");
        assert_eq!(sanitize_label("Test&Ampersand"), "TestAmpersand");
        assert_eq!(sanitize_label("Test;Semicolon"), "TestSemicolon");
    }

    #[test]
    fn test_sanitize_label_length_limit() {
        let long_label = "a".repeat(100);
        let sanitized = sanitize_label(&long_label);
        assert_eq!(sanitized.len(), 64);
    }

    #[test]
    fn test_sanitize_label_unicode() {
        // Unicode should be removed (not alphanumeric ASCII)
        assert_eq!(sanitize_label("Test😀Emoji"), "TestEmoji");
        assert_eq!(sanitize_label("Test™Symbol"), "TestSymbol");
    }

    #[test]
    fn test_validate_label_too_long() {
        let long_label = "a".repeat(65);
        assert!(validate_label(&long_label).is_err());
    }

    #[test]
    fn test_validate_label_only_invalid_chars() {
        assert!(validate_label("!!!").is_err());
        assert!(validate_label("$$$").is_err());
    }

    #[test]
    fn test_validate_label_valid() {
        assert!(validate_label("SSH Access").is_ok());
        assert_eq!(validate_label("SSH Access").unwrap(), "SSH Access");
    }

    #[test]
    fn test_validate_port_zero() {
        assert!(validate_port(0).is_err());
    }

    #[test]
    fn test_validate_port_valid() {
        assert_eq!(validate_port(1).unwrap(), 1);
        assert_eq!(validate_port(80).unwrap(), 80);
        assert_eq!(validate_port(443).unwrap(), 443);
        assert_eq!(validate_port(65535).unwrap(), 65535);
    }

    #[test]
    fn test_validate_port_range_valid() {
        assert_eq!(validate_port_range(80, 80).unwrap(), (80, 80));
        assert_eq!(validate_port_range(1, 1024).unwrap(), (1, 1024));
        assert_eq!(validate_port_range(8000, 9000).unwrap(), (8000, 9000));
    }

    #[test]
    fn test_validate_port_range_invalid() {
        assert!(validate_port_range(0, 100).is_err());
        assert!(validate_port_range(100, 0).is_err());
        assert!(validate_port_range(100, 50).is_err());
    }

    #[test]
    fn test_validate_interface_valid() {
        assert!(validate_interface("eth0").is_ok());
        assert!(validate_interface("br0.100").is_ok());
        assert!(validate_interface("wlan_2").is_ok());
        assert!(validate_interface("lo").is_ok());
        assert!(validate_interface("enp3s0").is_ok());
    }

    #[test]
    fn test_validate_interface_empty() {
        assert!(validate_interface("").is_ok());
    }

    #[test]
    fn test_validate_interface_invalid() {
        assert!(validate_interface(".").is_err());
        assert!(validate_interface("..").is_err());
        assert!(validate_interface("eth0 ; rm -rf /").is_err());
        assert!(validate_interface("test|pipe").is_err());
    }

    #[test]
    fn test_validate_interface_too_long() {
        let long_name = "a".repeat(16);
        assert!(validate_interface(&long_name).is_err());
    }

    #[test]
    fn test_validate_interface_max_length() {
        let name = "a".repeat(15);
        assert!(validate_interface(&name).is_ok());
    }

    // Rate limit validation tests
    #[test]
    fn test_validate_rate_limit_normal() {
        use crate::core::firewall::TimeUnit;

        assert!(validate_rate_limit(10, TimeUnit::Second).unwrap().is_none());
        assert!(validate_rate_limit(50, TimeUnit::Minute).unwrap().is_none());
        assert!(validate_rate_limit(100, TimeUnit::Hour).unwrap().is_none());
    }

    #[test]
    fn test_validate_rate_limit_warning() {
        use crate::core::firewall::TimeUnit;

        let result = validate_rate_limit(5000, TimeUnit::Second).unwrap();
        assert!(result.is_some());
        assert!(result.unwrap().contains("High rate"));
    }

    #[test]
    fn test_validate_rate_limit_exceeds_max() {
        use crate::core::firewall::TimeUnit;

        assert!(validate_rate_limit(99999, TimeUnit::Second).is_err());
        assert!(validate_rate_limit(999999, TimeUnit::Minute).is_err());
    }

    // Connection limit tests
    #[test]
    fn test_validate_connection_limit_zero() {
        assert!(validate_connection_limit(0).unwrap().is_none());
    }

    #[test]
    fn test_validate_connection_limit_normal() {
        assert!(validate_connection_limit(100).unwrap().is_none());
        assert!(validate_connection_limit(1000).unwrap().is_none());
    }

    #[test]
    fn test_validate_connection_limit_warning() {
        let result = validate_connection_limit(50000).unwrap();
        assert!(result.is_some());
        assert!(result.unwrap().contains("High connection limit"));
    }

    #[test]
    fn test_validate_connection_limit_exceeds_max() {
        assert!(validate_connection_limit(99999).is_err());
        assert!(validate_connection_limit(234234234).is_err());
    }

    // ICMP rate limit tests
    #[test]
    fn test_validate_icmp_rate_limit_zero() {
        assert!(validate_icmp_rate_limit(0).unwrap().is_none());
    }

    #[test]
    fn test_validate_icmp_rate_limit_normal() {
        assert!(validate_icmp_rate_limit(10).unwrap().is_none());
        assert!(validate_icmp_rate_limit(50).unwrap().is_none());
    }

    #[test]
    fn test_validate_icmp_rate_limit_warning() {
        let result = validate_icmp_rate_limit(200).unwrap();
        assert!(result.is_some());
        assert!(result.unwrap().contains("ICMP rate"));
    }

    #[test]
    fn test_validate_icmp_rate_limit_exceeds_max() {
        assert!(validate_icmp_rate_limit(5000).is_err());
    }

    // Log rate tests
    #[test]
    fn test_validate_log_rate_zero() {
        assert!(validate_log_rate(0).is_err());
    }

    #[test]
    fn test_validate_log_rate_normal() {
        assert!(validate_log_rate(5).unwrap().is_none());
        assert!(validate_log_rate(30).unwrap().is_none());
    }

    #[test]
    fn test_validate_log_rate_warning() {
        let result = validate_log_rate(100).unwrap();
        assert!(result.is_some());
        assert!(result.unwrap().contains("High log rate"));
    }

    #[test]
    fn test_validate_log_rate_exceeds_max() {
        assert!(validate_log_rate(5000).is_err());
    }

    // Log prefix tests
    #[test]
    fn test_validate_log_prefix_empty() {
        assert!(validate_log_prefix("").is_err());
    }

    #[test]
    fn test_validate_log_prefix_too_long() {
        let long_prefix = "a".repeat(65);
        assert!(validate_log_prefix(&long_prefix).is_err());
    }

    #[test]
    fn test_validate_log_prefix_valid() {
        assert_eq!(validate_log_prefix("DRFW-DROP").unwrap(), "DRFW-DROP");
        assert_eq!(
            validate_log_prefix("firewall:input").unwrap(),
            "firewall:input"
        );
    }

    #[test]
    fn test_validate_log_prefix_sanitizes() {
        assert_eq!(validate_log_prefix("test$bad").unwrap(), "testbad");
        assert_eq!(validate_log_prefix("test\nline").unwrap(), "testline");
    }

    #[test]
    fn test_validate_log_prefix_only_invalid_chars() {
        assert!(validate_log_prefix("$$$").is_err());
    }

    // Well-known port tests
    #[test]
    fn test_check_well_known_port_ssh() {
        let result = check_well_known_port(22);
        assert!(result.is_some());
        assert!(result.unwrap().contains("SSH"));
    }

    #[test]
    fn test_check_well_known_port_http() {
        let result = check_well_known_port(80);
        assert!(result.is_some());
        assert!(result.unwrap().contains("HTTP"));
    }

    #[test]
    fn test_check_well_known_port_https() {
        let result = check_well_known_port(443);
        assert!(result.is_some());
        assert!(result.unwrap().contains("HTTPS"));
    }

    #[test]
    fn test_check_well_known_port_privileged() {
        let result = check_well_known_port(999);
        assert!(result.is_some());
        assert!(result.unwrap().contains("Privileged"));
    }

    #[test]
    fn test_check_well_known_port_high() {
        let result = check_well_known_port(8080);
        assert!(result.is_none());
    }

    // Reserved IP tests
    #[test]
    fn test_check_reserved_ip_private_10() {
        let ip = "10.0.0.0/8".parse().unwrap();
        let result = check_reserved_ip(ip);
        assert!(result.is_some());
        assert!(result.unwrap().contains("RFC 1918"));
    }

    #[test]
    fn test_check_reserved_ip_private_172() {
        let ip = "172.16.0.0/12".parse().unwrap();
        let result = check_reserved_ip(ip);
        assert!(result.is_some());
        assert!(result.unwrap().contains("RFC 1918"));
    }

    #[test]
    fn test_check_reserved_ip_private_192() {
        let ip = "192.168.1.0/24".parse().unwrap();
        let result = check_reserved_ip(ip);
        assert!(result.is_some());
        assert!(result.unwrap().contains("RFC 1918"));
    }

    #[test]
    fn test_check_reserved_ip_loopback() {
        let ip = "127.0.0.1/8".parse().unwrap();
        let result = check_reserved_ip(ip);
        assert!(result.is_some());
        assert!(result.unwrap().contains("Loopback"));
    }

    #[test]
    fn test_check_reserved_ip_link_local() {
        let ip = "169.254.1.1/16".parse().unwrap();
        let result = check_reserved_ip(ip);
        assert!(result.is_some());
        assert!(result.unwrap().contains("Link-local"));
    }

    #[test]
    fn test_check_reserved_ip_ipv6_loopback() {
        let ip = "::1/128".parse().unwrap();
        let result = check_reserved_ip(ip);
        assert!(result.is_some());
        assert!(result.unwrap().contains("loopback"));
    }

    #[test]
    fn test_check_reserved_ip_ipv6_link_local() {
        let ip = "fe80::1/64".parse().unwrap();
        let result = check_reserved_ip(ip);
        assert!(result.is_some());
        assert!(result.unwrap().contains("link-local"));
    }

    #[test]
    fn test_check_reserved_ip_public() {
        let ip = "8.8.8.8/32".parse().unwrap();
        let result = check_reserved_ip(ip);
        assert!(result.is_none());
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_sanitize_label_never_exceeds_64_chars(input in "\\PC*") {
            let sanitized = sanitize_label(&input);
            prop_assert!(sanitized.len() <= 64);
        }

        #[test]
        fn test_sanitize_label_no_control_chars(input in "\\PC*") {
            let sanitized = sanitize_label(&input);
            prop_assert!(!sanitized.chars().any(char::is_control));
        }

        #[test]
        fn test_sanitize_label_no_dangerous_chars(input in "\\PC*") {
            let sanitized = sanitize_label(&input);
            prop_assert!(!sanitized.contains('"'));
            prop_assert!(!sanitized.contains('\''));
            prop_assert!(!sanitized.contains('$'));
            prop_assert!(!sanitized.contains('`'));
            prop_assert!(!sanitized.contains('|'));
            prop_assert!(!sanitized.contains('&'));
            prop_assert!(!sanitized.contains(';'));
        }

        #[test]
        fn test_validate_port_rejects_zero(port in any::<u16>()) {
            let result = validate_port(port);
            if port == 0 {
                prop_assert!(result.is_err());
            } else {
                prop_assert!(result.is_ok());
                prop_assert_eq!(result.unwrap(), port);
            }
        }

        #[test]
        fn test_validate_port_range_consistency(
            start in 1u16..=65535,
            end in 1u16..=65535
        ) {
            let result = validate_port_range(start, end);
            if start <= end {
                prop_assert!(result.is_ok());
                let (s, e) = result.unwrap();
                prop_assert_eq!(s, start);
                prop_assert_eq!(e, end);
            } else {
                prop_assert!(result.is_err());
            }
        }

        #[test]
        fn test_validate_interface_length_constraint(name in "[a-zA-Z0-9._-]{0,20}") {
            let result = validate_interface(&name);
            if name.len() <= 15 && name != "." && name != ".." {
                prop_assert!(result.is_ok());
            } else if name.len() > 15 {
                prop_assert!(result.is_err());
            }
        }

        #[test]
        fn test_validate_interface_char_constraint(
            valid_prefix in "[a-zA-Z0-9._-]{1,10}",
            invalid_char in "[^a-zA-Z0-9._-]"
        ) {
            let invalid_name = format!("{valid_prefix}{invalid_char}");
            let result = validate_interface(&invalid_name);
            prop_assert!(result.is_err());
        }
    }
}
