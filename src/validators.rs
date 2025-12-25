//! Input validation and sanitization functions for DRFW
//!
//! This module provides centralized validation for all user inputs to prevent
//! injection attacks and ensure data integrity.

/// Sanitizes a label for safe use in nftables comments.
///
/// Removes control characters, quotes, and shell metacharacters.
/// Limits length to 64 characters as per specification.
///
/// # Examples
///
/// ```
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
            // Allow alphanumeric, space, and safe punctuation only
            c.is_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.' | ':')
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
            prop_assert!(!sanitized.chars().any(|c| c.is_control()));
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
            let invalid_name = format!("{}{}", valid_prefix, invalid_char);
            let result = validate_interface(&invalid_name);
            prop_assert!(result.is_err());
        }
    }
}
