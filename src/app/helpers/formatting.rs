//! Text formatting utilities for UI display

use std::path::Path;

/// Smart truncate a file path to fit in notifications
///
/// Keeps the filename and 1-2 parent directories for context.
/// Example: "/very/long/path/to/configs/production/rules.nft"
///       -> ".../production/rules.nft"
pub fn truncate_path_smart(path: &str, max_len: usize) -> String {
    if path.len() <= max_len {
        return path.to_string();
    }

    let path_obj = Path::new(path);

    // Always keep filename
    let filename = path_obj
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("file");

    // Try to keep parent directory for context
    let parent = path_obj.parent();

    if let Some(parent) = parent
        && let Some(parent_name) = parent.file_name().and_then(|f| f.to_str())
    {
        let short = format!(".../{parent_name}/{filename}");
        if short.len() <= max_len {
            return short;
        }
    }

    // Fallback: just filename with ellipsis
    format!(".../{filename}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_path_short() {
        let path = "/short/path.txt";
        assert_eq!(truncate_path_smart(path, 100), path);
    }

    #[test]
    fn test_truncate_path_long() {
        let path = "/very/long/path/to/configs/production/rules.nft";
        let truncated = truncate_path_smart(path, 30);
        assert!(truncated.len() <= 30);
        assert!(truncated.contains("rules.nft"));
        assert!(truncated.starts_with("..."));
    }

    #[test]
    fn test_truncate_path_exact_length() {
        let path = "exact";
        assert_eq!(truncate_path_smart(path, 5), "exact");
    }
}
