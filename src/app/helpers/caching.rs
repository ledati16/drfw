//! Width calculation and cache management utilities

use crate::app::syntax_cache::HighlightedLine;

/// Calculate maximum content width from highlighted lines (generic implementation)
///
/// Works with both owned slices (`&[HighlightedLine]`) and reference slices (`&[&HighlightedLine]`)
/// via the `IntoIterator` trait. Used for horizontal scrolling calculations in syntax-highlighted views.
///
/// Phase 3.1: Unified implementation to eliminate code duplication
fn calculate_max_content_width_generic<'a, I>(tokens: I) -> f32
where
    I: IntoIterator<Item = &'a HighlightedLine>,
{
    const CHAR_WIDTH_PX: f32 = 8.4;
    const LINE_NUMBER_WIDTH_PX: f32 = 50.0;
    const TRAILING_PADDING_PX: f32 = 60.0;
    const MIN_WIDTH_PX: f32 = 800.0;
    const MAX_WIDTH_PX: f32 = 3000.0;

    let max_char_count = tokens
        .into_iter()
        .map(|line| {
            let indent_chars = line.indent;
            let token_chars: usize = line.tokens.iter().map(|t| t.text.len()).sum();
            indent_chars + token_chars
        })
        .max()
        .unwrap_or(0);

    let content_width =
        LINE_NUMBER_WIDTH_PX + (max_char_count as f32 * CHAR_WIDTH_PX) + TRAILING_PADDING_PX;
    content_width.clamp(MIN_WIDTH_PX, MAX_WIDTH_PX)
}

/// Calculate maximum content width from highlighted lines (owned slice)
///
/// Works with slices of `HighlightedLine`.
/// Used for horizontal scrolling calculations in syntax-highlighted views.
pub fn calculate_max_content_width(tokens: &[HighlightedLine]) -> f32 {
    calculate_max_content_width_generic(tokens)
}

/// Calculate maximum content width from highlighted lines (reference slice)
///
/// Works with slices of references to `HighlightedLine`.
/// Used for horizontal scrolling calculations when working with borrowed data.
pub fn calculate_max_content_width_from_refs(tokens: &[&HighlightedLine]) -> f32 {
    calculate_max_content_width_generic(tokens.iter().copied())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::syntax_cache::{HighlightedLine, Token, TokenColor};
    use std::borrow::Cow;

    fn create_test_line(indent: usize, text_len: usize) -> HighlightedLine {
        HighlightedLine {
            line_number: 1,
            formatted_line_number_json: "  1 ".to_string(),
            formatted_line_number_nft: "   1".to_string(),
            indent,
            tokens: vec![Token {
                text: Cow::Owned("x".repeat(text_len)),
                color: TokenColor::Primary,
                bold: false,
                italic: false,
            }],
        }
    }

    #[test]
    fn test_calculate_width_empty() {
        let tokens: Vec<HighlightedLine> = vec![];
        let width = calculate_max_content_width(&tokens);
        assert_eq!(width, 800.0); // MIN_WIDTH_PX
    }

    #[test]
    fn test_calculate_width_single_line() {
        let tokens = vec![create_test_line(0, 10)];
        let width = calculate_max_content_width(&tokens);
        // LINE_NUMBER_WIDTH (50) + (10 chars * 8.4) + TRAILING (60) = 194
        // Clamped to MIN 800
        assert_eq!(width, 800.0);
    }

    #[test]
    fn test_calculate_width_long_line() {
        let tokens = vec![create_test_line(0, 300)];
        let width = calculate_max_content_width(&tokens);
        // LINE_NUMBER_WIDTH (50) + (300 * 8.4) + TRAILING (60) = 2630
        assert!(width > 800.0);
        assert!(width < 3000.0);
    }

    #[test]
    fn test_calculate_width_with_indent() {
        let tokens = vec![create_test_line(4, 10)];
        let width = calculate_max_content_width(&tokens);
        // Should account for both indent (4) and text (10) = 14 chars total
        assert_eq!(width, 800.0); // Still clamped to min
    }

    #[test]
    fn test_calculate_width_max_clamp() {
        // Create a very long line that exceeds MAX_WIDTH_PX
        let tokens = vec![create_test_line(0, 1000)];
        let width = calculate_max_content_width(&tokens);
        assert_eq!(width, 3000.0); // MAX_WIDTH_PX
    }

    #[test]
    fn test_calculate_width_from_refs() {
        // Test that it works with Vec<&HighlightedLine>
        let line1 = create_test_line(0, 10);
        let line2 = create_test_line(0, 20);
        let tokens = vec![&line1, &line2];
        let width = calculate_max_content_width_from_refs(&tokens);
        assert_eq!(width, 800.0);
    }
}
