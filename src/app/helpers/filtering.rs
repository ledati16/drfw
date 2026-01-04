//! Fuzzy search and filtering utilities

use nucleo_matcher::{Config, Matcher, Utf32Str};

/// Fuzzy filters fonts by name using the nucleo matcher.
///
/// Returns fonts sorted by match quality (best matches first).
/// Empty queries return all fonts with a score of 0.
///
/// Uses buffer reuse optimization to minimize allocations during filtering.
///
/// # Arguments
///
/// * `fonts` - Iterator of font choices to filter
/// * `query` - Search string (case-insensitive matching)
///
/// # Returns
///
/// Vector of (font, score) tuples sorted by descending score (best matches first).
/// Higher scores indicate better matches.
pub fn fuzzy_filter_fonts<'a>(
    fonts: impl Iterator<Item = &'a crate::fonts::FontChoice>,
    query: &str,
) -> Vec<(&'a crate::fonts::FontChoice, u16)> {
    if query.is_empty() {
        return fonts.map(|f| (f, 0)).collect();
    }

    let mut matcher = Matcher::new(Config::DEFAULT);
    let mut needle_buf = Vec::new();
    let needle = Utf32Str::new(query, &mut needle_buf);

    // Reuse buffer across all fonts to reduce allocations
    let mut haystack_buf = Vec::new();

    let mut results: Vec<_> = fonts
        .filter_map(|font| {
            haystack_buf.clear(); // Reuse instead of reallocate
            let haystack = Utf32Str::new(font.name_lowercase(), &mut haystack_buf);
            matcher
                .fuzzy_match(haystack, needle)
                .map(|score| (font, score))
        })
        .collect();

    // Sort by score descending (highest relevance first)
    results.sort_unstable_by(|a, b| b.1.cmp(&a.1));
    results
}

/// Fuzzy filters themes by name using the nucleo matcher.
///
/// Returns themes sorted by match quality (best matches first).
/// Empty queries return all themes with a score of 0.
///
/// Uses buffer reuse optimization to minimize allocations during filtering.
///
/// # Arguments
///
/// * `themes` - Iterator of theme choices to filter
/// * `query` - Search string (case-insensitive matching)
///
/// # Returns
///
/// Vector of (theme, score) tuples sorted by descending score (best matches first).
/// Higher scores indicate better matches.
pub fn fuzzy_filter_themes(
    themes: impl Iterator<Item = crate::theme::ThemeChoice>,
    query: &str,
) -> Vec<(crate::theme::ThemeChoice, u16)> {
    if query.is_empty() {
        return themes.map(|t| (t, 0)).collect();
    }

    let mut matcher = Matcher::new(Config::DEFAULT);
    let query_lowercase = query.to_lowercase();
    let mut needle_buf = Vec::new();
    let needle = Utf32Str::new(&query_lowercase, &mut needle_buf);

    // Reuse buffer across all themes to reduce allocations
    let mut haystack_buf = Vec::new();

    let mut results: Vec<_> = themes
        .filter_map(|theme| {
            let theme_name_lowercase = theme.name().to_lowercase();
            haystack_buf.clear(); // Reuse instead of reallocate
            let haystack = Utf32Str::new(&theme_name_lowercase, &mut haystack_buf);
            matcher
                .fuzzy_match(haystack, needle)
                .map(|score| (theme, score))
        })
        .collect();

    // Sort by score descending (highest relevance first)
    results.sort_unstable_by(|a, b| b.1.cmp(&a.1));
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use strum::IntoEnumIterator;
    use crate::fonts::FontChoice;
    use crate::theme::ThemeChoice;

    #[test]
    fn test_fuzzy_filter_fonts_empty_query() {
        let fonts = vec![
            FontChoice::SystemDefault,
            FontChoice::SystemMonospace,
        ];
        let results = fuzzy_filter_fonts(fonts.iter(), "");
        assert_eq!(results.len(), 2);
        // All scores should be 0 for empty query
        assert!(results.iter().all(|(_, score)| *score == 0));
    }

    #[test]
    fn test_fuzzy_filter_fonts_match() {
        let fonts = vec![
            FontChoice::SystemDefault,
            FontChoice::SystemMonospace,
        ];
        let results = fuzzy_filter_fonts(fonts.iter(), "mono");
        // Should find SystemMonospace
        assert_eq!(results.len(), 1);
        // Score should be non-zero
        assert!(results[0].1 > 0);
        assert_eq!(results[0].0, &FontChoice::SystemMonospace);
    }

    #[test]
    fn test_fuzzy_filter_themes_empty_query() {
        let themes = ThemeChoice::iter();
        let results = fuzzy_filter_themes(themes, "");
        assert!(!results.is_empty());
        // All scores should be 0 for empty query
        assert!(results.iter().all(|(_, score)| *score == 0));
    }
}
