//! Syntax-highlighted code view rendering
//!
//! Functions for rendering pre-tokenized code with syntax highlighting:
//! - nftables.conf (diff and normal views)
//! - JSON output
//!
//! All highlighting is pre-computed in State to avoid rendering loop overhead.

use crate::app::Message;
use iced::widget::{container, keyed_column, row, space, text};
use iced::{Color, Length};

pub fn view_from_cached_diff_tokens<'a>(
    diff_tokens: &'a [(
        crate::app::syntax_cache::DiffType,
        crate::app::syntax_cache::HighlightedLine,
    )],
    theme: &crate::theme::AppTheme,
    mono_font: iced::Font,
    show_zebra_striping: bool,
    content_width_px: f32,
) -> iced::widget::keyed::Column<'a, usize, Message> {
    const SPACES: &str = "                                ";

    // Use pre-computed zebra stripe color from theme (computed once, not every frame)
    let even_stripe = theme.zebra_stripe;

    // Issue #20: Pre-allocate with exact line count
    let mut lines = keyed_column(Vec::with_capacity(diff_tokens.len())).spacing(1);

    for (diff_type, highlighted_line) in diff_tokens {
        let line_number = highlighted_line.line_number;
        let mut row_content = row![].spacing(0);

        // Line number (same format as normal view - no extra diff indicator, pre-formatted to avoid allocation)
        row_content = row_content.push(
            container(
                text(&highlighted_line.formatted_line_number_nft)
                    .font(mono_font)
                    .size(14)
                    .color(crate::app::syntax_cache::TokenColor::LineNumberNft.to_color(theme)),
            )
            .width(Length::Fixed(50.0))
            .padding(iced::Padding::new(0.0).right(8.0)),
        );

        // Indentation
        if highlighted_line.indent > 0 {
            let spaces = &SPACES[..highlighted_line.indent];
            row_content = row_content.push(text(spaces).font(mono_font).size(14));
        }

        // Tokens (already parsed - just build widgets!)
        for token in &highlighted_line.tokens {
            let color = token.color.to_color(theme);
            let font = iced::Font {
                weight: if token.bold {
                    iced::font::Weight::Bold
                } else {
                    iced::font::Weight::Normal
                },
                style: if token.italic {
                    iced::font::Style::Italic
                } else {
                    iced::font::Style::Normal
                },
                ..mono_font
            };
            row_content = row_content.push(text(&token.text).font(font).size(14).color(color));
        }

        // Background colors: diff colors for added/removed, zebra stripes for unchanged
        let bg_color = match diff_type {
            crate::app::syntax_cache::DiffType::Added => Some(Color {
                a: 0.1,
                ..theme.success
            }),
            crate::app::syntax_cache::DiffType::Removed => Some(Color {
                a: 0.1,
                ..theme.danger
            }),
            crate::app::syntax_cache::DiffType::Unchanged => {
                // Apply zebra striping to unchanged lines (if enabled)
                if show_zebra_striping {
                    let is_even = line_number % 2 == 0;
                    if is_even { Some(even_stripe) } else { None }
                } else {
                    None
                }
            }
        };

        lines = lines.push(
            line_number,
            container(row_content)
                .width(Length::Fixed(content_width_px))
                .style(move |_| container::Style {
                    background: bg_color.map(Into::into),
                    ..Default::default()
                }),
        );
    }

    // Add a spacer at the end to fill remaining vertical space with zebra background
    // Continue the zebra pattern: if last line_number is odd, next would be even
    let last_line_number = diff_tokens.last().map_or(0, |(_, hl)| hl.line_number);
    let spacer_bg = if show_zebra_striping {
        let is_even = (last_line_number + 1).is_multiple_of(2);
        if is_even { Some(even_stripe) } else { None }
    } else {
        None
    };

    lines = lines.push(
        usize::MAX,
        container(space().height(Length::Fill))
            .width(Length::Fixed(content_width_px))
            .style(move |_| container::Style {
                background: spacer_bg.map(Into::into),
                ..Default::default()
            }),
    );

    lines
}


/// Phase 1 Optimization: Build widgets from pre-tokenized NFT (cached in State)
/// Uses `keyed_column` for efficient widget reconciliation during resize
pub fn view_from_cached_nft_tokens<'a>(
    tokens: &'a [crate::app::syntax_cache::HighlightedLine],
    theme: &crate::theme::AppTheme,
    mono_font: iced::Font,
    show_zebra_striping: bool,
    content_width_px: f32,
) -> iced::widget::keyed::Column<'a, usize, Message> {
    const SPACES: &str = "                                ";

    // Use pre-computed zebra stripe color from theme (computed once, not every frame)
    let even_stripe = theme.zebra_stripe;

    // Issue #20: Pre-allocate with exact line count
    let mut lines = keyed_column(Vec::with_capacity(tokens.len())).spacing(1); // NFT uses tighter spacing than JSON

    for highlighted_line in tokens {
        let line_number = highlighted_line.line_number;
        let mut row_content = row![].spacing(0);

        // Line number (NFT uses darker gray and different format, pre-formatted to avoid allocation)
        row_content = row_content.push(
            container(
                text(&highlighted_line.formatted_line_number_nft)
                    .font(mono_font)
                    .size(14)
                    .color(crate::app::syntax_cache::TokenColor::LineNumberNft.to_color(theme)),
            )
            .width(iced::Length::Fixed(50.0))
            .padding(iced::Padding::new(0.0).right(8.0)),
        );

        // Indentation (NFT only uses actual indentation, no extra spacing)
        if highlighted_line.indent > 0 && !highlighted_line.tokens.is_empty() {
            let spaces = &SPACES[..highlighted_line.indent];
            row_content = row_content.push(text(spaces).font(mono_font).size(14));
        }

        // Tokens (already parsed!)
        for token in &highlighted_line.tokens {
            let font = iced::Font {
                weight: if token.bold {
                    iced::font::Weight::Bold
                } else {
                    iced::font::Weight::Normal
                },
                style: if token.italic {
                    iced::font::Style::Italic
                } else {
                    iced::font::Style::Normal
                },
                ..mono_font
            };
            row_content = row_content.push(
                text(&token.text)
                    .font(font)
                    .size(14)
                    .color(token.color.to_color(theme)),
            );
        }

        // Apply subtle zebra striping: even rows get background, odd rows transparent (if enabled)
        let bg = if show_zebra_striping {
            let is_even = line_number % 2 == 0;
            if is_even { Some(even_stripe) } else { None }
        } else {
            None
        };

        lines = lines.push(
            line_number,
            container(row_content)
                .width(Length::Fixed(content_width_px))
                .style(move |_| container::Style {
                    background: bg.map(Into::into),
                    ..Default::default()
                }),
        );
    }

    // Add a spacer at the end to fill remaining vertical space with zebra background
    // Continue the zebra pattern: if last line_number is odd, next would be even
    let last_line_number = tokens.last().map_or(0, |hl| hl.line_number);
    let spacer_bg = if show_zebra_striping {
        let is_even = (last_line_number + 1).is_multiple_of(2);
        if is_even { Some(even_stripe) } else { None }
    } else {
        None
    };

    lines = lines.push(
        usize::MAX,
        container(space().height(Length::Fill))
            .width(Length::Fixed(content_width_px))
            .style(move |_| container::Style {
                background: spacer_bg.map(Into::into),
                ..Default::default()
            }),
    );

    lines
}
