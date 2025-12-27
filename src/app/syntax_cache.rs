//! Syntax highlighting token cache for performance optimization (Phase 1)
//!
//! Pre-tokenizes syntax highlighting to avoid expensive per-frame parsing.

use iced::Color;
use std::borrow::Cow;

/// A highlighted token with its color
/// Uses Cow to avoid heap allocations for common static tokens like "{", "}", ":", etc.
#[derive(Debug, Clone)]
pub struct Token {
    pub text: Cow<'static, str>,
    pub color: TokenColor,
}

/// Token color category (resolved to actual color in view based on theme)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenColor {
    Primary,       // Default text
    Keyword,       // Keywords
    Type,          // Types, JSON keys
    String,        // String literals
    Number,        // Numbers
    Comment,       // Comments
    Bracket,       // Brackets (theme.info)
    LineNumber,    // Line numbers (gray) for JSON
    LineNumberNft, // Line numbers (darker gray) for NFT
}

/// Diff line type (for background coloring in diff view)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffType {
    Added,     // Green background
    Removed,   // Red background
    Unchanged, // No background
}

/// A line of highlighted code with pre-parsed tokens
#[derive(Debug, Clone)]
pub struct HighlightedLine {
    pub line_number: usize,
    pub indent: usize,
    pub tokens: Vec<Token>,
}

/// Cached syntax highlighting for JSON
pub fn tokenize_json(content: &str) -> Vec<HighlightedLine> {
    content
        .lines()
        .enumerate()
        .map(|(i, line)| {
            let trimmed = line.trim_start();
            let indent = line.len().saturating_sub(trimmed.len()).min(32);
            let tokens = parse_json_line(trimmed);

            HighlightedLine {
                line_number: i + 1,
                indent,
                tokens,
            }
        })
        .collect()
}

fn parse_json_line(line: &str) -> Vec<Token> {
    let mut tokens = Vec::with_capacity(20); // Pre-allocate (avg ~15 tokens/line, avoids reallocations)
    let mut chars = line.chars().peekable();
    let mut current_token = String::new();

    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                // Flush current token
                if !current_token.is_empty() {
                    tokens.push(Token {
                        text: Cow::Owned(std::mem::take(&mut current_token)),
                        color: TokenColor::Primary,
                    });
                }

                // Read the full string
                let mut string_content = String::from('"');
                while let Some(&next_ch) = chars.peek() {
                    chars.next();
                    string_content.push(next_ch);
                    if next_ch == '"' && !string_content.ends_with("\\\"") {
                        break;
                    }
                }

                // Check if this is a key (followed by colon)
                let mut temp_chars = chars.clone();
                let mut is_key = false;
                while let Some(&next_ch) = temp_chars.peek() {
                    if next_ch.is_whitespace() {
                        temp_chars.next();
                    } else {
                        is_key = next_ch == ':';
                        break;
                    }
                }

                tokens.push(Token {
                    text: Cow::Owned(string_content),
                    color: if is_key {
                        TokenColor::Type
                    } else {
                        TokenColor::String
                    },
                });
            }
            ':' => {
                if !current_token.is_empty() {
                    tokens.push(Token {
                        text: Cow::Owned(std::mem::take(&mut current_token)),
                        color: TokenColor::Primary,
                    });
                }
                tokens.push(Token {
                    text: Cow::Borrowed(":"), // Static string, zero heap allocation!
                    color: TokenColor::Primary,
                });
            }
            ',' => {
                if !current_token.is_empty() {
                    tokens.push(Token {
                        text: Cow::Owned(std::mem::take(&mut current_token)),
                        color: TokenColor::Primary,
                    });
                }
                tokens.push(Token {
                    text: Cow::Borrowed(","), // Static string, zero heap allocation!
                    color: TokenColor::Primary,
                });
            }
            '{' => {
                if !current_token.is_empty() {
                    tokens.push(Token {
                        text: Cow::Owned(std::mem::take(&mut current_token)),
                        color: TokenColor::Primary,
                    });
                }
                tokens.push(Token {
                    text: Cow::Borrowed("{"), // Static string, zero heap allocation!
                    color: TokenColor::Bracket,
                });
            }
            '}' => {
                if !current_token.is_empty() {
                    tokens.push(Token {
                        text: Cow::Owned(std::mem::take(&mut current_token)),
                        color: TokenColor::Primary,
                    });
                }
                tokens.push(Token {
                    text: Cow::Borrowed("}"), // Static string, zero heap allocation!
                    color: TokenColor::Bracket,
                });
            }
            '[' => {
                if !current_token.is_empty() {
                    tokens.push(Token {
                        text: Cow::Owned(std::mem::take(&mut current_token)),
                        color: TokenColor::Primary,
                    });
                }
                tokens.push(Token {
                    text: Cow::Borrowed("["), // Static string, zero heap allocation!
                    color: TokenColor::Bracket,
                });
            }
            ']' => {
                if !current_token.is_empty() {
                    tokens.push(Token {
                        text: Cow::Owned(std::mem::take(&mut current_token)),
                        color: TokenColor::Primary,
                    });
                }
                tokens.push(Token {
                    text: Cow::Borrowed("]"), // Static string, zero heap allocation!
                    color: TokenColor::Bracket,
                });
            }
            _ if ch.is_whitespace() => {
                if !current_token.is_empty() {
                    let text = std::mem::take(&mut current_token);
                    let color = classify_token(&text);
                    tokens.push(Token {
                        text: Cow::Owned(text),
                        color,
                    });
                }
                // Preserve single space (most common whitespace)
                tokens.push(Token {
                    text: if ch == ' ' {
                        Cow::Borrowed(" ") // Static string for space, zero allocation!
                    } else {
                        Cow::Owned(ch.to_string()) // Rare whitespace chars (tab, etc.)
                    },
                    color: TokenColor::Primary,
                });
            }
            _ => {
                current_token.push(ch);
            }
        }
    }

    // Flush remaining token
    if !current_token.is_empty() {
        let color = classify_token(&current_token);
        tokens.push(Token {
            text: Cow::Owned(current_token),
            color,
        });
    }

    tokens
}

fn classify_token(token: &str) -> TokenColor {
    // Check if it's a number
    if token.chars().all(|c| c.is_ascii_digit() || c == '.') {
        TokenColor::Number
    } else if matches!(token, "true" | "false" | "null") {
        TokenColor::Keyword
    } else {
        TokenColor::Primary
    }
}

/// Cached syntax highlighting for nftables
pub fn tokenize_nft(content: &str) -> Vec<HighlightedLine> {
    content
        .lines()
        .enumerate()
        .map(|(i, line)| {
            let trimmed = line.trim_start();
            let indent = line.len().saturating_sub(trimmed.len()).min(32);
            let tokens = parse_nft_line(trimmed);

            HighlightedLine {
                line_number: i + 1,
                indent,
                tokens,
            }
        })
        .collect()
}

fn parse_nft_line(line: &str) -> Vec<Token> {
    let mut tokens = Vec::new();

    // Check for comment
    if let Some(comment_start) = line.find('#') {
        let before_comment = &line[..comment_start];
        let comment_text = &line[comment_start..];

        // Parse non-comment part
        if !before_comment.is_empty() {
            tokens.extend(parse_nft_tokens(before_comment));
        }

        // Add comment
        tokens.push(Token {
            text: Cow::Owned(comment_text.to_string()),
            color: TokenColor::Comment,
        });
    } else {
        tokens = parse_nft_tokens(line);
    }

    tokens
}

fn parse_nft_tokens(line: &str) -> Vec<Token> {
    let keywords = [
        "table",
        "chain",
        "rule",
        "add",
        "delete",
        "flush",
        "list",
        "inet",
        "ip",
        "ip6",
        "filter",
        "nat",
        "route",
        "input",
        "forward",
        "output",
        "prerouting",
        "postrouting",
        "accept",
        "drop",
        "reject",
        "queue",
        "continue",
        "return",
        "jump",
        "goto",
        "ct",
        "state",
        "established",
        "related",
        "invalid",
        "new",
        "comment",
        "iifname",
        "oifname",
        "meta",
        "l4proto",
        "tcp",
        "udp",
        "icmp",
        "dport",
        "sport",
        "saddr",
        "daddr",
        "type",
        "hook",
        "priority",
        "policy",
    ];

    let mut tokens = Vec::with_capacity(15); // Pre-allocate (avg ~12 tokens/line)
    let mut current_token = String::new();
    let mut in_string = false;
    let chars = line.chars();

    for ch in chars {
        match ch {
            '"' => {
                if !in_string && !current_token.is_empty() {
                    let text = std::mem::take(&mut current_token);
                    let color = if keywords.contains(&text.as_str()) {
                        TokenColor::Keyword
                    } else {
                        TokenColor::Primary
                    };
                    tokens.push(Token {
                        text: Cow::Owned(text),
                        color,
                    });
                }

                current_token.push('"');
                in_string = !in_string;

                if !in_string {
                    tokens.push(Token {
                        text: Cow::Owned(std::mem::take(&mut current_token)),
                        color: TokenColor::String,
                    });
                }
            }
            _ if in_string => {
                current_token.push(ch);
            }
            '{' => {
                if !current_token.is_empty() {
                    let text = std::mem::take(&mut current_token);
                    let color = if keywords.contains(&text.as_str()) {
                        TokenColor::Keyword
                    } else {
                        TokenColor::Primary
                    };
                    tokens.push(Token {
                        text: Cow::Owned(text),
                        color,
                    });
                }
                tokens.push(Token {
                    text: Cow::Borrowed("{"), // Static string, zero allocation!
                    color: TokenColor::Bracket,
                });
            }
            '}' => {
                if !current_token.is_empty() {
                    let text = std::mem::take(&mut current_token);
                    let color = if keywords.contains(&text.as_str()) {
                        TokenColor::Keyword
                    } else {
                        TokenColor::Primary
                    };
                    tokens.push(Token {
                        text: Cow::Owned(text),
                        color,
                    });
                }
                tokens.push(Token {
                    text: Cow::Borrowed("}"), // Static string, zero allocation!
                    color: TokenColor::Bracket,
                });
            }
            ';' => {
                if !current_token.is_empty() {
                    let text = std::mem::take(&mut current_token);
                    let color = if keywords.contains(&text.as_str()) {
                        TokenColor::Keyword
                    } else {
                        TokenColor::Primary
                    };
                    tokens.push(Token {
                        text: Cow::Owned(text),
                        color,
                    });
                }
                tokens.push(Token {
                    text: Cow::Borrowed(";"), // Static string, zero allocation!
                    color: TokenColor::Bracket,
                });
            }
            _ if ch.is_whitespace() => {
                if !current_token.is_empty() {
                    let text = std::mem::take(&mut current_token);
                    let color = if keywords.contains(&text.as_str()) {
                        TokenColor::Keyword
                    } else if text.chars().all(|c| c.is_ascii_digit()) {
                        TokenColor::Number
                    } else {
                        TokenColor::Primary
                    };
                    tokens.push(Token {
                        text: Cow::Owned(text),
                        color,
                    });
                }
                tokens.push(Token {
                    text: if ch == ' ' {
                        Cow::Borrowed(" ") // Static string for space, zero allocation!
                    } else {
                        Cow::Owned(ch.to_string()) // Rare whitespace (tab, etc.)
                    },
                    color: TokenColor::Primary,
                });
            }
            _ => {
                current_token.push(ch);
            }
        }
    }

    // Flush remaining token
    if !current_token.is_empty() {
        let color = if keywords.contains(&current_token.as_str()) {
            TokenColor::Keyword
        } else if current_token.chars().all(|c| c.is_ascii_digit()) {
            TokenColor::Number
        } else {
            TokenColor::Primary
        };
        tokens.push(Token {
            text: Cow::Owned(current_token),
            color,
        });
    }

    tokens
}

/// Computes diff and tokenizes in one pass (Phase 1 optimization)
/// Returns None if no diff or no changes detected
pub fn compute_and_tokenize_diff(
    old_text: &str,
    new_text: &str,
) -> Option<Vec<(DiffType, HighlightedLine)>> {
    use similar::ChangeTag;

    let diff = similar::TextDiff::from_lines(old_text, new_text);
    let mut result = Vec::new();
    let mut line_number = 0;

    for change in diff.iter_all_changes() {
        line_number += 1;

        let diff_type = match change.tag() {
            ChangeTag::Delete => DiffType::Removed,
            ChangeTag::Insert => DiffType::Added,
            ChangeTag::Equal => DiffType::Unchanged,
        };

        // Get the line text without the trailing newline
        let line_text = change.as_str().unwrap_or("").trim_end_matches('\n');

        // Tokenize the line
        let parsed = tokenize_nft(if line_text.is_empty() {
            "\n"
        } else {
            line_text
        });

        if let Some(mut highlighted_line) = parsed.into_iter().next() {
            // Update line number to match diff line number
            highlighted_line.line_number = line_number;
            result.push((diff_type, highlighted_line));
        }
    }

    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

impl TokenColor {
    /// Resolves token color to actual Color based on theme
    pub fn to_color(self, theme: &crate::theme::AppTheme) -> Color {
        match self {
            TokenColor::Primary => theme.fg_primary,
            TokenColor::Keyword => theme.syntax_keyword,
            TokenColor::Type => theme.syntax_type,
            TokenColor::String => theme.syntax_string,
            TokenColor::Number => theme.syntax_number,
            TokenColor::Comment => theme.syntax_comment,
            TokenColor::Bracket => theme.info, // Brackets use info color (matches old code)
            TokenColor::LineNumber => Color::from_rgb(0.4, 0.4, 0.4),
            TokenColor::LineNumberNft => Color::from_rgb(0.25, 0.25, 0.25), // Darker gray for NFT
        }
    }
}
