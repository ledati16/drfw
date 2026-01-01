//! Syntax highlighting token cache for performance optimization
//!
//! Pre-tokenizes syntax highlighting to avoid expensive per-frame parsing.
//! Uses logos for declarative, DFA-based lexing (2-5× faster than manual parsing).

use iced::Color;
use logos::Logos;
use std::borrow::Cow;

/// Average number of syntax tokens per line in JSON output (pre-allocation optimization)
const AVG_JSON_TOKENS_PER_LINE: usize = 20;
/// Average number of syntax tokens per line in nftables text output (pre-allocation optimization)
const AVG_NFT_TOKENS_PER_LINE: usize = 15;

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

/// JSON lexer tokens (declarative DFA-based lexing via logos)
#[derive(Logos, Debug, Clone, Copy, PartialEq)]
enum JsonToken {
    #[token("{")]
    LBrace,
    #[token("}")]
    RBrace,
    #[token("[")]
    LBracket,
    #[token("]")]
    RBracket,
    #[token(":")]
    Colon,
    #[token(",")]
    Comma,

    #[regex(r#""([^"\\]|\\.)*""#)]
    String,

    #[regex(r"-?\d+(\.\d+)?([eE][+-]?\d+)?")]
    Number,

    #[token("true")]
    True,
    #[token("false")]
    False,
    #[token("null")]
    Null,

    // Whitespace (must be preserved for display)
    #[regex(r"[ \t]+")]
    Whitespace,
}

/// Nftables lexer tokens (declarative DFA-based lexing via logos)
#[derive(Logos, Debug, Clone, Copy, PartialEq)]
enum NftToken {
    // Keywords (grouped logically for readability)
    #[token("table")]
    Table,
    #[token("chain")]
    Chain,
    #[token("rule")]
    Rule,
    #[token("add")]
    Add,
    #[token("delete")]
    Delete,
    #[token("flush")]
    Flush,
    #[token("list")]
    List,

    #[token("inet")]
    Inet,
    #[token("ip")]
    Ip,
    #[token("ip6")]
    Ip6,

    #[token("filter")]
    Filter,
    #[token("nat")]
    Nat,
    #[token("route")]
    Route,

    #[token("input")]
    Input,
    #[token("forward")]
    Forward,
    #[token("output")]
    Output,
    #[token("prerouting")]
    Prerouting,
    #[token("postrouting")]
    Postrouting,

    #[token("accept")]
    Accept,
    #[token("drop")]
    Drop,
    #[token("reject")]
    Reject,
    #[token("queue")]
    Queue,
    #[token("continue")]
    Continue,
    #[token("return")]
    Return,
    #[token("jump")]
    Jump,
    #[token("goto")]
    Goto,

    #[token("ct")]
    Ct,
    #[token("state")]
    State,
    #[token("established")]
    Established,
    #[token("related")]
    Related,
    #[token("invalid")]
    Invalid,
    #[token("new")]
    New,

    #[token("comment")]
    Comment,
    #[token("iifname")]
    Iifname,
    #[token("oifname")]
    Oifname,
    #[token("meta")]
    Meta,
    #[token("l4proto")]
    L4proto,

    #[token("tcp")]
    Tcp,
    #[token("udp")]
    Udp,
    #[token("icmp")]
    Icmp,

    #[token("dport")]
    Dport,
    #[token("sport")]
    Sport,
    #[token("saddr")]
    Saddr,
    #[token("daddr")]
    Daddr,

    #[token("type")]
    Type,
    #[token("hook")]
    Hook,
    #[token("priority")]
    Priority,
    #[token("policy")]
    Policy,

    // Strings and numbers
    #[regex(r#""([^"\\]|\\.)*""#)]
    String,

    #[regex(r"\d+")]
    Number,

    // Comments
    #[regex(r"#[^\n]*")]
    CommentText,

    // Structural tokens
    #[token("{")]
    LBrace,
    #[token("}")]
    RBrace,
    #[token(";")]
    Semicolon,

    // Identifiers (interface names, etc.)
    #[regex(r"[a-zA-Z_][a-zA-Z0-9_\-\.]*")]
    Identifier,

    // Whitespace (must be preserved for display)
    #[regex(r"[ \t]+")]
    Whitespace,
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
    /// Pre-formatted line number for JSON view ("{:3} " format) - computed once, not every frame
    pub formatted_line_number_json: String,
    /// Pre-formatted line number for NFT view ("{:4}" format) - computed once, not every frame
    pub formatted_line_number_nft: String,
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
            let line_number = i + 1;

            HighlightedLine {
                line_number,
                indent,
                tokens,
                formatted_line_number_json: format!("{line_number:3} "),
                formatted_line_number_nft: format!("{line_number:4}"),
            }
        })
        .collect()
}

fn parse_json_line(line: &str) -> Vec<Token> {
    let mut tokens = Vec::with_capacity(AVG_JSON_TOKENS_PER_LINE);
    let mut lex = JsonToken::lexer(line);

    while let Some(token_result) = lex.next() {
        let Ok(token) = token_result else {
            // Skip invalid tokens
            continue;
        };

        let span = lex.span();
        let span_end = span.end; // Store end before span is moved
        let text = &line[span];

        match token {
            JsonToken::String => {
                // Look ahead to see if next non-whitespace token is a colon
                let remainder = &line[span_end..];
                let is_key = remainder.trim_start().starts_with(':');

                tokens.push(Token {
                    text: Cow::Owned(text.to_string()),
                    color: if is_key {
                        TokenColor::Type // JSON key
                    } else {
                        TokenColor::String // JSON value
                    },
                });
            }
            JsonToken::Number => {
                tokens.push(Token {
                    text: Cow::Owned(text.to_string()),
                    color: TokenColor::Number,
                });
            }
            JsonToken::True => {
                tokens.push(Token {
                    text: Cow::Borrowed("true"),
                    color: TokenColor::Keyword,
                });
            }
            JsonToken::False => {
                tokens.push(Token {
                    text: Cow::Borrowed("false"),
                    color: TokenColor::Keyword,
                });
            }
            JsonToken::Null => {
                tokens.push(Token {
                    text: Cow::Borrowed("null"),
                    color: TokenColor::Keyword,
                });
            }
            JsonToken::LBrace => {
                tokens.push(Token {
                    text: Cow::Borrowed("{"),
                    color: TokenColor::Bracket,
                });
            }
            JsonToken::RBrace => {
                tokens.push(Token {
                    text: Cow::Borrowed("}"),
                    color: TokenColor::Bracket,
                });
            }
            JsonToken::LBracket => {
                tokens.push(Token {
                    text: Cow::Borrowed("["),
                    color: TokenColor::Bracket,
                });
            }
            JsonToken::RBracket => {
                tokens.push(Token {
                    text: Cow::Borrowed("]"),
                    color: TokenColor::Bracket,
                });
            }
            JsonToken::Colon => {
                tokens.push(Token {
                    text: Cow::Borrowed(":"),
                    color: TokenColor::Primary,
                });
            }
            JsonToken::Comma => {
                tokens.push(Token {
                    text: Cow::Borrowed(","),
                    color: TokenColor::Primary,
                });
            }
            JsonToken::Whitespace => {
                tokens.push(Token {
                    text: Cow::Owned(text.to_string()),
                    color: TokenColor::Primary,
                });
            }
        }
    }

    tokens
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
            let line_number = i + 1;

            HighlightedLine {
                line_number,
                indent,
                tokens,
                formatted_line_number_json: format!("{line_number:3} "),
                formatted_line_number_nft: format!("{line_number:4}"),
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
    let mut tokens = Vec::with_capacity(AVG_NFT_TOKENS_PER_LINE);
    let mut lex = NftToken::lexer(line);

    while let Some(token_result) = lex.next() {
        let Ok(token) = token_result else {
            // Skip invalid tokens
            continue;
        };

        let span = lex.span();
        let text = &line[span];

        use NftToken::*;
        match token {
            // Keywords - use owned strings since text is a slice
            Table | Chain | Rule | Add | Delete | Flush | List | Inet | Ip | Ip6 | Filter | Nat
            | Route | Input | Forward | Output | Prerouting | Postrouting | Accept | Drop
            | Reject | Queue | Continue | Return | Jump | Goto | Ct | State | Established
            | Related | Invalid | New | Comment | Iifname | Oifname | Meta | L4proto | Tcp
            | Udp | Icmp | Dport | Sport | Saddr | Daddr | Type | Hook | Priority | Policy => {
                tokens.push(Token {
                    text: Cow::Owned(text.to_string()),
                    color: TokenColor::Keyword,
                });
            }
            String => {
                tokens.push(Token {
                    text: Cow::Owned(text.to_string()),
                    color: TokenColor::String,
                });
            }
            Number => {
                tokens.push(Token {
                    text: Cow::Owned(text.to_string()),
                    color: TokenColor::Number,
                });
            }
            CommentText => {
                tokens.push(Token {
                    text: Cow::Owned(text.to_string()),
                    color: TokenColor::Comment,
                });
            }
            LBrace => {
                tokens.push(Token {
                    text: Cow::Borrowed("{"),
                    color: TokenColor::Primary,
                });
            }
            RBrace => {
                tokens.push(Token {
                    text: Cow::Borrowed("}"),
                    color: TokenColor::Primary,
                });
            }
            Semicolon => {
                tokens.push(Token {
                    text: Cow::Borrowed(";"),
                    color: TokenColor::Primary,
                });
            }
            Identifier => {
                tokens.push(Token {
                    text: Cow::Owned(text.to_string()),
                    color: TokenColor::Primary,
                });
            }
            Whitespace => {
                tokens.push(Token {
                    text: Cow::Owned(text.to_string()),
                    color: TokenColor::Primary,
                });
            }
        }
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
    // Issue #18: Pre-allocate Vec with estimated capacity (max of old/new line count)
    let line_count = old_text.lines().count().max(new_text.lines().count());
    let mut result = Vec::with_capacity(line_count);
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
            // Re-compute formatted line numbers since we changed line_number
            highlighted_line.formatted_line_number_json = format!("{line_number:3} ");
            highlighted_line.formatted_line_number_nft = format!("{line_number:4}");
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
            TokenColor::LineNumber | TokenColor::LineNumberNft => theme.fg_muted, // Use theme's muted color for line numbers
        }
    }
}
