//! Syntax highlighting token cache for performance optimization
//!
//! Pre-tokenizes syntax highlighting to avoid expensive per-frame parsing.
//! Uses logos for declarative, DFA-based lexing (2-5× faster than manual parsing).

use iced::Color;
use logos::Logos;
use std::borrow::Cow;

/// Average number of syntax tokens per line in nftables text output (pre-allocation optimization)
const AVG_NFT_TOKENS_PER_LINE: usize = 15;

/// A highlighted token with its color and optional styling
/// Uses Cow to avoid heap allocations for common static tokens like "{", "}", ":", etc.
#[derive(Debug, Clone)]
pub struct Token {
    pub text: Cow<'static, str>,
    pub color: TokenColor,
    pub bold: bool,
    pub italic: bool,
}

/// Token color category (resolved to actual color in view based on theme)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenColor {
    Primary,       // Default text
    Keyword,       // Keywords
    String,        // String literals
    Number,        // Numbers
    Comment,       // Comments
    LineNumberNft, // Line numbers for NFT
    ActionAccept,  // Accept action (green, rendered bold)
    ActionDeny,    // Drop/Reject actions (red, rendered bold)
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

    // Additional keywords for advanced rules
    #[token("fib")]
    Fib,
    #[token("iif")]
    Iif,
    #[token("oif")]
    Oif,
    #[token("eq")]
    Eq,
    #[token("protocol")]
    Protocol,
    #[token("redirect")]
    Redirect,
    #[token("ipv6-icmp")]
    Ipv6Icmp,
    #[token("icmpv6")]
    Icmpv6,
    #[token("limit")]
    Limit,
    #[token("rate")]
    Rate,
    #[token("second")]
    Second,
    #[token("minute")]
    Minute,
    #[token("hour")]
    Hour,
    #[token("day")]
    Day,
    #[token("week")]
    Week,
    #[token("log")]
    Log,
    #[token("prefix")]
    Prefix,
    #[token("level")]
    Level,
    #[token("info")]
    Info,
    #[token("warn")]
    Warn,
    #[token("debug")]
    Debug,
    #[token("pkttype")]
    Pkttype,
    #[token("host")]
    Host,
    #[token("counter")]
    Counter,
    #[token("with")]
    With,
    #[token("icmpx")]
    Icmpx,
    #[token("th")]
    Th,
    #[token("count")]
    Count,

    // Strings and numbers
    #[regex(r#""([^"\\]|\\.)*""#)]
    String,

    // IP addresses with optional CIDR (must come before Number to match first)
    #[regex(r"\d+\.\d+\.\d+\.\d+(\/\d+)?")]
    IpAddress,

    // IPv6 addresses (basic pattern - hex digits with colons)
    #[regex(r"[0-9a-fA-F:]+:[0-9a-fA-F:]+(\/\d+)?")]
    Ipv6Address,

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
    #[token("/")]
    Slash,
    #[token("-")]
    Dash,
    #[token(":")]
    Colon,
    #[token(",")]
    Comma,
    #[token(".")]
    Period,
    #[token("<=")]
    LessEqual,
    #[token("<")]
    Less,
    #[token(">=")]
    GreaterEqual,
    #[token(">")]
    Greater,
    #[token("=")]
    Equal,

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
            bold: false,
            italic: true,
        });
    } else {
        tokens = parse_nft_tokens(line);
    }

    tokens
}

fn parse_nft_tokens(line: &str) -> Vec<Token> {
    #[allow(clippy::enum_glob_use)] // Clear within this match-heavy function
    use NftToken::*;

    let mut tokens = Vec::with_capacity(AVG_NFT_TOKENS_PER_LINE);
    let mut lex = NftToken::lexer(line);

    while let Some(token_result) = lex.next() {
        let Ok(token) = token_result else {
            // Skip invalid tokens
            continue;
        };

        let span = lex.span();
        let text = &line[span];
        match token {
            // Actions - semantic colors + bold for maximum visibility
            Accept => {
                tokens.push(Token {
                    text: Cow::Owned(text.to_string()),
                    color: TokenColor::ActionAccept,
                    bold: true,
                    italic: false,
                });
            }
            Drop | Reject => {
                tokens.push(Token {
                    text: Cow::Owned(text.to_string()),
                    color: TokenColor::ActionDeny,
                    bold: true,
                    italic: false,
                });
            }
            // Keywords - use owned strings since text is a slice
            Table | Chain | Rule | Add | Delete | Flush | List | Inet | Ip | Ip6 | Filter | Nat
            | Route | Input | Forward | Output | Prerouting | Postrouting | Queue | Continue
            | Return | Jump | Goto | Ct | State | Established | Related | Invalid | New
            | Comment | Iifname | Oifname | Meta | L4proto | Tcp | Udp | Icmp | Dport | Sport
            | Saddr | Daddr | Type | Hook | Priority | Policy | Fib | Iif | Oif | Eq | Protocol
            | Redirect | Ipv6Icmp | Icmpv6 | Limit | Rate | Second | Minute | Hour | Day | Week
            | Log | Prefix | Level | Info | Warn | Debug | Pkttype | Host | Counter | With
            | Icmpx | Th | Count => {
                tokens.push(Token {
                    text: Cow::Owned(text.to_string()),
                    color: TokenColor::Keyword,
                    bold: false,
                    italic: false,
                });
            }
            String => {
                tokens.push(Token {
                    text: Cow::Owned(text.to_string()),
                    color: TokenColor::String,
                    bold: false,
                    italic: false,
                });
            }
            IpAddress | Ipv6Address | Number => {
                tokens.push(Token {
                    text: Cow::Owned(text.to_string()),
                    color: TokenColor::Number,
                    bold: false,
                    italic: false,
                });
            }
            CommentText => {
                tokens.push(Token {
                    text: Cow::Owned(text.to_string()),
                    color: TokenColor::Comment,
                    bold: false,
                    italic: true,
                });
            }
            LBrace => {
                tokens.push(Token {
                    text: Cow::Borrowed("{"),
                    color: TokenColor::Primary,
                    bold: false,
                    italic: false,
                });
            }
            RBrace => {
                tokens.push(Token {
                    text: Cow::Borrowed("}"),
                    color: TokenColor::Primary,
                    bold: false,
                    italic: false,
                });
            }
            Semicolon => {
                tokens.push(Token {
                    text: Cow::Borrowed(";"),
                    color: TokenColor::Primary,
                    bold: false,
                    italic: false,
                });
            }
            Slash => {
                tokens.push(Token {
                    text: Cow::Borrowed("/"),
                    color: TokenColor::Primary,
                    bold: false,
                    italic: false,
                });
            }
            Dash => {
                tokens.push(Token {
                    text: Cow::Borrowed("-"),
                    color: TokenColor::Primary,
                    bold: false,
                    italic: false,
                });
            }
            Colon => {
                tokens.push(Token {
                    text: Cow::Borrowed(":"),
                    color: TokenColor::Primary,
                    bold: false,
                    italic: false,
                });
            }
            Comma => {
                tokens.push(Token {
                    text: Cow::Borrowed(","),
                    color: TokenColor::Primary,
                    bold: false,
                    italic: false,
                });
            }
            Period => {
                tokens.push(Token {
                    text: Cow::Borrowed("."),
                    color: TokenColor::Primary,
                    bold: false,
                    italic: false,
                });
            }
            LessEqual => {
                tokens.push(Token {
                    text: Cow::Borrowed("<="),
                    color: TokenColor::Primary,
                    bold: false,
                    italic: false,
                });
            }
            Less => {
                tokens.push(Token {
                    text: Cow::Borrowed("<"),
                    color: TokenColor::Primary,
                    bold: false,
                    italic: false,
                });
            }
            GreaterEqual => {
                tokens.push(Token {
                    text: Cow::Borrowed(">="),
                    color: TokenColor::Primary,
                    bold: false,
                    italic: false,
                });
            }
            Greater => {
                tokens.push(Token {
                    text: Cow::Borrowed(">"),
                    color: TokenColor::Primary,
                    bold: false,
                    italic: false,
                });
            }
            Equal => {
                tokens.push(Token {
                    text: Cow::Borrowed("="),
                    color: TokenColor::Primary,
                    bold: false,
                    italic: false,
                });
            }
            Identifier | Whitespace => {
                tokens.push(Token {
                    text: Cow::Owned(text.to_string()),
                    color: TokenColor::Primary,
                    bold: false,
                    italic: false,
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
            TokenColor::String => theme.syntax_string,
            TokenColor::Number => theme.syntax_number,
            TokenColor::Comment => theme.syntax_comment,
            TokenColor::LineNumberNft => theme.fg_muted,
            TokenColor::ActionAccept => theme.success, // Green for accept (rendered bold)
            TokenColor::ActionDeny => theme.danger,    // Red for drop/reject (rendered bold)
        }
    }
}
