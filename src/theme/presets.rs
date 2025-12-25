use super::AppTheme;

/// Nord - Professional arctic-inspired theme (DEFAULT)
/// Clean, modern, excellent for professional tools
pub fn nord() -> AppTheme {
    AppTheme::from_hex(
        "Nord",
        0x2E3440, // bg_base - Polar Night 0
        0x242933, // bg_sidebar - Slightly darker
        0x3B4252, // bg_surface - Polar Night 1
        0x434C5E, // bg_elevated - Polar Night 2
        0x4C566A, // bg_hover - Polar Night 3
        0x5E81AC, // bg_active - Frost 2 (muted)
        0xECEFF4, // fg_primary - Snow Storm 2
        0xD8DEE9, // fg_secondary - Snow Storm 1
        0x616E88, // fg_muted - Polar Night 3 lightened
        0x2E3440, // fg_on_accent - Dark text on light accent
        0x88C0D0, // accent - Frost 1 (cyan)
        0x8FBCBB, // accent_hover - Frost 0
        0xA3BE8C, // success - Aurora green
        0xEBCB8B, // warning - Aurora yellow
        0xBF616A, // danger - Aurora red
        0x81A1C1, // info - Frost 3 (blue)
        0x434C5E, // border - Polar Night 2
        0x5E81AC, // border_strong - Frost 2
        0x3B4252, // divider - Polar Night 1
        0x81A1C1, // syntax_keyword - Frost 3 (blue)
        0xB48EAD, // syntax_type - Aurora purple
        0xA3BE8C, // syntax_string - Aurora green
        0xD08770, // syntax_number - Aurora orange
        0x616E88, // syntax_comment - Muted
        0x88C0D0, // syntax_operator - Frost 1
    )
}

/// Gruvbox - Warm retro terminal aesthetic
/// Original DRFW theme, beloved by terminal enthusiasts
pub fn gruvbox() -> AppTheme {
    AppTheme::from_hex(
        "Gruvbox",
        0x282828, // bg_base - bg0_h
        0x1D2021, // bg_sidebar - bg0
        0x3C3836, // bg_surface - bg1
        0x504945, // bg_elevated - bg2
        0x474035, // bg_hover - Between bg1 and bg2
        0x665C54, // bg_active - bg3
        0xFBF1C7, // fg_primary - fg0
        0xEBDBB2, // fg_secondary - fg1
        0xA89984, // fg_muted - fg4
        0x282828, // fg_on_accent - Dark on light
        0xD79921, // accent - Yellow
        0xFAABD2, // accent_hover - Bright yellow
        0x98971A, // success - Green
        0xD79921, // warning - Yellow
        0xCC241D, // danger - Red
        0x458588, // info - Blue
        0x504945, // border - bg2
        0x689D6A, // border_strong - Aqua
        0x3C3836, // divider - bg1
        0xFB4934, // syntax_keyword - Bright red
        0xFAABD2, // syntax_type - Bright yellow
        0xB8BB26, // syntax_string - Bright green
        0xD3869B, // syntax_number - Bright purple
        0x928374, // syntax_comment - Gray
        0x8EC07C, // syntax_operator - Bright aqua
    )
}

/// Dracula - Popular purple-cyan dark theme
/// High contrast, vibrant, modern
pub fn dracula() -> AppTheme {
    AppTheme::from_hex(
        "Dracula",
        0x282A36, // bg_base - Background
        0x21222C, // bg_sidebar - Darker
        0x313341, // bg_surface - Current line (lightened)
        0x393B4D, // bg_elevated - Lighter
        0x44475A, // bg_hover - Selection
        0x6272A4, // bg_active - Comment (lightened)
        0xF8F8F2, // fg_primary - Foreground
        0xE6E6E0, // fg_secondary - Slightly muted
        0x6272A4, // fg_muted - Comment
        0x282A36, // fg_on_accent - Dark on light
        0xBD93F9, // accent - Purple
        0xCDA5FF, // accent_hover - Lighter purple
        0x50FA7B, // success - Green
        0xF1FA8C, // warning - Yellow
        0xFF5555, // danger - Red
        0x8BE9FD, // info - Cyan
        0x44475A, // border - Selection
        0xBD93F9, // border_strong - Purple
        0x313341, // divider - Current line
        0xFF79C6, // syntax_keyword - Pink
        0xBD93F9, // syntax_type - Purple
        0xF1FA8C, // syntax_string - Yellow
        0xFFB86C, // syntax_number - Orange
        0x6272A4, // syntax_comment - Comment
        0x8BE9FD, // syntax_operator - Cyan
    )
}

/// Monokai - Classic warm coding theme
/// Vibrant highlights on dark warm background
pub fn monokai() -> AppTheme {
    AppTheme::from_hex(
        "Monokai",
        0x272822, // bg_base - Background
        0x1E1F1C, // bg_sidebar - Darker
        0x363731, // bg_surface - Lighter
        0x3E3D32, // bg_elevated - Even lighter
        0x49483E, // bg_hover - Selection
        0x75715E, // bg_active - Comment
        0xF8F8F2, // fg_primary - Foreground
        0xE6E6E0, // fg_secondary - Slightly muted
        0x75715E, // fg_muted - Comment
        0x272822, // fg_on_accent - Dark on light
        0x66D9EF, // accent - Blue
        0x76E9FF, // accent_hover - Lighter blue
        0xA6E22E, // success - Green
        0xE6DB74, // warning - Yellow
        0xF92672, // danger - Pink/red
        0xAE81FF, // info - Purple
        0x49483E, // border - Selection
        0x66D9EF, // border_strong - Blue
        0x363731, // divider - Surface
        0xF92672, // syntax_keyword - Pink
        0x66D9EF, // syntax_type - Blue
        0xE6DB74, // syntax_string - Yellow
        0xAE81FF, // syntax_number - Purple
        0x75715E, // syntax_comment - Comment
        0xFD971F, // syntax_operator - Orange
    )
}

/// Everforest - Green-tinted, easy on eyes
/// Nature-inspired, calming for long sessions
pub fn everforest() -> AppTheme {
    AppTheme::from_hex(
        "Everforest",
        0x2B3339, // bg_base - bg0
        0x232A2E, // bg_sidebar - bg_dim
        0x323C41, // bg_surface - bg1
        0x3A454A, // bg_elevated - bg2
        0x404C51, // bg_hover - bg3
        0x4F585E, // bg_active - bg4
        0xD3C6AA, // fg_primary - fg
        0xB4A794, // fg_secondary - Muted fg
        0x7A8478, // fg_muted - gray0
        0x2B3339, // fg_on_accent - Dark on light
        0x7FBBB3, // accent - Aqua
        0x8FC5BD, // accent_hover - Lighter aqua
        0xA7C080, // success - Green
        0xDBBC7F, // warning - Yellow
        0xE67E80, // danger - Red
        0x7FBBB3, // info - Aqua
        0x3A454A, // border - bg2
        0x7FBBB3, // border_strong - Aqua
        0x323C41, // divider - bg1
        0xE67E80, // syntax_keyword - Red
        0xD699B6, // syntax_type - Purple
        0xDBBC7F, // syntax_string - Yellow
        0xD699B6, // syntax_number - Purple
        0x859289, // syntax_comment - gray1
        0x83C092, // syntax_operator - Green
    )
}

/// Tokyo Night - Modern vibrant dark theme
/// Popular, energetic, great contrast
pub fn tokyo_night() -> AppTheme {
    AppTheme::from_hex(
        "Tokyo Night",
        0x1A1B26, // bg_base - Background
        0x16161E, // bg_sidebar - Darker
        0x24283B, // bg_surface - bg_dark
        0x2F3549, // bg_elevated - bg_highlight
        0x3B4261, // bg_hover - Lighter
        0x565F89, // bg_active - fg_dark
        0xC0CAF5, // fg_primary - Foreground
        0xA9B1D6, // fg_secondary - fg_dark
        0x565F89, // fg_muted - Very muted
        0x1A1B26, // fg_on_accent - Dark on light
        0x7AA2F7, // accent - Blue
        0x8AB4F8, // accent_hover - Lighter blue
        0x9ECE6A, // success - Green
        0xE0AF68, // warning - Yellow
        0xF7768E, // danger - Red
        0x7DCFFF, // info - Cyan
        0x3B4261, // border - Lighter bg
        0x7AA2F7, // border_strong - Blue
        0x24283B, // divider - bg_dark
        0xBB9AF7, // syntax_keyword - Purple
        0x7AA2F7, // syntax_type - Blue
        0x9ECE6A, // syntax_string - Green
        0xFF9E64, // syntax_number - Orange
        0x565F89, // syntax_comment - Muted
        0x7DCFFF, // syntax_operator - Cyan
    )
}

/// Catppuccin Mocha - Trendy pastel dark theme
/// Soft colors, modern aesthetic, comfortable
pub fn catppuccin_mocha() -> AppTheme {
    AppTheme::from_hex(
        "Catppuccin Mocha",
        0x1E1E2E, // bg_base - Base
        0x181825, // bg_sidebar - Crust
        0x313244, // bg_surface - Surface0
        0x45475A, // bg_elevated - Surface1
        0x585B70, // bg_hover - Surface2
        0x6C7086, // bg_active - Overlay0
        0xCDD6F4, // fg_primary - Text
        0xBAC2DE, // fg_secondary - Subtext1
        0x6C7086, // fg_muted - Overlay0
        0x1E1E2E, // fg_on_accent - Dark on light
        0x89B4FA, // accent - Blue
        0x99C4FF, // accent_hover - Lighter blue
        0xA6E3A1, // success - Green
        0xF9E2AF, // warning - Yellow
        0xF38BA8, // danger - Red
        0x89DCEB, // info - Sky
        0x45475A, // border - Surface1
        0x89B4FA, // border_strong - Blue
        0x313244, // divider - Surface0
        0xCBA6F7, // syntax_keyword - Mauve
        0x89B4FA, // syntax_type - Blue
        0xA6E3A1, // syntax_string - Green
        0xFAB387, // syntax_number - Peach
        0x6C7086, // syntax_comment - Overlay0
        0x94E2D5, // syntax_operator - Teal
    )
}

/// One Dark - Popular from Atom/VSCode
/// Well-balanced, professional, widely loved
pub fn one_dark() -> AppTheme {
    AppTheme::from_hex(
        "One Dark",
        0x282C34, // bg_base - Background
        0x21252B, // bg_sidebar - Darker
        0x2C313A, // bg_surface - Lighter
        0x3E4451, // bg_elevated - Gutter gray
        0x4B5263, // bg_hover - Lighter
        0x5C6370, // bg_active - Comment gray
        0xABB2BF, // fg_primary - Foreground
        0x9DA5B3, // fg_secondary - Slightly muted
        0x5C6370, // fg_muted - Comment gray
        0x282C34, // fg_on_accent - Dark on light
        0x61AFEF, // accent - Blue
        0x71BFFF, // accent_hover - Lighter blue
        0x98C379, // success - Green
        0xE5C07B, // warning - Yellow
        0xE06C75, // danger - Red
        0x56B6C2, // info - Cyan
        0x3E4451, // border - Gutter gray
        0x61AFEF, // border_strong - Blue
        0x2C313A, // divider - Surface
        0xC678DD, // syntax_keyword - Purple
        0x61AFEF, // syntax_type - Blue
        0x98C379, // syntax_string - Green
        0xD19A66, // syntax_number - Orange
        0x5C6370, // syntax_comment - Comment gray
        0x56B6C2, // syntax_operator - Cyan
    )
}

/// Solarized Dark - Scientifically designed theme
/// Classic, carefully crafted for readability
pub fn solarized_dark() -> AppTheme {
    AppTheme::from_hex(
        "Solarized Dark",
        0x002B36, // bg_base - Base03
        0x00212B, // bg_sidebar - Darker
        0x073642, // bg_surface - Base02
        0x094451, // bg_elevated - Lighter
        0x0E5261, // bg_hover - Even lighter
        0x586E75, // bg_active - Base01
        0xFDF6E3, // fg_primary - Base3
        0xEEE8D5, // fg_secondary - Base2
        0x657B83, // fg_muted - Base00
        0x002B36, // fg_on_accent - Dark on light
        0x268BD2, // accent - Blue
        0x369BD2, // accent_hover - Lighter blue
        0x859900, // success - Green
        0xB58900, // warning - Yellow
        0xDC322F, // danger - Red
        0x2AA198, // info - Cyan
        0x073642, // border - Base02
        0x268BD2, // border_strong - Blue
        0x073642, // divider - Base02
        0xD33682, // syntax_keyword - Magenta
        0x268BD2, // syntax_type - Blue
        0x2AA198, // syntax_string - Cyan
        0xCB4B16, // syntax_number - Orange
        0x586E75, // syntax_comment - Base01
        0x859900, // syntax_operator - Green
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_themes_have_names() {
        let themes = [
            nord(),
            gruvbox(),
            dracula(),
            monokai(),
            everforest(),
            tokyo_night(),
            catppuccin_mocha(),
            one_dark(),
            solarized_dark(),
        ];

        for theme in &themes {
            assert!(!theme.name.is_empty());
        }
    }

    #[test]
    fn test_theme_colors_are_valid() {
        // Just verify themes can be created without panicking
        let _ = nord();
        let _ = gruvbox();
        let _ = dracula();
        let _ = monokai();
        let _ = everforest();
        let _ = tokyo_night();
        let _ = catppuccin_mocha();
        let _ = one_dark();
        let _ = solarized_dark();
    }
}
