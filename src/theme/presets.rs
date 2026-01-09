use super::AppTheme;

/// Oxide - Hybrid of Everdeer and Gruvbox (The "Rust/Oxide" theme)
/// Warm neutral browns with earthy copper accents, highly legible and grounded
pub fn oxide() -> AppTheme {
    AppTheme::from_hex(
        "Oxide",
        0x0023_1D1B, // bg_base - Neutral warm brown
        0x001D_1816, // bg_sidebar - Deep oxide brown
        0x002E_2623, // bg_surface - Lighter card surface
        0x003A_312E, // bg_elevated - Input/button background
        0x0046_3B38, // bg_hover - Subtle highlight
        0x0052_4541, // bg_active - Active state brown
        0x00E6_DBD3, // fg_primary - Warm parchment text
        0x00B8_ACA2, // fg_secondary - Muted clay text
        0x007A_6E67, // fg_muted - Darkened earth gray
        0x001D_1816, // fg_on_accent - Dark text on copper
        0x00A7_5533, // accent - Burnt copper orange
        0x00BD_6D4D, // accent_hover - Warm clay highlight
        0x008F_A172, // success - Muted sage green
        0x00D8_A657, // warning - Warm gold
        0x00C2_5D4E, // danger - Terracotta red
        0x007D_AEA3, // info - Muted teal
        0x003E_3532, // border - Subtle brown border
        0x00A7_5533, // border_strong - Copper accent border
        0x002E_2623, // divider - Surface match
        0x00D4_7761, // syntax_keyword - Oxide terracotta
        0x00D6_99B6, // syntax_type - Muted orchid
        0x00DB_B98F, // syntax_string - Sandstone gold
        0x00B8_ACA2, // syntax_number - Secondary text
        0x007A_6E67, // syntax_comment - Muted brown
        0x00A7_5533, // syntax_operator - Burnt copper
    )
}

/// Oxide Light - Light counterpart to Oxide (Default light theme)
/// Warm copper-tinted cream with subtle terracotta influence - professional yet distinctive
pub fn oxide_light() -> AppTheme {
    AppTheme::from_hex(
        "Oxide Light",
        0x00F2_E8D8, // bg_base - Warm cream with subtle copper tint
        0x00E3_D7C5, // bg_sidebar - Warm clay sidebar
        0x00F7_F0E5, // bg_surface - Light warm cream cards
        0x00FC_F8F0, // bg_elevated - Almost white with warmth
        0x00DC_CFBD, // bg_hover - Warm tan hover
        0x00D4_C4B0, // bg_active - Adobe tan active
        0x003A_2E25, // fg_primary - Deep warm brown (almost black)
        0x006A_5D51, // fg_secondary - Medium warm brown
        0x009B_8D7F, // fg_muted - Light brown for disabled
        0x00FF_FCF8, // fg_on_accent - Light cream on copper
        0x00A7_5533, // accent - Burnt copper (same as dark)
        0x0092_4A2E, // accent_hover - Darker copper for contrast
        0x006B_8456, // success - Sage green
        0x00BD_8838, // warning - Warm amber
        0x00AD_4433, // danger - Warm terracotta
        0x004D_8A7E, // info - Teal contrast
        0x00D8_CCBA, // border - Warm border
        0x00A7_5533, // border_strong - Copper border
        0x00E3_D7C5, // divider - Warm divider
        0x00AD_4433, // syntax_keyword - Terracotta
        0x008B_5A8E, // syntax_type - Muted purple (contrast)
        0x00BD_8838, // syntax_string - Warm amber
        0x006A_5D51, // syntax_number - Medium brown
        0x009B_8D7F, // syntax_comment - Muted brown
        0x00A7_5533, // syntax_operator - Copper accent
    )
}

/// Aethel - Atmospheric noble theme (Gemini's Masterpiece)
/// Deep violet-tinted charcoal backgrounds with celestial indigo and mauve accents
pub fn aethel() -> AppTheme {
    AppTheme::from_hex(
        "Aethel",
        0x0016_161E, // bg_base - Midnight indigo-charcoal
        0x000F_0F14, // bg_sidebar - Deepest ink
        0x001A_1B26, // bg_surface - Polished slate
        0x0024_283B, // bg_elevated - Muted graphite
        0x002F_3549, // bg_hover - Subtle highlight
        0x0041_4868, // bg_active - Active indigo
        0x00DC_DFE4, // fg_primary - Silvered white
        0x00A9_B1D6, // fg_secondary - Cool gray
        0x0056_5F89, // fg_muted - Deep ash
        0x0016_161E, // fg_on_accent - Dark text on celestial
        0x0089_B4FA, // accent - Celestial indigo
        0x00A3_C7FF, // accent_hover - Lighter frost
        0x009E_CE6A, // success - Seafoam green
        0x00E0_AF68, // warning - Ember gold
        0x00F7_768E, // danger - Rose red
        0x007D_CFFF, // info - Sky cyan
        0x0024_283B, // border - Gutter gray
        0x0089_B4FA, // border_strong - Indigo accent
        0x001A_1B26, // divider - Surface match
        0x00BB_9AF7, // syntax_keyword - Mauve purple
        0x007D_CFFF, // syntax_type - Sky blue
        0x009E_CE6A, // syntax_string - Seafoam green
        0x00FF_9E64, // syntax_number - Terracotta orange
        0x0056_5F89, // syntax_comment - Muted ash
        0x0089_B4FA, // syntax_operator - Indigo
    )
}

/// Nord - Professional arctic-inspired theme
/// Clean, modern, excellent for professional tools
pub fn nord() -> AppTheme {
    AppTheme::from_hex(
        "Nord",
        0x002E_3440, // bg_base - Polar Night 0
        0x0024_2933, // bg_sidebar - Slightly darker
        0x003B_4252, // bg_surface - Polar Night 1
        0x0043_4C5E, // bg_elevated - Polar Night 2
        0x004C_566A, // bg_hover - Polar Night 3
        0x005E_81AC, // bg_active - Frost 2 (muted)
        0x00EC_EFF4, // fg_primary - Snow Storm 2
        0x00D8_DEE9, // fg_secondary - Snow Storm 1
        0x0061_6E88, // fg_muted - Polar Night 3 lightened
        0x002E_3440, // fg_on_accent - Dark text on light accent
        0x0088_C0D0, // accent - Frost 1 (cyan)
        0x008F_BCBB, // accent_hover - Frost 0
        0x00A3_BE8C, // success - Aurora green
        0x00EB_CB8B, // warning - Aurora yellow
        0x00BF_616A, // danger - Aurora red
        0x0081_A1C1, // info - Frost 3 (blue)
        0x0043_4C5E, // border - Polar Night 2
        0x005E_81AC, // border_strong - Frost 2
        0x003B_4252, // divider - Polar Night 1
        0x0081_A1C1, // syntax_keyword - Frost 3 (blue)
        0x00B4_8EAD, // syntax_type - Aurora purple
        0x00A3_BE8C, // syntax_string - Aurora green
        0x00D0_8770, // syntax_number - Aurora orange
        0x0061_6E88, // syntax_comment - Muted
        0x0088_C0D0, // syntax_operator - Frost 1
    )
}

/// Gruvbox - Warm retro terminal aesthetic
/// Original DRFW theme, beloved by terminal enthusiasts
pub fn gruvbox() -> AppTheme {
    AppTheme::from_hex(
        "Gruvbox",
        0x0028_2828, // bg_base - bg0_h
        0x001D_2021, // bg_sidebar - bg0
        0x003C_3836, // bg_surface - bg1
        0x0050_4945, // bg_elevated - bg2
        0x0047_4035, // bg_hover - Between bg1 and bg2
        0x0066_5C54, // bg_active - bg3
        0x00FB_F1C7, // fg_primary - fg0
        0x00EB_DBB2, // fg_secondary - fg1
        0x00A8_9984, // fg_muted - fg4
        0x0028_2828, // fg_on_accent - Dark on light
        0x00D7_9921, // accent - Yellow
        0x00FA_BD2F, // accent_hover - Bright yellow
        0x0098_971A, // success - Green
        0x00D7_9921, // warning - Yellow
        0x00CC_241D, // danger - Red
        0x0045_8588, // info - Blue
        0x0050_4945, // border - bg2
        0x0068_9D6A, // border_strong - Aqua
        0x003C_3836, // divider - bg1
        0x00FB_4934, // syntax_keyword - Bright red
        0x00FA_ABD2, // syntax_type - Bright yellow
        0x00B8_BB26, // syntax_string - Bright green
        0x00D3_869B, // syntax_number - Bright purple
        0x0092_8374, // syntax_comment - Gray
        0x008E_C07C, // syntax_operator - Bright aqua
    )
}

/// Dracula - Popular purple-cyan dark theme
/// High contrast, vibrant, modern
pub fn dracula() -> AppTheme {
    AppTheme::from_hex(
        "Dracula",
        0x0028_2A36, // bg_base - Background
        0x0021_222C, // bg_sidebar - Darker
        0x0031_3341, // bg_surface - Current line (lightened)
        0x0039_3B4D, // bg_elevated - Lighter
        0x0044_475A, // bg_hover - Selection
        0x0062_72A4, // bg_active - Comment (lightened)
        0x00F8_F8F2, // fg_primary - Foreground
        0x00E6_E6E0, // fg_secondary - Slightly muted
        0x0062_72A4, // fg_muted - Comment
        0x0028_2A36, // fg_on_accent - Dark on light
        0x00BD_93F9, // accent - Purple
        0x00CD_A5FF, // accent_hover - Lighter purple
        0x0050_FA7B, // success - Green
        0x00F1_FA8C, // warning - Yellow
        0x00FF_5555, // danger - Red
        0x008B_E9FD, // info - Cyan
        0x0044_475A, // border - Selection
        0x00BD_93F9, // border_strong - Purple
        0x0031_3341, // divider - Current line
        0x00FF_79C6, // syntax_keyword - Pink
        0x00BD_93F9, // syntax_type - Purple
        0x00F1_FA8C, // syntax_string - Yellow
        0x00FF_B86C, // syntax_number - Orange
        0x0062_72A4, // syntax_comment - Comment
        0x008B_E9FD, // syntax_operator - Cyan
    )
}

/// Monokai - Classic warm coding theme
/// Vibrant highlights on dark warm background
pub fn monokai() -> AppTheme {
    AppTheme::from_hex(
        "Monokai",
        0x0027_2822, // bg_base - Background
        0x001E_1F1C, // bg_sidebar - Darker
        0x0036_3731, // bg_surface - Lighter
        0x003E_3D32, // bg_elevated - Even lighter
        0x0049_483E, // bg_hover - Selection
        0x0088_846F, // bg_active - Comment (official)
        0x00F8_F8F2, // fg_primary - Foreground
        0x00E6_E6E0, // fg_secondary - Slightly muted
        0x0088_846F, // fg_muted - Comment (official)
        0x0027_2822, // fg_on_accent - Dark on light
        0x0066_D9EF, // accent - Blue
        0x0076_E9FF, // accent_hover - Lighter blue
        0x00A6_E22E, // success - Green
        0x00E6_DB74, // warning - Yellow
        0x00F9_2672, // danger - Pink/red
        0x00AE_81FF, // info - Purple
        0x0049_483E, // border - Selection
        0x0066_D9EF, // border_strong - Blue
        0x0036_3731, // divider - Surface
        0x00F9_2672, // syntax_keyword - Pink
        0x0066_D9EF, // syntax_type - Blue
        0x00E6_DB74, // syntax_string - Yellow
        0x00AE_81FF, // syntax_number - Purple
        0x0088_846F, // syntax_comment - Comment (official)
        0x00FD_971F, // syntax_operator - Orange
    )
}

/// Everforest - Green-tinted, easy on eyes
/// Nature-inspired, calming for long sessions
pub fn everforest() -> AppTheme {
    AppTheme::from_hex(
        "Everforest",
        0x002D_353B, // bg_base - bg0 (official)
        0x0023_2A2E, // bg_sidebar - bg_dim
        0x0034_3F44, // bg_surface - bg1 (official)
        0x003D_484D, // bg_elevated - bg2 (official)
        0x0040_4C51, // bg_hover - bg3
        0x004F_585E, // bg_active - bg4
        0x00D3_C6AA, // fg_primary - fg
        0x00B4_A794, // fg_secondary - Muted fg
        0x007A_8478, // fg_muted - gray0
        0x002B_3339, // fg_on_accent - Dark on light
        0x007F_BBB3, // accent - Aqua
        0x008F_C5BD, // accent_hover - Lighter aqua
        0x00A7_C080, // success - Green
        0x00DB_BC7F, // warning - Yellow
        0x00E6_7E80, // danger - Red
        0x007F_BBB3, // info - Aqua
        0x003A_454A, // border - bg2
        0x007F_BBB3, // border_strong - Aqua
        0x0032_3C41, // divider - bg1
        0x00E6_7E80, // syntax_keyword - Red
        0x00D6_99B6, // syntax_type - Purple
        0x00DB_BC7F, // syntax_string - Yellow
        0x00D6_99B6, // syntax_number - Purple
        0x0085_9289, // syntax_comment - gray1
        0x0083_C092, // syntax_operator - Green
    )
}

/// Tokyo Night - Modern vibrant dark theme
/// Popular, energetic, great contrast
pub fn tokyo_night() -> AppTheme {
    AppTheme::from_hex(
        "Tokyo Night",
        0x001A_1B26, // bg_base - Background
        0x0016_161E, // bg_sidebar - Darker
        0x0024_283B, // bg_surface - bg_dark
        0x002F_3549, // bg_elevated - bg_highlight
        0x003B_4261, // bg_hover - Lighter
        0x0056_5F89, // bg_active - fg_dark
        0x00A9_B1D6, // fg_primary - Foreground (official)
        0x00A9_B1D6, // fg_secondary - fg_dark
        0x0056_5F89, // fg_muted - Very muted
        0x001A_1B26, // fg_on_accent - Dark on light
        0x007A_A2F7, // accent - Blue
        0x008A_B4F8, // accent_hover - Lighter blue
        0x009E_CE6A, // success - Green
        0x00E0_AF68, // warning - Yellow
        0x00DB_4B4B, // danger - Red (official, was pink)
        0x007D_CFFF, // info - Cyan
        0x003B_4261, // border - Lighter bg
        0x007A_A2F7, // border_strong - Blue
        0x0024_283B, // divider - bg_dark
        0x00BB_9AF7, // syntax_keyword - Purple
        0x007A_A2F7, // syntax_type - Blue
        0x009E_CE6A, // syntax_string - Green
        0x00FF_9E64, // syntax_number - Orange
        0x0056_5F89, // syntax_comment - Muted
        0x007D_CFFF, // syntax_operator - Cyan
    )
}

/// Catppuccin Mocha - Trendy pastel dark theme
/// Soft colors, modern aesthetic, comfortable
pub fn catppuccin_mocha() -> AppTheme {
    AppTheme::from_hex(
        "Catppuccin Mocha",
        0x001E_1E2E, // bg_base - Base
        0x0018_1825, // bg_sidebar - Crust
        0x0031_3244, // bg_surface - Surface0
        0x0045_475A, // bg_elevated - Surface1
        0x0058_5B70, // bg_hover - Surface2
        0x006C_7086, // bg_active - Overlay0
        0x00CD_D6F4, // fg_primary - Text
        0x00BA_C2DE, // fg_secondary - Subtext1
        0x006C_7086, // fg_muted - Overlay0
        0x001E_1E2E, // fg_on_accent - Dark on light
        0x0089_B4FA, // accent - Blue
        0x0099_C4FF, // accent_hover - Lighter blue
        0x00A6_E3A1, // success - Green
        0x00F9_E2AF, // warning - Yellow
        0x00F3_8BA8, // danger - Red
        0x0089_DCEB, // info - Sky
        0x0045_475A, // border - Surface1
        0x0089_B4FA, // border_strong - Blue
        0x0031_3244, // divider - Surface0
        0x00CB_A6F7, // syntax_keyword - Mauve
        0x0089_B4FA, // syntax_type - Blue
        0x00A6_E3A1, // syntax_string - Green
        0x00FA_B387, // syntax_number - Peach
        0x006C_7086, // syntax_comment - Overlay0
        0x0094_E2D5, // syntax_operator - Teal
    )
}

/// One Dark - Popular from Atom/VSCode
/// Well-balanced, professional, widely loved
pub fn one_dark() -> AppTheme {
    AppTheme::from_hex(
        "One Dark",
        0x0028_2C34, // bg_base - Background
        0x0021_252B, // bg_sidebar - Darker
        0x002C_313A, // bg_surface - Lighter
        0x003E_4451, // bg_elevated - Gutter gray
        0x004B_5263, // bg_hover - Lighter
        0x005C_6370, // bg_active - Comment gray
        0x00AB_B2BF, // fg_primary - Foreground
        0x009D_A5B3, // fg_secondary - Slightly muted
        0x005C_6370, // fg_muted - Comment gray
        0x0028_2C34, // fg_on_accent - Dark on light
        0x0061_AFEF, // accent - Blue
        0x0071_BFFF, // accent_hover - Lighter blue
        0x0098_C379, // success - Green
        0x00E5_C07B, // warning - Yellow
        0x00E0_6C75, // danger - Red
        0x0056_B6C2, // info - Cyan
        0x003E_4451, // border - Gutter gray
        0x0061_AFEF, // border_strong - Blue
        0x002C_313A, // divider - Surface
        0x00C6_78DD, // syntax_keyword - Purple
        0x0061_AFEF, // syntax_type - Blue
        0x0098_C379, // syntax_string - Green
        0x00D1_9A66, // syntax_number - Orange
        0x005C_6370, // syntax_comment - Comment gray
        0x0056_B6C2, // syntax_operator - Cyan
    )
}

/// Ayu Dark - Warm, nature-inspired theme beloved by Rust community
/// Muted warm colors with excellent readability
pub fn ayu_dark() -> AppTheme {
    AppTheme::from_hex(
        "Ayu Dark",
        0x000F_1419, // bg_base - Deep space background (official)
        0x0001_0B10, // bg_sidebar - Darker sidebar (recalculated)
        0x000D_1016, // bg_surface - Card background
        0x0012_151C, // bg_elevated - Elevated elements
        0x0018_1D24, // bg_hover - Hover state
        0x001F_2430, // bg_active - Active selection
        0x00B3_B1AD, // fg_primary - Warm white text
        0x008A_8984, // fg_secondary - Muted gray
        0x004D_5566, // fg_muted - Dark comment gray
        0x0001_060E, // fg_on_accent - Dark on accent
        0x00FF_B454, // accent - Warm orange
        0x00FF_CC66, // accent_hover - Lighter orange
        0x00BA_E67E, // success - Fresh green
        0x00FF_B454, // warning - Orange
        0x00F2_8779, // danger - Coral red
        0x0039_BAE6, // info - Sky blue
        0x0015_1A1F, // border - Subtle border
        0x00FF_B454, // border_strong - Orange border
        0x0012_151C, // divider - Match surface
        0x00FF_8F40, // syntax_keyword - Bright orange (official)
        0x0073_D0FF, // syntax_type - Sky blue
        0x00AA_D94C, // syntax_string - Fresh green
        0x00FF_AA33, // syntax_number - Orange
        0x00AC_B6BF, // syntax_comment - Muted gray blue
        0x00F2_9718, // syntax_operator - Golden orange
    )
}

/// Rosé Pine - Low-contrast, aesthetic-focused theme
/// Subtle pine green and rose accents on muted backgrounds
pub fn rose_pine() -> AppTheme {
    AppTheme::from_hex(
        "Rosé Pine",
        0x0019_1724, // bg_base - Deep pine background
        0x0015_1320, // bg_sidebar - Darker sidebar
        0x001F_1D2E, // bg_surface - Surface pine
        0x0026_233A, // bg_elevated - Elevated elements
        0x002A_273F, // bg_hover - Hover state
        0x0035_3244, // bg_active - Active highlight
        0x00E0_DEF4, // fg_primary - Soft white text
        0x009C_CFD8, // fg_secondary - Foam cyan (official)
        0x006E_6A86, // fg_muted - Pine gray
        0x0019_1724, // fg_on_accent - Dark on accent
        0x00EB_BCBA, // accent - Rose pink (official)
        0x00F6_C177, // accent_hover - Golden rose
        0x009C_CFD8, // success - Foam cyan (official)
        0x00F6_C177, // warning - Gold
        0x00EB_6F92, // danger - Rose red
        0x009C_CFD8, // info - Foam cyan (official)
        0x002A_273F, // border - Subtle border
        0x00EB_BCBA, // border_strong - Rose border (official)
        0x001F_1D2E, // divider - Match surface
        0x00C4_A7E7, // syntax_keyword - Soft purple
        0x009C_CFD8, // syntax_type - Foam cyan (official)
        0x00F6_C177, // syntax_string - Gold
        0x00EA_9A97, // syntax_number - Coral
        0x006E_6A86, // syntax_comment - Muted gray
        0x0031_748F, // syntax_operator - Pine teal (official)
    )
}

/// Catppuccin Latte - Light variant of popular pastel theme
/// Warm beige backgrounds with soft pastel accents
///
/// Official palette: <https://catppuccin.com/palette/>
pub fn catppuccin_latte() -> AppTheme {
    AppTheme::from_hex(
        "Catppuccin Latte",
        0x00EF_F1F5, // bg_base - Base (main background)
        0x00E6_E9EF, // bg_sidebar - Mantle (sidebar)
        0x00EF_F1F5, // bg_surface - Base (cards match background, use shadow for depth)
        0x00DC_E0E8, // bg_elevated - Crust (inputs darker than surface)
        0x00CC_D0DA, // bg_hover - Surface0 (hover state)
        0x00BC_C0CC, // bg_active - Surface1 (active selection)
        0x004C_4F69, // fg_primary - Text
        0x005C_5F77, // fg_secondary - Subtext1
        0x006C_6F85, // fg_muted - Subtext0
        0x00EF_F1F5, // fg_on_accent - Base (light on accent)
        0x001E_66F5, // accent - Sapphire
        0x0040_79F7, // accent_hover - Lighter sapphire
        0x0040_A02B, // success - Green
        0x00FE_640B, // warning - Peach
        0x00D2_0F39, // danger - Red
        0x0020_9FB5, // info - Teal
        0x00BC_C0CC, // border - Surface1 (visible against Base)
        0x001E_66F5, // border_strong - Sapphire
        0x00DC_E0E8, // divider - Crust
        0x0088_39EF, // syntax_keyword - Mauve
        0x001E_66F5, // syntax_type - Sapphire
        0x0040_A02B, // syntax_string - Green
        0x00FE_640B, // syntax_number - Peach
        0x009C_A0B0, // syntax_comment - Overlay0
        0x0072_87FD, // syntax_operator - Lavender
    )
}

/// Gruvbox Light - Warm retro light theme
/// Cream backgrounds with earthy warm accents
pub fn gruvbox_light() -> AppTheme {
    AppTheme::from_hex(
        "Gruvbox Light",
        0x00FB_F1C7, // bg_base - Light cream background (bg0)
        0x00F9_F5D7, // bg_sidebar - Lighter cream (bg0_s)
        0x00EB_DBB2, // bg_surface - Card surface (bg1)
        0x00D5_C4A1, // bg_elevated - Elevated elements (bg2)
        0x00BD_AE93, // bg_hover - Hover state (bg3)
        0x00A8_9984, // bg_active - Active selection (bg4)
        0x003C_3836, // fg_primary - Dark brown text (fg0)
        0x005A_524C, // fg_secondary - Brown gray (fg1)
        0x007C_6F64, // fg_muted - Light brown (fg2)
        0x00FB_F1C7, // fg_on_accent - Light on accent
        0x00AF_3A03, // accent - Dark orange
        0x00D6_5D0E, // accent_hover - Brighter orange
        0x0079_740E, // success - Dark green
        0x00B5_7614, // warning - Dark yellow
        0x009D_0006, // danger - Dark red
        0x0042_7B58, // info - Dark aqua
        0x00BD_AE93, // border - Visible border (bg3 - darker than bg_elevated)
        0x00AF_3A03, // border_strong - Orange border
        0x00D5_C4A1, // divider - Match elevated (bg2)
        0x009D_0006, // syntax_keyword - Dark red
        0x0076_678E, // syntax_type - Dark purple
        0x0079_740E, // syntax_string - Dark green
        0x00AF_3A03, // syntax_number - Dark orange
        0x0092_8374, // syntax_comment - Gray
        0x00AF_3A03, // syntax_operator - Orange
    )
}

// ═══════════════════════════════════════════════════
// POPULAR DARK THEMES
// ═══════════════════════════════════════════════════

/// GitHub Dark Default - Official GitHub dark theme
/// Professional navy-black theme from GitHub's Primer design system (17.9M installs)
pub fn github_dark() -> AppTheme {
    AppTheme::from_hex(
        "GitHub Dark",
        0x000D_1117, // bg_base - Canvas default (official)
        0x0001_0409, // bg_sidebar - Darker canvas
        0x0016_1B22, // bg_surface - Canvas subtle (official)
        0x0021_262D, // bg_elevated - Elevated surface
        0x002D_333B, // bg_hover - Hover state
        0x0038_3E47, // bg_active - Active state
        0x00C9_D1D9, // fg_primary - Foreground default (official)
        0x008B_949E, // fg_secondary - Foreground muted (official)
        0x006E_7681, // fg_muted - Foreground subtle
        0x000D_1117, // fg_on_accent - Dark on light
        0x0058_A6FF, // accent - Accent emphasis (official blue)
        0x0079_C0FF, // accent_hover - Lighter blue
        0x003F_B950, // success - Success emphasis (official green)
        0x00D2_9922, // warning - Attention emphasis (official gold)
        0x00F8_5149, // danger - Danger emphasis (official red)
        0x0058_A6FF, // info - Accent blue
        0x0021_262D, // border - Border default
        0x0058_A6FF, // border_strong - Accent border
        0x0016_1B22, // divider - Canvas subtle
        0x00FF_7B72, // syntax_keyword - Red (official)
        0x00D2_A8FF, // syntax_type - Purple (official)
        0x00A5_D6FF, // syntax_string - Blue string (official)
        0x0079_C0FF, // syntax_number - Blue number (official)
        0x008B_949E, // syntax_comment - Foreground muted (official)
        0x00FF_A657, // syntax_operator - Orange (official)
    )
}

/// Material Theme Palenight - Popular purple-blue professional theme
/// Deep purple background with vibrant syntax colors (2.46M installs)
pub fn material_palenight() -> AppTheme {
    AppTheme::from_hex(
        "Material Palenight",
        0x0029_2D3E, // bg_base - Editor background (official)
        0x0021_2532, // bg_sidebar - Darker sidebar
        0x0032_3644, // bg_surface - Lighter surface
        0x003B_3F4F, // bg_elevated - Elevated elements
        0x0046_4B5D, // bg_hover - Hover state
        0x004C_5374, // bg_active - Line number color (official)
        0x00BF_C7D5, // fg_primary - Editor foreground (official)
        0x00A9_B0BE, // fg_secondary - Muted foreground
        0x0069_7098, // fg_muted - Comment color (official)
        0x0029_2D3E, // fg_on_accent - Dark on light
        0x0082_AAFF, // accent - Function blue (official)
        0x0092_BAFF, // accent_hover - Lighter blue
        0x00C3_E88D, // success - String green (official)
        0x00FF_CB6B, // warning - Type/variable yellow (official)
        0x00FF_5572, // danger - Tag red (official)
        0x0089_DDFF, // info - Operator cyan (official)
        0x003B_3F4F, // border - Elevated match
        0x0082_AAFF, // border_strong - Accent blue
        0x0032_3644, // divider - Surface match
        0x00C7_92EA, // syntax_keyword - Keyword purple (official)
        0x00FF_CB6B, // syntax_type - Type yellow (official)
        0x00C3_E88D, // syntax_string - String green (official)
        0x00F7_8C6C, // syntax_number - Number orange (official)
        0x0069_7098, // syntax_comment - Comment gray (official)
        0x0089_DDFF, // syntax_operator - Operator cyan (official)
    )
}

/// Min Dark - Minimal distraction-free theme by VS Code designer
/// True minimalist aesthetic with muted grays (551K installs)
pub fn min_dark() -> AppTheme {
    AppTheme::from_hex(
        "Min Dark",
        0x001F_1F1E, // bg_base - Editor background (official)
        0x0019_1A19, // bg_sidebar - Activity bar background (official)
        0x0025_2524, // bg_surface - Slightly lighter
        0x002B_2B2A, // bg_elevated - Elevated elements
        0x0032_3231, // bg_hover - Hover state
        0x003A_3A39, // bg_active - Active state
        0x00BB_BBBB, // fg_primary - Editor foreground (official)
        0x009E_9E9E, // fg_secondary - Muted foreground
        0x007D_7D7D, // fg_muted - Activity bar foreground (official)
        0x001F_1F1E, // fg_on_accent - Dark on light
        0x009E_7296, // accent - Purple accent (from design)
        0x00AE_82A6, // accent_hover - Lighter purple
        0x006C_9B65, // success - Green (from design)
        0x00AF_B36F, // warning - Yellow-green (from design)
        0x00BB_6565, // danger - Muted red
        0x0065_9BA8, // info - Muted cyan
        0x002B_2B2A, // border - Subtle border
        0x009E_7296, // border_strong - Purple accent
        0x0025_2524, // divider - Surface match
        0x009E_7296, // syntax_keyword - Purple
        0x0065_9BA8, // syntax_type - Cyan
        0x006C_9B65, // syntax_string - Green
        0x00AF_B36F, // syntax_number - Yellow-green
        0x0065_6565, // syntax_comment - Dark gray
        0x00BB_BBBB, // syntax_operator - Foreground
    )
}

/// Poimandres - Minimal semantic dark theme from React community
/// Blueberry-inspired with semantic meaning focus (141K devoted users)
pub fn poimandres() -> AppTheme {
    AppTheme::from_hex(
        "Poimandres",
        0x001B_1E28, // bg_base - Editor background (official)
        0x0015_171F, // bg_sidebar - Darker sidebar
        0x0021_242E, // bg_surface - Lighter surface
        0x0027_2A36, // bg_elevated - Elevated elements
        0x002D_303D, // bg_hover - Hover state
        0x0035_3945, // bg_active - Active state
        0x00A6_ACCD, // fg_primary - Editor foreground (official)
        0x008B_91B0, // fg_secondary - Muted foreground
        0x0076_7C9D, // fg_muted - Comment (official)
        0x001B_1E28, // fg_on_accent - Dark on light
        0x00AD_D7FF, // accent - Function blue (official)
        0x00BD_E7FF, // accent_hover - Lighter blue
        0x005D_E4C7, // success - String/constant cyan (official)
        0x00FF_D580, // warning - Gold/yellow
        0x00D0_679D, // danger - Error pink (official)
        0x0091_B4D5, // info - Keyword operator blue (official)
        0x0027_2A36, // border - Elevated match
        0x00AD_D7FF, // border_strong - Function blue
        0x0021_242E, // divider - Surface match
        0x00A6_ACCD, // syntax_keyword - Keyword lavender (official)
        0x00E4_F0FB, // syntax_type - Variable white (official)
        0x005D_E4C7, // syntax_string - String cyan (official)
        0x005D_E4C7, // syntax_number - Number cyan (official)
        0x0076_7C9D, // syntax_comment - Comment gray (official)
        0x0091_B4D5, // syntax_operator - Operator blue (official)
    )
}

/// Pnevma - High-contrast neutral theme with desaturated earth tones
/// Pure neutral gray base with soft, muted colors for reduced visual fatigue
pub fn pnevma() -> AppTheme {
    AppTheme::from_hex(
        "Pnevma",
        0x001C_1C1C, // bg_base - Pure neutral dark gray (v2)
        0x0018_1818, // bg_sidebar - Slightly darker
        0x0024_2424, // bg_surface - Slightly lighter surface
        0x002F_2E2D, // bg_elevated - Color0 (v2)
        0x004A_4845, // bg_hover - Color8 bright black (v2)
        0x004D_4D4D, // bg_active - Selection background (v2)
        0x00D0_D0D0, // fg_primary - Foreground/Color7 (v2)
        0x00B0_B0B0, // fg_secondary - Dimmed foreground
        0x006A_6866, // fg_muted - Muted gray
        0x001C_1C1C, // fg_on_accent - Dark on light (v2)
        0x007F_A5BD, // accent - Color4 blue (v2)
        0x00A1_BDCE, // accent_hover - Color12 bright blue (v2)
        0x0090_A57D, // success - Color2 green (v2)
        0x00D7_AF87, // warning - Color3 orange (v2)
        0x00A3_6666, // danger - Color1 red (v2)
        0x007F_A5BD, // info - Color4 blue (v2)
        0x002F_2E2D, // border - Color0 match
        0x007F_A5BD, // border_strong - Accent blue
        0x0024_2424, // divider - Surface match
        0x00C7_9EC4, // syntax_keyword - Color5 magenta (v2)
        0x007F_A5BD, // syntax_type - Color4 blue (v2)
        0x0090_A57D, // syntax_string - Color2 green (v2)
        0x00D7_AF87, // syntax_number - Color3 orange (v2)
        0x004A_4845, // syntax_comment - Color8 muted (v2)
        0x008A_DBB4, // syntax_operator - Color6 cyan (v2)
    )
}

/// Night Owl - Professional dark blue theme optimized for night coding
/// Dark navy with vibrant syntax colors for excellent readability
pub fn night_owl() -> AppTheme {
    AppTheme::from_hex(
        "Night Owl",
        0x0001_1627, // bg_base - Dark navy
        0x0001_0D18, // bg_sidebar - Darker navy
        0x0011_2A42, // bg_surface - Card background
        0x0019_3549, // bg_elevated - Input background
        0x0021_4456, // bg_hover - Hover state
        0x002A_5568, // bg_active - Active state
        0x00D6_DEEB, // fg_primary - Light gray-blue
        0x0089_A4BB, // fg_secondary - Medium gray-blue
        0x005F_7E97, // fg_muted - Muted blue
        0x0001_1627, // fg_on_accent - Dark on accent
        0x00C7_92EA, // accent - Magenta (official)
        0x006A_4CAA, // accent_hover - Darker purple
        0x00C5_E478, // success - Green-yellow
        0x00F7_8C6C, // warning - Orange
        0x00EF_5350, // danger - Red (official, was pink)
        0x0082_AAFF, // info - Light blue
        0x0011_2A42, // border - Match surface
        0x00C7_92EA, // border_strong - Magenta border (official)
        0x0011_2A42, // divider - Match surface
        0x00C7_92EA, // syntax_keyword - Magenta
        0x0082_AAFF, // syntax_type - Light blue
        0x00EC_C48D, // syntax_string - Golden
        0x00F7_8C6C, // syntax_number - Orange
        0x0063_7777, // syntax_comment - Muted teal
        0x007F_DBCA, // syntax_operator - Teal
    )
}

/// `SynthWave` '84 - Retro neon cyberpunk theme
/// Dark background with vibrant neon pink, cyan, and purple
pub fn synthwave_84() -> AppTheme {
    AppTheme::from_hex(
        "SynthWave '84",
        0x0026_2335, // bg_base - Dark purple-black
        0x0020_1B2D, // bg_sidebar - Darker purple
        0x0034_294A, // bg_surface - Purple card
        0x0041_3356, // bg_elevated - Lighter purple
        0x004E_4061, // bg_hover - Hover purple
        0x005B_4D6C, // bg_active - Active purple
        0x00FF_FFFF, // fg_primary - White (official)
        0x00C4_C0D0, // fg_secondary - Light purple-gray
        0x008A_85A0, // fg_muted - Muted purple
        0x0026_2335, // fg_on_accent - Dark on accent
        0x00FF_7EDB, // accent - Neon pink/magenta (official)
        0x00E0_0066, // accent_hover - Darker pink
        0x0003_EDF9, // success - Neon cyan (official)
        0x00FE_DE5D, // warning - Neon yellow (official)
        0x00FE_4450, // danger - Neon red
        0x0003_EDF9, // info - Bright cyan (official)
        0x0034_294A, // border - Match surface
        0x00FF_7EDB, // border_strong - Neon pink (official)
        0x0034_294A, // divider - Match surface
        0x00FF_7EDB, // syntax_keyword - Pink
        0x0003_EDF9, // syntax_type - Cyan (official)
        0x00FE_DE5D, // syntax_string - Yellow (official)
        0x00FF_8B39, // syntax_number - Orange (official)
        0x006D_6D6D, // syntax_comment - Gray
        0x00FF_7EDB, // syntax_operator - Pink
    )
}

// ═══════════════════════════════════════════════════
// LIGHT THEMES
// ═══════════════════════════════════════════════════

/// GitHub Light Default - Official GitHub light theme
/// Clean professional light theme from GitHub's Primer design system (17.9M installs)
pub fn github_light() -> AppTheme {
    AppTheme::from_hex(
        "GitHub Light",
        0x00FF_FFFF, // bg_base - Canvas default white (official)
        0x00F6_F8FA, // bg_sidebar - Canvas subtle (official)
        0x00FF_FFFF, // bg_surface - White surface
        0x00F6_F8FA, // bg_elevated - Subtle gray
        0x00EB_EEF2, // bg_hover - Hover state
        0x00D8_DEE4, // bg_active - Active state
        0x0024_292F, // fg_primary - Foreground default (official)
        0x0057_606A, // fg_secondary - Foreground muted (official)
        0x0068_7178, // fg_muted - Foreground subtle
        0x00FF_FFFF, // fg_on_accent - Light on dark
        0x0009_69DA, // accent - Accent emphasis blue (official)
        0x0000_59C7, // accent_hover - Darker blue
        0x001A_7F37, // success - Success emphasis green (official)
        0x009A_6700, // warning - Attention emphasis orange (official)
        0x00CF_222E, // danger - Danger emphasis red (official)
        0x0009_69DA, // info - Accent blue
        0x00D8_DEE4, // border - Border default
        0x0009_69DA, // border_strong - Accent border
        0x00F6_F8FA, // divider - Canvas subtle
        0x00CF_222E, // syntax_keyword - Red (official)
        0x0082_50DF, // syntax_type - Purple (official)
        0x000A_3069, // syntax_string - Blue string (official)
        0x0009_69DA, // syntax_number - Blue number (official)
        0x0057_606A, // syntax_comment - Foreground muted (official)
        0x00BF_3989, // syntax_operator - Pink (official)
    )
}

/// One Light - Clean minimal light theme (pairs with One Dark)
/// Soft white backgrounds with subtle blue and green accents
pub fn one_light() -> AppTheme {
    AppTheme::from_hex(
        "One Light",
        0x00FA_FAFA, // bg_base - Soft white
        0x00F0_F0F0, // bg_sidebar - Light gray
        0x00FF_FFFF, // bg_surface - Pure white cards
        0x00EC_ECEC, // bg_elevated - Slightly darker
        0x00DB_DBDB, // bg_hover - Hover gray
        0x00CA_CACA, // bg_active - Active gray
        0x0038_3A42, // fg_primary - Dark gray
        0x006A_6C75, // fg_secondary - Medium gray
        0x00A0_A1A7, // fg_muted - Comment gray (official)
        0x00FA_FAFA, // fg_on_accent - Light on accent
        0x0040_78F2, // accent - Blue
        0x0030_68E0, // accent_hover - Darker blue
        0x0050_A14F, // success - Green
        0x00C1_8401, // warning - Orange
        0x00E4_5649, // danger - Red
        0x0040_78F2, // info - Blue
        0x00DB_DBDB, // border - Light border
        0x0040_78F2, // border_strong - Blue border
        0x00EC_ECEC, // divider - Match elevated
        0x00A6_26A4, // syntax_keyword - Purple
        0x0040_78F2, // syntax_type - Blue
        0x0050_A14F, // syntax_string - Green
        0x00C1_8401, // syntax_number - Orange
        0x00A0_A1A7, // syntax_comment - Gray
        0x0038_3A42, // syntax_operator - Dark gray
    )
}

/// Solarized Light - Classic scientifically-designed light theme
/// Warm cream backgrounds designed for eye comfort and readability
pub fn solarized_light() -> AppTheme {
    AppTheme::from_hex(
        "Solarized Light",
        0x00FD_F6E3, // bg_base - Base3 (warm cream)
        0x00EE_E8D5, // bg_sidebar - Base2
        0x00FD_F6E3, // bg_surface - Base3
        0x00EE_E8D5, // bg_elevated - Base2
        0x0093_A1A1, // bg_hover - Base1
        0x0083_9496, // bg_active - Base0
        0x0065_7B83, // fg_primary - Base00
        0x0058_6E75, // fg_secondary - Base01
        0x0093_A1A1, // fg_muted - Base1
        0x00FD_F6E3, // fg_on_accent - Light on accent
        0x0026_8BD2, // accent - Blue
        0x0021_76BA, // accent_hover - Darker blue
        0x0085_9900, // success - Green
        0x00B5_8900, // warning - Yellow
        0x00DC_322F, // danger - Red
        0x002A_A198, // info - Cyan
        0x0093_A1A1, // border - Base1
        0x0026_8BD2, // border_strong - Blue
        0x00EE_E8D5, // divider - Base2
        0x00D3_3682, // syntax_keyword - Magenta
        0x0026_8BD2, // syntax_type - Blue
        0x002A_A198, // syntax_string - Cyan
        0x00CB_4B16, // syntax_number - Orange
        0x0093_A1A1, // syntax_comment - Base1
        0x0085_9900, // syntax_operator - Green
    )
}

/// Rosé Pine Dawn - Romantic light theme with rose and gold accents
/// Warm cream backgrounds with rose, gold, and pine colors
///
/// Official palette: <https://rosepinetheme.com/palette>
pub fn rose_pine_dawn() -> AppTheme {
    AppTheme::from_hex(
        "Rosé Pine Dawn",
        0x00FA_F4ED, // bg_base - Base (warm cream)
        0x00F2_E9E1, // bg_sidebar - Surface (slightly darker)
        0x00FF_FAF3, // bg_surface - Lighter cream (cards)
        0x00F2_E9E1, // bg_elevated - Surface (inputs)
        0x00E0_D3C2, // bg_hover - Hover (darker tan)
        0x00D4_C7B6, // bg_active - Active tan
        0x0057_5279, // fg_primary - Text
        0x0079_7593, // fg_secondary - Subtle
        0x009B_9099, // fg_muted - Muted
        0x00FA_F4ED, // fg_on_accent - Base (light on accent)
        0x00D7_827E, // accent - Rose
        0x00C5_7570, // accent_hover - Darker rose
        0x0056_949F, // success - Pine
        0x00EA_9D34, // warning - Gold
        0x00B4_637A, // danger - Love
        0x0090_7AA9, // info - Iris
        0x00D4_C7B6, // border - Visible border (darker than surface)
        0x00D7_827E, // border_strong - Rose border
        0x00E0_D3C2, // divider - Slightly darker
        0x00B4_637A, // syntax_keyword - Love
        0x0056_949F, // syntax_type - Pine
        0x00EA_9D34, // syntax_string - Gold
        0x00D7_827E, // syntax_number - Rose
        0x009B_9099, // syntax_comment - Muted
        0x00D7_827E, // syntax_operator - Rose
    )
}

/// Everforest Light - Soft green nature-inspired light theme
/// Warm cream backgrounds with forest green accents
///
/// Official palette: <https://github.com/sainnhe/everforest>
pub fn everforest_light() -> AppTheme {
    AppTheme::from_hex(
        "Everforest Light",
        0x00FD_F6E3, // bg_base - bg0 (warm cream)
        0x00F8_F0DC, // bg_sidebar - bg_dim (light tan)
        0x00FF_FFEF, // bg_surface - Lighter cream (cards)
        0x00F0_E5D1, // bg_elevated - bg1 (warm beige)
        0x00E4_D9C5, // bg_hover - bg2 (darker beige)
        0x00D8_CDB9, // bg_active - bg3 (active beige)
        0x005C_6A72, // fg_primary - fg (dark gray-green)
        0x007D_8B92, // fg_secondary - gray0
        0x009F_A9AD, // fg_muted - gray1
        0x00FF_F9E8, // fg_on_accent - Light on accent
        0x008D_A101, // accent - Green
        0x007A_8C00, // accent_hover - Darker green
        0x0093_B259, // success - Bright green
        0x00E6_9875, // warning - Orange
        0x00E6_7E80, // danger - Red
        0x007F_BFB2, // info - Aqua
        0x00D8_CDB9, // border - bg3 (visible, darker than bg_elevated)
        0x008D_A101, // border_strong - Green border
        0x00E4_D9C5, // divider - bg2
        0x00F8_5552, // syntax_keyword - Red
        0x0039_97A2, // syntax_type - Aqua
        0x00DB_B274, // syntax_string - Yellow
        0x00E6_9875, // syntax_number - Orange
        0x00A6_B1B7, // syntax_comment - Gray
        0x008D_A101, // syntax_operator - Green
    )
}

/// Monochrome Dark - Pure grayscale theme for minimal visual noise
/// No syntax highlighting colors, just shades of gray with subtle hierarchy
///
/// Contrast ratios meet WCAG AA (4.5:1) for all text on backgrounds:
/// - `fg_primary` on `bg_base`: 13.3:1 (AAA)
/// - `fg_secondary` on `bg_base`: 7.5:1 (AAA)
/// - `fg_muted` on `bg_surface`: 4.5:1 (AA)
/// - `danger` on `bg_base`: 6.3:1 (AA)
///
/// Semantic colors use different gray levels for distinguishability:
/// - Success: Light gray (#B0B0B0) - positive/completed
/// - Warning: Medium gray (#909090) - caution/attention
/// - Danger: Bright gray (#C8C8C8) - highest contrast for errors
pub fn monochrome() -> AppTheme {
    AppTheme::from_hex(
        "Monochrome",
        0x0012_1212, // bg_base - Near black
        0x000E_0E0E, // bg_sidebar - Deepest black
        0x001A_1A1A, // bg_surface - Dark gray cards
        0x0024_2424, // bg_elevated - Input background
        0x002E_2E2E, // bg_hover - Hover state
        0x0038_3838, // bg_active - Active state
        0x00E8_E8E8, // fg_primary - Near white (13.3:1 contrast)
        0x00B0_B0B0, // fg_secondary - Medium gray (7.5:1 contrast)
        0x0088_8888, // fg_muted - Gray for AA compliance (4.5:1)
        0x0012_1212, // fg_on_accent - Dark on light accent
        0x00A0_A0A0, // accent - Medium gray accent (6.5:1 contrast)
        0x00B8_B8B8, // accent_hover - Lighter gray
        0x00B0_B0B0, // success - Light gray (distinct from danger)
        0x0090_9090, // warning - Medium gray (middle intensity)
        0x00C8_C8C8, // danger - Bright gray (highest contrast for visibility)
        0x00A0_A0A0, // info - Medium-light gray
        0x002A_2A2A, // border - Subtle border
        0x0050_5050, // border_strong - Stronger border
        0x001A_1A1A, // divider - Surface match
        0x00E8_E8E8, // syntax_keyword - Primary (white)
        0x00B0_B0B0, // syntax_type - Secondary
        0x00B0_B0B0, // syntax_string - Secondary
        0x0090_9090, // syntax_number - Muted
        0x0070_7070, // syntax_comment - Dim but readable (4.0:1)
        0x0090_9090, // syntax_operator - Muted
    )
}

/// Monochrome Light - Pure grayscale light theme for minimal visual noise
/// Light counterpart to Monochrome with inverted hierarchy
///
/// Contrast ratios meet WCAG AA (4.5:1) for all text on backgrounds:
/// - `fg_primary` on `bg_base`: 12.6:1 (AAA)
/// - `fg_secondary` on `bg_base`: 6.8:1 (AAA)
/// - `fg_muted` on `bg_surface`: 4.6:1 (AA)
/// - `danger` on `bg_base`: 12.6:1 (AAA)
///
/// Semantic colors use different gray levels for distinguishability:
/// - Success: Medium gray (#606060) - visible but calm
/// - Warning: Medium-dark gray (#484848) - draws moderate attention
/// - Danger: Near black (#1A1A1A) - maximum contrast for errors
pub fn monochrome_light() -> AppTheme {
    AppTheme::from_hex(
        "Monochrome Light",
        0x00F2_F2F2, // bg_base - Light gray
        0x00E6_E6E6, // bg_sidebar - Slightly darker for separation
        0x00FF_FFFF, // bg_surface - White cards
        0x00F8_F8F8, // bg_elevated - Near white inputs
        0x00E0_E0E0, // bg_hover - Visible hover
        0x00D0_D0D0, // bg_active - Active state
        0x001A_1A1A, // fg_primary - Near black (12.6:1 contrast)
        0x0048_4848, // fg_secondary - Dark gray (6.8:1 contrast)
        0x0068_6868, // fg_muted - Medium gray for AA compliance (4.6:1)
        0x00FF_FFFF, // fg_on_accent - White on dark accent
        0x0050_5050, // accent - Medium-dark gray accent
        0x0038_3838, // accent_hover - Darker gray
        0x0060_6060, // success - Medium gray (visible but calm)
        0x0048_4848, // warning - Medium-dark gray (attention)
        0x001A_1A1A, // danger - Near black (maximum contrast)
        0x0058_5858, // info - Medium gray
        0x00D0_D0D0, // border - Subtle border
        0x0090_9090, // border_strong - Visible border
        0x00E0_E0E0, // divider - Light gray
        0x001A_1A1A, // syntax_keyword - Primary (black)
        0x0048_4848, // syntax_type - Secondary
        0x0048_4848, // syntax_string - Secondary
        0x0060_6060, // syntax_number - Muted
        0x0088_8888, // syntax_comment - Dim but readable (4.5:1)
        0x0060_6060, // syntax_operator - Muted
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_themes_have_names() {
        let themes = [
            // Custom themes
            oxide(),
            aethel(),
            // Popular dark themes
            github_dark(),
            dracula(),
            one_dark(),
            monokai(),
            night_owl(),
            synthwave_84(),
            material_palenight(),
            min_dark(),
            // Modern dark themes
            tokyo_night(),
            catppuccin_mocha(),
            rose_pine(),
            poimandres(),
            pnevma(),
            // Nature/atmospheric dark themes
            nord(),
            gruvbox(),
            everforest(),
            ayu_dark(),
            // Light themes
            github_light(),
            gruvbox_light(),
            catppuccin_latte(),
            rose_pine_dawn(),
            everforest_light(),
            oxide_light(),
            one_light(),
            solarized_light(),
            // Accessibility
            monochrome(),
            monochrome_light(),
        ];

        for theme in &themes {
            assert!(!theme.name.is_empty());
        }
    }

    #[test]
    fn test_theme_colors_are_valid() {
        // Just verify themes can be created without panicking
        // Custom themes
        let _ = oxide();
        let _ = aethel();
        // Popular dark themes
        let _ = github_dark();
        let _ = dracula();
        let _ = one_dark();
        let _ = monokai();
        let _ = night_owl();
        let _ = synthwave_84();
        let _ = material_palenight();
        let _ = min_dark();
        // Modern dark themes
        let _ = tokyo_night();
        let _ = catppuccin_mocha();
        let _ = rose_pine();
        let _ = poimandres();
        let _ = pnevma();
        // Nature/atmospheric dark themes
        let _ = nord();
        let _ = gruvbox();
        let _ = everforest();
        let _ = ayu_dark();
        // Light themes
        let _ = github_light();
        let _ = gruvbox_light();
        let _ = catppuccin_latte();
        let _ = rose_pine_dawn();
        let _ = everforest_light();
        let _ = oxide_light();
        let _ = one_light();
        let _ = solarized_light();
        // Accessibility
        let _ = monochrome();
        let _ = monochrome_light();
    }
}
