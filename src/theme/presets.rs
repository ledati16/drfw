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
        0x00FA_ABD2, // accent_hover - Bright yellow
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
        0x0075_715E, // bg_active - Comment
        0x00F8_F8F2, // fg_primary - Foreground
        0x00E6_E6E0, // fg_secondary - Slightly muted
        0x0075_715E, // fg_muted - Comment
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
        0x0075_715E, // syntax_comment - Comment
        0x00FD_971F, // syntax_operator - Orange
    )
}

/// Everforest - Green-tinted, easy on eyes
/// Nature-inspired, calming for long sessions
pub fn everforest() -> AppTheme {
    AppTheme::from_hex(
        "Everforest",
        0x002B_3339, // bg_base - bg0
        0x0023_2A2E, // bg_sidebar - bg_dim
        0x0032_3C41, // bg_surface - bg1
        0x003A_454A, // bg_elevated - bg2
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
        0x00C0_CAF5, // fg_primary - Foreground
        0x00A9_B1D6, // fg_secondary - fg_dark
        0x0056_5F89, // fg_muted - Very muted
        0x001A_1B26, // fg_on_accent - Dark on light
        0x007A_A2F7, // accent - Blue
        0x008A_B4F8, // accent_hover - Lighter blue
        0x009E_CE6A, // success - Green
        0x00E0_AF68, // warning - Yellow
        0x00F7_768E, // danger - Red
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

/// Solarized Dark - Scientifically designed theme
/// Classic, carefully crafted for readability
pub fn solarized_dark() -> AppTheme {
    AppTheme::from_hex(
        "Solarized Dark",
        0x0000_2B36, // bg_base - Base03
        0x0000_212B, // bg_sidebar - Darker
        0x0007_3642, // bg_surface - Base02
        0x0009_4451, // bg_elevated - Lighter
        0x000E_5261, // bg_hover - Even lighter
        0x0058_6E75, // bg_active - Base01
        0x00FD_F6E3, // fg_primary - Base3
        0x00EE_E8D5, // fg_secondary - Base2
        0x0065_7B83, // fg_muted - Base00
        0x0000_2B36, // fg_on_accent - Dark on light
        0x0026_8BD2, // accent - Blue
        0x0036_9BD2, // accent_hover - Lighter blue
        0x0085_9900, // success - Green
        0x00B5_8900, // warning - Yellow
        0x00DC_322F, // danger - Red
        0x002A_A198, // info - Cyan
        0x0007_3642, // border - Base02
        0x0026_8BD2, // border_strong - Blue
        0x0007_3642, // divider - Base02
        0x00D3_3682, // syntax_keyword - Magenta
        0x0026_8BD2, // syntax_type - Blue
        0x002A_A198, // syntax_string - Cyan
        0x00CB_4B16, // syntax_number - Orange
        0x0058_6E75, // syntax_comment - Base01
        0x0085_9900, // syntax_operator - Green
    )
}

/// Ayu Dark - Warm, nature-inspired theme beloved by Rust community
/// Muted warm colors with excellent readability
pub fn ayu_dark() -> AppTheme {
    AppTheme::from_hex(
        "Ayu Dark",
        0x000A_0E14, // bg_base - Deep space background
        0x0001_060E, // bg_sidebar - Darker sidebar
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
        0x00FF_AA33, // syntax_keyword - Bright orange
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
        0x009C_CED7, // fg_secondary - Muted cyan
        0x006E_6A86, // fg_muted - Pine gray
        0x0019_1724, // fg_on_accent - Dark on accent
        0x00EB_BED3, // accent - Rose pink
        0x00F6_C177, // accent_hover - Golden rose
        0x009C_CED7, // success - Soft cyan
        0x00F6_C177, // warning - Gold
        0x00EB_6F92, // danger - Rose red
        0x009C_CED7, // info - Cyan
        0x002A_273F, // border - Subtle border
        0x00EB_BED3, // border_strong - Rose border
        0x001F_1D2E, // divider - Match surface
        0x00C4_A7E7, // syntax_keyword - Soft purple
        0x009C_CED7, // syntax_type - Cyan
        0x00F6_C177, // syntax_string - Gold
        0x00EA_9A97, // syntax_number - Coral
        0x006E_6A86, // syntax_comment - Muted gray
        0x003E_8FB0, // syntax_operator - Teal
    )
}

/// Material Theme - Palenight variant, one of the most popular themes
/// Deep purple backgrounds with vibrant cyan and pink accents
pub fn material_theme() -> AppTheme {
    AppTheme::from_hex(
        "Material Theme",
        0x0029_2D3E, // bg_base - Deep purple gray
        0x0021_252E, // bg_sidebar - Darker sidebar
        0x0032_364A, // bg_surface - Card surface
        0x003B_3F51, // bg_elevated - Elevated elements
        0x0044_475A, // bg_hover - Hover state
        0x0050_5666, // bg_active - Active selection
        0x00EE_FFFF, // fg_primary - Bright white
        0x00B0_BEC5, // fg_secondary - Cool gray
        0x0067_6E95, // fg_muted - Purple gray
        0x0029_2D3E, // fg_on_accent - Dark on accent
        0x0082_AAFF, // accent - Bright cyan
        0x00A3_C7FF, // accent_hover - Lighter cyan
        0x00C3_E88D, // success - Fresh green
        0x00FF_CB6B, // warning - Warm yellow
        0x00F0_7178, // danger - Coral red
        0x0089_DDFF, // info - Sky blue
        0x003B_3F51, // border - Subtle border
        0x0082_AAFF, // border_strong - Cyan border
        0x0032_364A, // divider - Match surface
        0x00C7_92EA, // syntax_keyword - Purple
        0x0089_DDFF, // syntax_type - Sky blue
        0x00C3_E88D, // syntax_string - Green
        0x00F7_8C6C, // syntax_number - Orange
        0x0067_6E95, // syntax_comment - Muted
        0x0089_DDFF, // syntax_operator - Cyan
    )
}

/// Catppuccin Latte - Light variant of popular pastel theme
/// Warm beige backgrounds with soft pastel accents
pub fn catppuccin_latte() -> AppTheme {
    AppTheme::from_hex(
        "Catppuccin Latte",
        0x00EF_F1F5, // bg_base - Soft latte background
        0x00E6_E9EF, // bg_sidebar - Darker latte
        0x00DC_E0E8, // bg_surface - Card surface
        0x00CC_D0DA, // bg_elevated - Elevated elements
        0x00BA_BDC4, // bg_hover - Hover state
        0x00AC_B0BE, // bg_active - Active selection
        0x004C_4F69, // fg_primary - Dark text
        0x005C_5F77, // fg_secondary - Muted dark
        0x006C_6F85, // fg_muted - Gray text
        0x00EF_F1F5, // fg_on_accent - Light on accent
        0x001E_66F5, // accent - Sapphire blue
        0x0040_79F7, // accent_hover - Lighter blue
        0x0040_A02B, // success - Green
        0x00DF_8E1D, // warning - Peach
        0x00D2_0F39, // danger - Red
        0x0020_9FB5, // info - Teal
        0x00CC_D0DA, // border - Subtle border
        0x001E_66F5, // border_strong - Blue border
        0x00DC_E0E8, // divider - Match surface
        0x0088_39EF, // syntax_keyword - Mauve
        0x001E_66F5, // syntax_type - Sapphire
        0x0040_A02B, // syntax_string - Green
        0x00FE_640B, // syntax_number - Peach
        0x009C_A0B0, // syntax_comment - Overlay 2
        0x0072_87FD, // syntax_operator - Lavender
    )
}

/// Gruvbox Light - Warm retro light theme
/// Cream backgrounds with earthy warm accents
pub fn gruvbox_light() -> AppTheme {
    AppTheme::from_hex(
        "Gruvbox Light",
        0x00FB_F1C7, // bg_base - Light cream background
        0x00F9_F5D7, // bg_sidebar - Lighter cream
        0x00EB_DBB2, // bg_surface - Card surface
        0x00D5_C4A1, // bg_elevated - Elevated elements
        0x00BD_AE93, // bg_hover - Hover state
        0x00A8_9984, // bg_active - Active selection
        0x003C_3836, // fg_primary - Dark brown text
        0x005A_524C, // fg_secondary - Brown gray
        0x007C_6F64, // fg_muted - Light brown
        0x00FB_F1C7, // fg_on_accent - Light on accent
        0x00AF_3A03, // accent - Dark orange
        0x00D6_5D0E, // accent_hover - Brighter orange
        0x0079_740E, // success - Dark green
        0x00B5_7614, // warning - Dark yellow
        0x009D_0006, // danger - Dark red
        0x0042_7B58, // info - Dark aqua
        0x00D5_C4A1, // border - Subtle border
        0x00AF_3A03, // border_strong - Orange border
        0x00EB_DBB2, // divider - Match surface
        0x009D_0006, // syntax_keyword - Dark red
        0x0076_678E, // syntax_type - Dark purple
        0x0079_740E, // syntax_string - Dark green
        0x00AF_3A03, // syntax_number - Dark orange
        0x0092_8374, // syntax_comment - Gray
        0x00AF_3A03, // syntax_operator - Orange
    )
}

/// GitHub Light - Clean, professional light theme
/// Pure white backgrounds with GitHub's signature blue and green
pub fn github_light() -> AppTheme {
    AppTheme::from_hex(
        "GitHub Light",
        0x00FF_FFFF, // bg_base - Pure white
        0x00F6_F8FA, // bg_sidebar - Light gray
        0x00F6_F8FA, // bg_surface - Card surface
        0x00E1_E4E8, // bg_elevated - Elevated elements
        0x00D0_D7DE, // bg_hover - Hover state
        0x00AC_B6BF, // bg_active - Active selection
        0x0024_292F, // fg_primary - Dark text
        0x0057_606A, // fg_secondary - Gray text
        0x0066_6E76, // fg_muted - Light gray
        0x00FF_FFFF, // fg_on_accent - White on accent
        0x0009_69DA, // accent - GitHub blue
        0x001F_6FEB, // accent_hover - Brighter blue
        0x001A_7F37, // success - GitHub green
        0x009A_6700, // warning - Orange
        0x00CF_222E, // danger - GitHub red
        0x0009_69DA, // info - Blue
        0x00D0_D7DE, // border - Light border
        0x0009_69DA, // border_strong - Blue border
        0x00D8_DEE4, // divider - Match elevated
        0x00CF_222E, // syntax_keyword - Red
        0x0009_69DA, // syntax_type - Blue
        0x000A_3069, // syntax_string - Dark green
        0x0005_50AE, // syntax_number - Purple
        0x0057_606A, // syntax_comment - Gray
        0x00CF_222E, // syntax_operator - Red
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_themes_have_names() {
        let themes = [
            oxide(),
            aethel(),
            nord(),
            gruvbox(),
            gruvbox_light(),
            dracula(),
            monokai(),
            everforest(),
            tokyo_night(),
            catppuccin_mocha(),
            catppuccin_latte(),
            one_dark(),
            solarized_dark(),
            ayu_dark(),
            rose_pine(),
            material_theme(),
            github_light(),
        ];

        for theme in &themes {
            assert!(!theme.name.is_empty());
        }
    }

    #[test]
    fn test_theme_colors_are_valid() {
        // Just verify themes can be created without panicking
        let _ = oxide();
        let _ = aethel();
        let _ = nord();
        let _ = gruvbox();
        let _ = gruvbox_light();
        let _ = dracula();
        let _ = monokai();
        let _ = everforest();
        let _ = tokyo_night();
        let _ = catppuccin_mocha();
        let _ = catppuccin_latte();
        let _ = one_dark();
        let _ = solarized_dark();
        let _ = ayu_dark();
        let _ = rose_pine();
        let _ = material_theme();
        let _ = github_light();
    }
}
