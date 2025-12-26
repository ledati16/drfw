use iced::Font;
use serde::{Deserialize, Serialize};

/// Font choices for the UI
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum RegularFontChoice {
    #[default]
    SystemDefault,
    Inter,
    RobotoRegular,
    SegoeUI,
    SanFrancisco,
    Ubuntu,
}

impl RegularFontChoice {
    pub fn all() -> Vec<Self> {
        vec![
            Self::SystemDefault,
            Self::Inter,
            Self::RobotoRegular,
            Self::SegoeUI,
            Self::SanFrancisco,
            Self::Ubuntu,
        ]
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::SystemDefault => "System Default",
            Self::Inter => "Inter",
            Self::RobotoRegular => "Roboto",
            Self::SegoeUI => "Segoe UI",
            Self::SanFrancisco => "San Francisco",
            Self::Ubuntu => "Ubuntu",
        }
    }

    pub const fn to_font(self) -> Font {
        match self {
            Self::SystemDefault => Font::DEFAULT,
            Self::Inter => Font::with_name("Inter"),
            Self::RobotoRegular => Font::with_name("Roboto"),
            Self::SegoeUI => Font::with_name("Segoe UI"),
            Self::SanFrancisco => Font::with_name("San Francisco"),
            Self::Ubuntu => Font::with_name("Ubuntu"),
        }
    }
}

impl std::fmt::Display for RegularFontChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Monospace font choices for code display
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum MonoFontChoice {
    #[default]
    SystemMonospace,
    FiraCode,
    JetBrainsMono,
    SourceCodePro,
    CascadiaCode,
    UbuntuMono,
}

impl MonoFontChoice {
    pub fn all() -> Vec<Self> {
        vec![
            Self::SystemMonospace,
            Self::FiraCode,
            Self::JetBrainsMono,
            Self::SourceCodePro,
            Self::CascadiaCode,
            Self::UbuntuMono,
        ]
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::SystemMonospace => "System Monospace",
            Self::FiraCode => "Fira Code",
            Self::JetBrainsMono => "JetBrains Mono",
            Self::SourceCodePro => "Source Code Pro",
            Self::CascadiaCode => "Cascadia Code",
            Self::UbuntuMono => "Ubuntu Mono",
        }
    }

    pub const fn to_font(self) -> Font {
        match self {
            Self::SystemMonospace => Font::MONOSPACE,
            Self::FiraCode => Font::with_name("Fira Code"),
            Self::JetBrainsMono => Font::with_name("JetBrains Mono"),
            Self::SourceCodePro => Font::with_name("Source Code Pro"),
            Self::CascadiaCode => Font::with_name("Cascadia Code"),
            Self::UbuntuMono => Font::with_name("Ubuntu Mono"),
        }
    }
}

impl std::fmt::Display for MonoFontChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}
