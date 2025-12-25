use iced::widget::{button, container};
use iced::{Border, Color, Shadow, Theme, Vector};

// Gruvbox Dark Palette
pub const GRUV_BG0: Color = Color::from_rgb(0.157, 0.157, 0.157); // #282828
pub const GRUV_BG1: Color = Color::from_rgb(0.235, 0.219, 0.212); // #3c3836
pub const GRUV_BG2: Color = Color::from_rgb(0.314, 0.286, 0.271); // #504945
pub const GRUV_FG0: Color = Color::from_rgb(0.984, 0.945, 0.780); // #fbf1c7
pub const GRUV_FG4: Color = Color::from_rgb(0.659, 0.600, 0.518); // #a89984

pub const GRUV_RED: Color = Color::from_rgb(0.800, 0.141, 0.114); // #cc241d
pub const GRUV_GREEN: Color = Color::from_rgb(0.596, 0.592, 0.102); // #98971a
pub const GRUV_YELLOW: Color = Color::from_rgb(0.839, 0.514, 0.086); // #d79921
pub const GRUV_BLUE: Color = Color::from_rgb(0.271, 0.447, 0.475); // #458588
pub const GRUV_PURPLE: Color = Color::from_rgb(0.690, 0.384, 0.525); // #b16286
pub const GRUV_AQUA: Color = Color::from_rgb(0.424, 0.588, 0.522); // #689d6a
pub const GRUV_ORANGE: Color = Color::from_rgb(0.839, 0.302, 0.051); // #d65d0e

pub const BG_MAIN: Color = GRUV_BG0;
pub const BG_SIDEBAR: Color = Color::from_rgb(0.114, 0.114, 0.114);
pub const ACCENT: Color = GRUV_YELLOW;
pub const SUCCESS: Color = GRUV_GREEN;
pub const DANGER: Color = GRUV_RED;
pub const TEXT_BRIGHT: Color = GRUV_FG0;
pub const TEXT_DIM: Color = GRUV_FG4;

pub fn main_container(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(BG_MAIN.into()),
        text_color: Some(TEXT_BRIGHT),
        ..Default::default()
    }
}

pub fn sidebar_container(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(BG_SIDEBAR.into()),
        border: Border {
            color: GRUV_BG1,
            width: 0.0,
            radius: 0.0.into(),
        },
        ..Default::default()
    }
}

pub fn card_container(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(GRUV_BG1.into()),
        border: Border {
            color: GRUV_BG2,
            width: 1.0,
            radius: 8.0.into(),
        },
        shadow: Shadow {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.5),
            offset: Vector::new(0.0, 2.0),
            blur_radius: 4.0,
        },
        ..Default::default()
    }
}

pub fn active_card_container(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(GRUV_BG2.into()),
        border: Border {
            color: GRUV_AQUA,
            width: 1.0,
            radius: 8.0.into(),
        },
        ..Default::default()
    }
}

pub fn hovered_card_container(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Color::from_rgb(0.28, 0.26, 0.25).into()),
        border: Border {
            color: GRUV_BG2,
            width: 1.0,
            radius: 8.0.into(),
        },
        shadow: Shadow {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.6),
            offset: Vector::new(0.0, 3.0),
            blur_radius: 6.0,
        },
        ..Default::default()
    }
}

pub fn section_header_container(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Color::from_rgba(1.0, 1.0, 1.0, 0.02).into()),
        border: Border {
            radius: 4.0.into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

pub fn pill_container(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Color::from_rgba(1.0, 1.0, 1.0, 0.05).into()),
        border: Border {
            radius: 20.0.into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

pub fn primary_button(_theme: &Theme, status: button::Status) -> button::Style {
    let base = button::Style {
        background: Some(GRUV_AQUA.into()),
        text_color: GRUV_BG0,
        border: Border {
            radius: 4.0.into(),
            ..Default::default()
        },
        ..Default::default()
    };

    match status {
        button::Status::Hovered => button::Style {
            background: Some(Color::from_rgb(0.55, 0.75, 0.65).into()),
            ..base
        },
        button::Status::Pressed => button::Style {
            background: Some(Color::from_rgb(0.3, 0.5, 0.4).into()),
            ..base
        },
        _ => base,
    }
}

pub fn dirty_button(theme: &Theme, status: button::Status) -> button::Style {
    let mut style = primary_button(theme, status);
    style.shadow = Shadow {
        color: Color::from_rgba(GRUV_YELLOW.r, GRUV_YELLOW.g, GRUV_YELLOW.b, 0.2),
        offset: Vector::new(0.0, 0.0),
        blur_radius: 8.0,
    };
    style.border.width = 2.0;
    style.border.color = GRUV_YELLOW;
    style
}

pub fn danger_button(_theme: &Theme, status: button::Status) -> button::Style {
    let base = button::Style {
        background: Some(GRUV_RED.into()),
        text_color: GRUV_FG0,
        border: Border {
            radius: 4.0.into(),
            ..Default::default()
        },
        ..Default::default()
    };

    match status {
        button::Status::Hovered => button::Style {
            background: Some(Color::from_rgb(0.9, 0.3, 0.2).into()),
            ..base
        },
        _ => base,
    }
}

pub fn card_button(theme: &Theme, _status: button::Status) -> button::Style {
    let c = card_container(theme);
    button::Style {
        background: c.background,
        text_color: GRUV_FG0,
        border: c.border,
        shadow: c.shadow,
    }
}

pub fn hovered_card_button(theme: &Theme, _status: button::Status) -> button::Style {
    let c = hovered_card_container(theme);
    button::Style {
        background: c.background,
        text_color: GRUV_FG0,
        border: c.border,
        shadow: c.shadow,
    }
}

pub fn active_card_button(theme: &Theme, _status: button::Status) -> button::Style {
    let c = active_card_container(theme);
    button::Style {
        background: c.background,
        text_color: GRUV_FG0,
        border: c.border,
        shadow: c.shadow,
    }
}

pub fn active_tab_button(theme: &Theme, status: button::Status) -> button::Style {
    let mut style = button::secondary(theme, status);

    style.background = Some(GRUV_BG2.into());

    style.text_color = TEXT_BRIGHT;

    style.border.radius = 4.0.into();

    style
}
