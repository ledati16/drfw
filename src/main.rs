mod app;
mod audit;
mod command;
mod config;
mod core;
mod elevation;
mod theme;
mod utils;
mod validators;

use iced::Size;

fn main() -> iced::Result {
    let _ = crate::utils::ensure_dirs();

    // Set up logging to file
    if let Some(mut log_path) = crate::utils::get_state_dir() {
        log_path.push("drfw.log");
        if let Ok(file) = std::fs::File::create(log_path) {
            tracing_subscriber::fmt().with_writer(file).init();
        } else {
            tracing_subscriber::fmt::init();
        }
    } else {
        tracing_subscriber::fmt::init();
    }

    iced::application("DRFW — Dumb Rust Firewall", app::State::update, app::view)
        .subscription(app::State::subscription)
        .window(iced::window::Settings {
            size: Size::new(1000.0, 700.0),
            ..Default::default()
        })
        .theme(|_| iced::Theme::Dark)
        .run_with(app::State::new)
}
