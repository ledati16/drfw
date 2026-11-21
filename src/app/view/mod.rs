//! UI rendering module for DRFW
//!
//! Split into logical submodules for maintainability.

// Widget IDs for state preservation
pub const SIDEBAR_SCROLLABLE_ID: &str = "sidebar-rule-list";
pub const SIDEBAR_TAGS_SCROLLABLE_ID: &str = "sidebar-tags";
pub const WORKSPACE_SCROLLABLE_ID: &str = "workspace-preview";

// Submodule declarations
mod confirmation;
mod diagnostics;
mod exposure;
mod helper_modals;
mod modals;
mod pickers;
mod profile;
mod rule_form;
mod settings;
mod shortcuts;
mod sidebar;
mod syntax;
mod verify_errors;
mod workspace;

// Shared imports used by main view function
use iced::widget::{Space, center, column, container, opaque, stack};
use iced::{Element, Length, alignment};

use crate::app::ui_components::{main_container, modal_backdrop, notification_banner};
use crate::app::{AppStatus, Message, State, WorkspaceTab};

/// Width of the "+"/"-" marker column of the diff view, in pixels.
pub const DIFF_GUTTER_WIDTH_PX: f32 = 18.0;

/// The layers drawn over the sidebar and workspace (see [`LAYERS`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Layer {
    /// The Exposure panel, below every dialog: a rule opened from it is
    /// edited on top of it
    Exposure,
    /// The main-flow dialog: one of "Start fresh?", a risky-setting warning,
    /// the rule form, the apply flow, Save to System, or the verification
    /// errors (the first open one, in that order)
    Dialog,
    /// Port/address/tag helper over the rule form
    Helper,
    Diagnostics,
    Export,
    FontPicker,
    ThemePicker,
    ProfileManager,
    /// "Unsaved changes" before a profile switch (hides the profile manager)
    ProfileSwitchConfirm,
    ShortcutsHelp,
    /// "Your changes could not be saved" after a close request
    CloseFailed,
    /// Notifications, above every dialog so none hides an error
    Banners,
}

/// Draw order of the layers, bottom to top. Must agree with
/// `handlers::top_layer` (which decides what Escape/Enter act on); a test
/// checks that it does.
pub(crate) const LAYERS: [Layer; 12] = [
    Layer::Exposure,
    Layer::Dialog,
    Layer::Helper,
    Layer::Diagnostics,
    Layer::Export,
    Layer::FontPicker,
    Layer::ThemePicker,
    Layer::ProfileManager,
    Layer::ProfileSwitchConfirm,
    Layer::ShortcutsHelp,
    Layer::CloseFailed,
    Layer::Banners,
];

/// Main view entry point
pub fn view(state: &State) -> Element<'_, Message> {
    let theme = &state.theme;

    let sidebar = sidebar::view_sidebar(state);
    let workspace = workspace::view_workspace(state, preview_content(state));
    let content = iced::widget::row![sidebar, workspace];

    let mut root: Element<'_, Message> = container(content)
        .width(Length::Fill)
        .height(Length::Fill)
        .style(move |_| main_container(theme))
        .into();

    // IMPORTANT: every layer is always a stack level (an empty Space when
    // closed), so the widget tree keeps its shape and scroll state survives
    for layer in LAYERS {
        let top = layer_element(state, layer).unwrap_or_else(|| Space::new().into());
        root = stack![root, top].into();
    }
    root
}

/// The ruleset preview: the diff when it is enabled and there is one, the
/// plain ruleset otherwise. Clicks on its lines are resolved against the
/// same choice (`handlers::ui_state::preview_line`).
fn preview_content(state: &State) -> Element<'_, Message> {
    let theme = &state.theme;
    match state.active_tab {
        WorkspaceTab::Nftables => match (state.show_diff, &state.cached_diff_tokens) {
            (true, Some(diff_tokens)) => container(syntax::view_from_cached_diff_tokens(
                diff_tokens,
                theme,
                state.font_mono,
                state.show_zebra_striping,
                state.cached_diff_width_px,
            ))
            .width(Length::Fill)
            .into(),
            // Diff disabled, or no changes: the pre-tokenized ruleset
            _ => container(syntax::view_from_cached_nft_tokens(
                &state.cached_nft_tokens,
                theme,
                state.font_mono,
                state.show_zebra_striping,
                state.cached_nft_width_px,
            ))
            .width(Length::Fill)
            .into(),
        },
        WorkspaceTab::Settings => container(settings::view_settings(state))
            .width(Length::Fill)
            .into(),
    }
}

/// A modal: centered on a backdrop that fades and blocks what is beneath.
fn modal<'a>(state: &'a State, content: Element<'a, Message>) -> Element<'a, Message> {
    let theme = &state.theme;
    opaque(center(content).style(move |_| modal_backdrop(theme)))
}

/// The content of `layer`, or `None` when it is closed.
pub(crate) fn layer_element(state: &State, layer: Layer) -> Option<Element<'_, Message>> {
    let theme = &state.theme;
    let content: Element<'_, Message> = match layer {
        Layer::Exposure => exposure::view_exposure_modal(
            state.exposure.panel.as_ref()?,
            theme,
            state.font_regular,
            state.font_mono,
        ),
        Layer::Dialog => dialog(state)?,
        Layer::Helper => {
            let (Some(form), Some(helper)) = (&state.rule_form, &state.rule_form_helper) else {
                return None;
            };
            helper.helper_type?;
            helper_modals::view_helper_modal(
                form,
                helper,
                theme,
                state.font_regular,
                state.font_mono,
            )
        }
        Layer::Diagnostics if state.show_diagnostics => {
            diagnostics::view_diagnostics_modal(state, theme, state.font_regular, state.font_mono)
        }
        Layer::Export if state.show_export_modal => {
            modals::view_export_modal(theme, state.font_regular, state.export_in_progress)
        }
        Layer::FontPicker => pickers::view_font_picker(state, state.font_picker.as_ref()?),
        Layer::ThemePicker => pickers::view_theme_picker(state, state.theme_picker.as_ref()?),
        Layer::ProfileManager if state.pending_profile_switch.is_none() => {
            profile::view_profile_manager(state, state.profile_manager.as_ref()?)
        }
        Layer::ProfileSwitchConfirm if state.pending_profile_switch.is_some() => {
            profile::view_profile_switch_confirm(theme, state.font_regular)
        }
        Layer::ShortcutsHelp if state.show_shortcuts_help => {
            shortcuts::view_shortcuts_help(theme, state.font_regular, state.font_mono)
        }
        Layer::CloseFailed => {
            modals::view_close_failed(state.close_error.as_deref()?, theme, state.font_regular)
        }
        Layer::Banners => return banners(state),
        _ => return None,
    };
    Some(modal(state, content))
}

/// The main-flow dialog, if one is open (see [`Layer::Dialog`]).
fn dialog(state: &State) -> Option<Element<'_, Message>> {
    let theme = &state.theme;
    if state.confirm_start_fresh
        && let Some(issue) = &state.unreadable_profile
    {
        return Some(profile::view_start_fresh_confirm(
            issue,
            theme,
            state.font_regular,
        ));
    }
    if let Some(warning) = &state.pending_warning {
        return Some(modals::view_warning_modal(
            warning,
            theme,
            state.font_regular,
        ));
    }
    if let Some(form) = &state.rule_form {
        return Some(rule_form::view_rule_form(
            form,
            state.form_errors.as_ref(),
            &state.interface_combo,
            &state.output_interface_combo,
            theme,
            state.font_regular,
            state.font_mono,
            state.ruleset.advanced_security.egress_profile
                == crate::core::firewall::EgressProfile::Server,
            state.confirm_discard_form,
        ));
    }
    match &state.status {
        AppStatus::AwaitingApply | AppStatus::Applying | AppStatus::PendingConfirmation { .. } => {
            Some(confirmation::view_apply_flow_modal(
                &state.status,
                state.apply_session.as_ref(),
                state.auto_revert_enabled,
                &state.settings_display.apply_timer_secs,
                &state.countdown_display,
                state.countdown_remaining,
                state
                    .progress_animation
                    .interpolate_with(|v| v, iced::time::Instant::now()),
                theme,
                state.font_regular,
            ))
        }
        AppStatus::AwaitingSaveToSystem => Some(confirmation::view_save_to_system_modal(
            &state.save_dialog,
            theme,
            state.font_regular,
        )),
        // Below the rule form (opened from it) and the apply flow
        _ => state
            .verify_errors
            .as_ref()
            .filter(|_| state.show_verify_errors)
            .map(|panel| {
                verify_errors::view_verify_errors_modal(
                    panel,
                    theme,
                    state.font_regular,
                    state.font_mono,
                )
            }),
    }
}

/// Notification banners, free-floating at the top right (not modal: only the
/// banners themselves take clicks, to dismiss them).
fn banners(state: &State) -> Option<Element<'_, Message>> {
    if state.banners.is_empty() {
        return None;
    }
    let banner_column = column(
        state
            .banners
            .iter()
            .take(2)
            .enumerate()
            .map(|(index, banner)| {
                notification_banner(
                    banner,
                    &state.theme,
                    index,
                    state.font_regular,
                    state.font_mono,
                )
            }),
    )
    .spacing(8)
    .width(Length::Shrink)
    .padding(16)
    .align_x(alignment::Horizontal::Right);

    Some(
        container(banner_column)
            .width(Length::Fill)
            .height(Length::Shrink)
            .align_x(alignment::Horizontal::Right)
            .align_y(alignment::Vertical::Top)
            .into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::handlers::test_utils::create_test_state;
    use crate::app::handlers::{TopLayer, top_layer};

    /// The layer a [`TopLayer`] is drawn in (`None`: the base content).
    fn layer_of(top: TopLayer) -> Option<Layer> {
        Some(match top {
            TopLayer::CloseFailed => Layer::CloseFailed,
            TopLayer::ShortcutsHelp => Layer::ShortcutsHelp,
            TopLayer::ProfileSwitchConfirm => Layer::ProfileSwitchConfirm,
            TopLayer::ProfileManager => Layer::ProfileManager,
            TopLayer::ThemePicker => Layer::ThemePicker,
            TopLayer::FontPicker => Layer::FontPicker,
            TopLayer::ExportModal => Layer::Export,
            TopLayer::Diagnostics => Layer::Diagnostics,
            TopLayer::HelperModal => Layer::Helper,
            TopLayer::Exposure => Layer::Exposure,
            TopLayer::StartFreshConfirm
            | TopLayer::Warning
            | TopLayer::RuleForm
            | TopLayer::ApplyFlow
            | TopLayer::SaveToSystem
            | TopLayer::VerifyErrors => Layer::Dialog,
            TopLayer::Base => return None,
        })
    }

    /// The open layers, bottom to top, as the view stacks them.
    fn visible_layers(state: &State) -> Vec<Layer> {
        LAYERS
            .into_iter()
            .filter(|&layer| layer_element(state, layer).is_some())
            .collect()
    }

    /// The top-most drawn dialog is the one Escape/Enter act on, and the
    /// banners are drawn above all of them.
    #[test]
    fn test_draw_order_matches_top_layer_and_banners_are_on_top() {
        let mut state = create_test_state();
        state.push_banner("Could not save", crate::app::BannerSeverity::Error);
        let check = |state: &State| {
            let visible = visible_layers(state);
            assert_eq!(visible.last(), Some(&Layer::Banners), "{visible:?}");
            let top_dialog = visible.iter().rev().nth(1).copied();
            assert_eq!(top_dialog, layer_of(top_layer(state)), "{visible:?}");
        };
        check(&state);

        let _ = crate::app::handlers::handle_toggle_exposure(&mut state, true);
        check(&state);
        state.verify_errors = Some(crate::app::verify_errors::VerifyErrorsPanel::new(
            &crate::core::verify::VerifyResult::failure(vec![
                crate::core::verify::VerifyIssue::unlocated("bad"),
            ]),
            &state.ruleset,
        ));
        state.show_verify_errors = true;
        check(&state);
        state.rule_form = Some(crate::app::RuleForm::default());
        check(&state);
        state.rule_form_helper = Some(crate::app::RuleFormHelper {
            helper_type: Some(crate::app::HelperType::Ports),
            ..Default::default()
        });
        check(&state);
        state.show_diagnostics = true;
        check(&state);
        state.show_export_modal = true;
        check(&state);
        let _ = crate::app::handlers::handle_open_theme_picker(&mut state);
        check(&state);
        crate::app::handlers::handle_open_profile_manager(&mut state);
        check(&state);
        state.pending_profile_switch = Some("other".into());
        check(&state);
        state.show_shortcuts_help = true;
        check(&state);
        state.close_error = Some("disk full".into());
        check(&state);
    }

    #[test]
    fn test_banners_are_the_top_layer() {
        assert_eq!(LAYERS.last(), Some(&Layer::Banners));
    }
}
