//! UI rendering module for DRFW
//!
//! Split into logical submodules for maintainability.

// Text input IDs for focus management
pub const FONT_SEARCH_INPUT_ID: &str = "font-search-input";

// Submodule declarations
mod confirmation;
mod diagnostics;
mod helper_modals;
mod modals;
mod pickers;
mod profile;
mod rule_form;
mod settings;
mod shortcuts;
mod sidebar;
mod syntax;
mod workspace;

// Shared imports used by main view function
use crate::app::ui_components::{main_container, modal_backdrop, notification_banner};
use crate::app::{AppStatus, Message, State, WorkspaceTab};
use iced::widget::{column, container, stack};
use iced::{Alignment, Element, Length, alignment};

/// Main view entry point
pub fn view(state: &State) -> Element<'_, Message> {
    let theme = &state.theme;

    let sidebar = sidebar::view_sidebar(state);

    let preview_content: Element<'_, Message> = match state.active_tab {
        WorkspaceTab::Nftables => {
            // Phase 1 Optimized: Use pre-cached diff tokens (no computation in view!)
            if state.show_diff {
                if let Some(ref diff_tokens) = state.cached_diff_tokens {
                    container(syntax::view_from_cached_diff_tokens(
                        diff_tokens,
                        theme,
                        state.font_mono,
                        state.show_zebra_striping,
                        state.cached_diff_width_px, // Dynamic width for diff view
                    ))
                    .width(Length::Fill)
                    .into()
                } else {
                    // No changes - show normal view
                    container(syntax::view_from_cached_nft_tokens(
                        &state.cached_nft_tokens,
                        theme,
                        state.font_mono,
                        state.show_zebra_striping,
                        state.cached_nft_width_px, // Dynamic width for NFT view
                    ))
                    .width(Length::Fill)
                    .into()
                }
            } else {
                // Diff disabled - use pre-tokenized cache (60-80% CPU savings)
                container(syntax::view_from_cached_nft_tokens(
                    &state.cached_nft_tokens,
                    theme,
                    state.font_mono,
                    state.show_zebra_striping,
                    state.cached_nft_width_px, // Dynamic width for NFT view
                ))
                .width(Length::Fill)
                .into()
            }
        }
        WorkspaceTab::Settings => container(settings::view_settings(state))
            .width(Length::Fill)
            .into(),
    };

    let workspace = workspace::view_workspace(state, preview_content);

    let content = iced::widget::row![sidebar, workspace];

    let overlay = if let Some(warning) = &state.pending_warning {
        Some(
            container(modals::view_warning_modal(
                warning,
                theme,
                state.font_regular,
            ))
            .style(move |_| modal_backdrop(theme))
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x(Length::Fill)
            .center_y(Length::Fill),
        )
    } else if let Some(form) = &state.rule_form {
        Some(
            container(rule_form::view_rule_form(
                form,
                state.form_errors.as_ref(),
                &state.interface_combo_state,
                &state.output_interface_combo_state,
                theme,
                state.font_regular,
                state.font_mono,
                state.ruleset.advanced_security.egress_profile
                    == crate::core::firewall::EgressProfile::Server,
            ))
            .style(move |_| modal_backdrop(theme))
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x(Length::Fill)
            .center_y(Length::Fill),
        )
    } else {
        match &state.status {
            AppStatus::AwaitingApply
            | AppStatus::Applying
            | AppStatus::PendingConfirmation { .. } => Some(
                container(confirmation::view_apply_flow_modal(
                    &state.status,
                    state.auto_revert_enabled,
                    state.auto_revert_timeout_secs,
                    state.countdown_remaining,
                    state
                        .progress_animation
                        .interpolate_with(|v| v, iced::time::Instant::now()),
                    theme,
                    state.font_regular,
                ))
                .style(move |_| modal_backdrop(theme))
                .width(Length::Fill)
                .height(Length::Fill)
                .center_x(Length::Fill)
                .center_y(Length::Fill),
            ),
            _ => None,
        }
    };

    let base = container(content)
        .width(Length::Fill)
        .height(Length::Fill)
        .style(move |_| main_container(theme));

    // Modal overlay layer (fades base content)
    let with_overlay = if let Some(overlay) = overlay {
        stack![base, overlay].into()
    } else {
        base.into()
    };

    // Helper modal layer (appears on top of rule form when editing multi-value fields)
    let with_helper: Element<'_, Message> =
        if let (Some(form), Some(helper)) = (&state.rule_form, &state.rule_form_helper) {
            if helper.helper_type.is_some() {
                stack![
                    with_overlay,
                    container(helper_modals::view_helper_modal(
                        form,
                        helper,
                        theme,
                        state.font_regular,
                        state.font_mono,
                    ))
                    .style(move |_| modal_backdrop(theme))
                    .width(Length::Fill)
                    .height(Length::Fill)
                    .center_x(Length::Fill)
                    .center_y(Length::Fill)
                ]
                .into()
            } else {
                with_overlay
            }
        } else {
            with_overlay
        };

    // Banner overlay layer (free-floating at top-right, ABOVE modal backdrop)
    let with_banners: Element<'_, Message> = if state.banners.is_empty() {
        with_helper
    } else {
        let banner_column = column(
            state
                .banners
                .iter()
                .take(2)
                .enumerate()
                .map(|(index, banner)| notification_banner(banner, theme, index))
                .collect::<Vec<_>>(),
        )
        .spacing(8)
        .width(Length::Shrink)
        .padding(16);

        stack![
            with_helper,
            container(banner_column)
                .width(Length::Fill)
                .height(Length::Shrink)
                .align_x(alignment::Horizontal::Right)
                .align_y(alignment::Vertical::Top)
        ]
        .into()
    };

    // Diagnostics modal overlay (on top of everything)
    let with_diagnostics = if state.show_diagnostics {
        stack![
            with_banners,
            container(diagnostics::view_diagnostics_modal(
                state,
                theme,
                state.font_regular,
                state.font_mono
            ))
            .style(move |_| modal_backdrop(theme))
            .width(Length::Fill)
            .height(Length::Fill)
            .align_x(Alignment::Center)
            .align_y(Alignment::Center)
        ]
        .into()
    } else {
        with_banners
    };

    // Export modal overlay
    let with_export = if state.show_export_modal {
        stack![
            with_diagnostics,
            container(modals::view_export_modal(theme, state.font_regular))
                .style(move |_| modal_backdrop(theme))
                .width(Length::Fill)
                .height(Length::Fill)
                .align_x(Alignment::Center)
                .align_y(Alignment::Center)
        ]
        .into()
    } else {
        with_diagnostics
    };

    // Font picker modal overlay
    let with_font_picker = if let Some(ref picker_state) = state.font_picker {
        stack![
            with_export,
            container(pickers::view_font_picker(state, picker_state))
                .style(move |_| modal_backdrop(theme))
                .width(Length::Fill)
                .height(Length::Fill)
                .align_x(Alignment::Center)
                .align_y(Alignment::Center)
        ]
        .into()
    } else {
        with_export
    };

    // Theme picker modal overlay
    let with_theme_picker = if let Some(ref picker_state) = state.theme_picker {
        stack![
            with_font_picker,
            container(pickers::view_theme_picker(state, picker_state))
                .style(move |_| modal_backdrop(theme))
                .width(Length::Fill)
                .height(Length::Fill)
                .align_x(Alignment::Center)
                .align_y(Alignment::Center)
        ]
        .into()
    } else {
        with_font_picker
    };

    // Profile switch confirmation overlay
    let with_profile_confirm = if state.pending_profile_switch.is_some() {
        stack![
            with_theme_picker,
            container(profile::view_profile_switch_confirm(
                theme,
                state.font_regular
            ))
            .style(move |_| modal_backdrop(theme))
            .width(Length::Fill)
            .height(Length::Fill)
            .align_x(Alignment::Center)
            .align_y(Alignment::Center)
        ]
        .into()
    } else {
        with_theme_picker
    };

    // Profile manager modal overlay (hide when profile switch confirmation is active)
    let with_profile_manager = if let Some(ref mgr_state) = state.profile_manager
        && state.pending_profile_switch.is_none()
    {
        stack![
            with_profile_confirm,
            container(profile::view_profile_manager(state, mgr_state))
                .style(move |_| modal_backdrop(theme))
                .width(Length::Fill)
                .height(Length::Fill)
                .align_x(Alignment::Center)
                .align_y(Alignment::Center)
        ]
        .into()
    } else {
        with_profile_confirm
    };

    // Keyboard shortcuts help overlay
    if state.show_shortcuts_help {
        stack![
            with_profile_manager,
            container(shortcuts::view_shortcuts_help(
                theme,
                state.font_regular,
                state.font_mono
            ))
            .style(move |_| modal_backdrop(theme))
            .width(Length::Fill)
            .height(Length::Fill)
            .align_x(Alignment::Center)
            .align_y(Alignment::Center)
        ]
        .into()
    } else {
        with_profile_manager
    }
}
