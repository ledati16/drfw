//! The "Add from template" menu: which rule templates apply to this
//! computer, as the sidebar shows them
//!
//! [`crate::core::templates::available_templates`] decides which templates
//! the current interfaces call for, and [`TemplateKind`] gives their title,
//! description and rules (one source of truth). This module only keeps the
//! menu's text, built when the menu opens (in `update()`), never in
//! `view()`. The rules are made when an entry is chosen, so every use gets
//! fresh ids.

use crate::core::firewall::Rule;
use crate::core::templates::{self, TemplateKind};

/// The open menu.
#[derive(Debug, Clone, Default)]
pub struct TemplateMenu {
    /// One entry per template that applies (empty: none does)
    pub entries: Vec<TemplateEntry>,
}

/// One menu entry, all text pre-formatted.
#[derive(Debug, Clone)]
pub struct TemplateEntry {
    pub kind: TemplateKind,
    /// [`TemplateKind::title`], e.g. "VM guests: DHCP and DNS on virbr0"
    pub title: String,
    /// [`TemplateKind::description`]
    pub detail: &'static str,
}

/// Shown in the menu when no template applies.
pub const NO_TEMPLATES: &str = "No templates for this computer's network interfaces. \
     Templates appear for libvirt bridges (virbr*) and Tailscale (tailscale0).";

impl TemplateMenu {
    /// The entries for the interfaces in `interfaces`.
    pub fn for_interfaces(interfaces: &[String]) -> Self {
        Self {
            entries: templates::available_templates(interfaces)
                .into_iter()
                .map(|kind| TemplateEntry {
                    title: kind.title(),
                    detail: kind.description(),
                    kind,
                })
                .collect(),
        }
    }
}

impl TemplateEntry {
    /// The template's rules, with fresh ids.
    pub fn rules(&self) -> Vec<Rule> {
        self.kind.rules()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn test_menu_only_offers_templates_for_present_interfaces() {
        let menu = TemplateMenu::for_interfaces(&names(&["eth0", "wlan0"]));
        assert_eq!(menu.entries.len(), 0);

        let menu = TemplateMenu::for_interfaces(&names(&["eth0", "virbr0"]));
        let titles: Vec<&str> = menu.entries.iter().map(|e| e.title.as_str()).collect();
        assert_eq!(titles, ["VM guests: DHCP and DNS on virbr0"]);

        let menu = TemplateMenu::for_interfaces(&names(&["eth0", "tailscale0"]));
        let titles: Vec<&str> = menu.entries.iter().map(|e| e.title.as_str()).collect();
        assert_eq!(
            titles,
            ["Tailscale: direct connections", "Trust tailscale0"]
        );
    }

    #[test]
    fn test_entry_rules_are_fresh_each_time() {
        let menu = TemplateMenu::for_interfaces(&names(&["virbr0"]));
        let first = menu.entries[0].rules();
        let second = menu.entries[0].rules();
        assert_eq!(first.len(), 2, "UDP and TCP");
        assert!(
            first.iter().all(|a| second.iter().all(|b| a.id != b.id)),
            "fresh ids"
        );
        assert!(
            first
                .iter()
                .all(|r| r.interface.as_deref() == Some("virbr0"))
        );
    }
}
