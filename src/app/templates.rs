//! The "Add from template" menu: which rule templates apply to this
//! computer, as the sidebar shows them
//!
//! [`crate::core::templates::available_templates`] decides which templates
//! the current interfaces call for, and [`TemplateKind`] gives their title,
//! description and rules (one source of truth). This module only keeps the
//! menu's text, built when the menu opens (in `update()`), never in
//! `view()`. The rules are made when an entry is chosen, so every use gets
//! fresh ids.

use crate::core::firewall::{EgressProfile, FirewallRuleset, Rule};
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
    /// What else the profile's settings call for ("In Server Mode …"),
    /// one line each; empty when nothing
    pub notes: Vec<String>,
    /// Every rule of the template is in the profile already (same label,
    /// chain and interface): the entry is shown disabled, so it is not
    /// added twice
    pub already_added: bool,
}

/// Shown instead of adding a template whose rules are all in the profile.
pub const ALREADY_ADDED: &str = "Already in this profile.";

/// Shown in the menu when no template applies.
pub const NO_TEMPLATES: &str = "No templates for this computer's network interfaces. \
     Templates appear for libvirt bridges (virbr*) and Tailscale (tailscale0).";

impl TemplateMenu {
    /// The entries for the interfaces in `interfaces`, with the notes and
    /// duplicate check for `ruleset` (the profile they would be added to).
    pub fn for_interfaces(interfaces: &[String], ruleset: &FirewallRuleset) -> Self {
        Self {
            entries: templates::available_templates(interfaces)
                .into_iter()
                .map(|kind| TemplateEntry {
                    title: kind.title(),
                    detail: kind.description(),
                    notes: notes_for(&kind, ruleset),
                    already_added: already_added(&kind, ruleset),
                    kind,
                })
                .collect(),
        }
    }
}

/// What the template also needs under the profile's settings. The VM
/// template's rules are inbound: in Server Mode the DHCP offers to the
/// guests are new outbound packets, and with forwarded traffic blocked the
/// guests' own traffic through this computer is dropped.
fn notes_for(kind: &TemplateKind, ruleset: &FirewallRuleset) -> Vec<String> {
    let TemplateKind::VmGuestDhcpDns { interface } = kind else {
        return Vec::new();
    };
    let advanced = &ruleset.advanced_security;
    let mut notes = Vec::new();
    if advanced.egress_profile == EgressProfile::Server {
        notes.push(format!(
            "Server Mode is on: the DHCP offers to the guests also need an Output rule \
             (UDP to port 68 on {interface})."
        ));
    }
    if advanced.block_forwarding {
        notes.push(
            "Block forwarded traffic is on: guest traffic routed through this computer \
             (to the internet or the LAN) also needs Forwarded rules."
                .to_string(),
        );
    }
    notes
}

/// Every rule of `kind` is in `ruleset` already (same label, chain and
/// interface; enabled or not).
fn already_added(kind: &TemplateKind, ruleset: &FirewallRuleset) -> bool {
    kind.rules().iter().all(|rule| {
        ruleset.rules.iter().any(|r| {
            r.label == rule.label && r.chain == rule.chain && r.interface == rule.interface
        })
    })
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

    fn menu(interfaces: &[&str]) -> TemplateMenu {
        TemplateMenu::for_interfaces(&names(interfaces), &FirewallRuleset::new())
    }

    #[test]
    fn test_menu_only_offers_templates_for_present_interfaces() {
        let menu = menu(&["eth0", "wlan0"]);
        assert_eq!(menu.entries.len(), 0);

        let menu = self::menu(&["eth0", "virbr0"]);
        let titles: Vec<&str> = menu.entries.iter().map(|e| e.title.as_str()).collect();
        assert_eq!(titles, ["VM guests: DHCP and DNS on virbr0"]);

        let menu = self::menu(&["eth0", "tailscale0"]);
        let titles: Vec<&str> = menu.entries.iter().map(|e| e.title.as_str()).collect();
        assert_eq!(
            titles,
            ["Tailscale: direct connections", "Trust tailscale0"]
        );
    }

    #[test]
    fn test_entry_rules_are_fresh_each_time() {
        let menu = menu(&["virbr0"]);
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

    /// B.L5: the VM template says what Server Mode and blocked forwarded
    /// traffic also need, and a template already added is marked.
    #[test]
    fn test_vm_template_notes_and_duplicates() {
        let mut ruleset = FirewallRuleset::new();
        let plain = TemplateMenu::for_interfaces(&names(&["virbr0"]), &ruleset);
        assert_eq!(plain.entries[0].notes.len(), 0);
        assert!(!plain.entries[0].already_added);

        ruleset.advanced_security.egress_profile = EgressProfile::Server;
        ruleset.advanced_security.block_forwarding = true;
        ruleset.rules = plain.entries[0].rules();
        let menu = TemplateMenu::for_interfaces(&names(&["virbr0", "tailscale0"]), &ruleset);
        let vm = &menu.entries[0];
        assert_eq!(vm.notes.len(), 2);
        assert!(vm.notes[0].contains("UDP to port 68 on virbr0"));
        assert!(vm.notes[1].starts_with("Block forwarded traffic is on"));
        assert!(vm.already_added);
        assert!(
            menu.entries[1..]
                .iter()
                .all(|e| e.notes.is_empty() && !e.already_added)
        );
    }
}
