//! Ruleset payloads for root: only DRFW's own `inet drfw` table
//!
//! The root helper ([`crate::helper`]) runs `nft` on a ruleset DRFW sends on
//! stdin. polkit remembers the helper's authorization for about five
//! minutes, so the helper must not trust that the payload is DRFW's own
//! output: whatever runs inside the DRFW process could otherwise send
//! `flush ruleset`, or delete Docker's, libvirt's or Tailscale's tables,
//! without a prompt. This module decides what a payload may contain; the
//! helper refuses everything else (exit 1, nothing runs).
//!
//! # apply and check: [`check_ruleset_json`]
//!
//! The payload is exactly the JSON [`FirewallRuleset::to_nftables_json`]
//! produces, `{"nftables": [ … ]}`, in which every command is one of:
//!
//! | Command | `FirewallRuleset::build_commands` emits it as |
//! |---------|-----------------------------------------------|
//! | `add` / `delete` `table` `{family: "inet", name: "drfw"}` | the `add` + `delete` + `add` table replace |
//! | `flush` `table` `{family: "inet", name: "drfw"}` | (DRFW before per-source limits: `add` + `flush`; kept so their kept-ruleset records still save) |
//! | `add` `chain` with family `inet`, table `drfw` | the `input` / `forward` / `output` base chains |
//! | `add` `rule` with family `inet`, table `drfw` | every rule |
//! | `add` `set` with family `inet`, table `drfw` | per-source limit sets, the discovery reply set |
//!
//! Each object may only have the keys DRFW writes for it ([`TABLE_KEYS`],
//! [`CHAIN_KEYS`], [`RULE_KEYS`], [`SET_KEYS`]); names are compared exactly
//! (`drfw ` and `DRFW` are other tables). There is no `metainfo` (DRFW does
//! not send one), no `destroy`, `insert`, `replace`, `create`, `list`,
//! `reset` or `flush ruleset`, and no other family or table. On top of that
//! every rule expression must be one the text renderer
//! ([`crate::core::nft_text`]) knows, which is exactly the subset DRFW
//! generates: matches, `limit`, `ct count`, `log`, `counter`, the verdicts
//! and the `add`/`update @set` statements. Named sets (`@name`) and chains
//! are table-local in nft, so a rule in `inet drfw` cannot touch another
//! table.
//!
//! The bytes must also be the canonical serialization of what they parse to
//! (compact, as `serde_json` writes it): duplicate keys, whitespace or
//! anything else another JSON parser could read differently is refused, so
//! nft reads exactly what was checked. DRFW's own JSON always is (it is
//! `serde_json::to_vec` of the generated value).
//!
//! # save-config: [`SavePayload`]
//!
//! Save to System sends the same JSON plus, optionally, the preview section
//! of each command (`"sections"`: one of the fixed headings, never free
//! text). The helper checks the commands exactly like an apply's and renders
//! the boot file itself with [`crate::core::nft_text`]; with the sections it
//! is byte for byte [`FirewallRuleset::to_nft_text`], the GUI's preview. The
//! last kept rules are saved from their recorded JSON (no sections: the
//! text [`crate::core::confirmed::ConfirmedRecord::nft_text`] shows).
//!
//! Not covered: the revert guard's own batch (the `nft list table inet drfw`
//! output that `APPLY_SCRIPT` saves before an apply and its watcher may load
//! later) is produced as root inside the script and never passes through
//! here; it only ever names the `inet drfw` table.
//!
//! [`FirewallRuleset::to_nftables_json`]: crate::core::firewall::FirewallRuleset::to_nftables_json
//! [`FirewallRuleset::to_nft_text`]: crate::core::firewall::FirewallRuleset::to_nft_text

use serde_json::{Map, Value};

use crate::core::firewall::{FirewallRuleset, NFT_FAMILY, NFT_TABLE, SECTIONS};

/// Keys of a `table` object DRFW sends.
pub const TABLE_KEYS: [&str; 2] = ["family", "name"];
/// Keys of an `add chain` object DRFW sends.
pub const CHAIN_KEYS: [&str; 7] = ["family", "table", "name", "type", "hook", "prio", "policy"];
/// Keys of an `add rule` object DRFW sends (`comment` is optional).
pub const RULE_KEYS: [&str; 5] = ["family", "table", "chain", "expr", "comment"];
/// Keys of an `add set` object DRFW sends (`flags`, `timeout` and `size`
/// are optional).
pub const SET_KEYS: [&str; 7] = [
    "family", "table", "name", "type", "flags", "timeout", "size",
];

/// The command list of a payload.
const NFTABLES_KEY: &str = "nftables";
/// A save payload's optional section of each command.
const SECTIONS_KEY: &str = "sections";

/// Why a payload is not one DRFW sends to root.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct PayloadError(String);

impl PayloadError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

/// Checks an `apply` or `check` payload: DRFW's nftables JSON, touching
/// only the `inet drfw` table (see the module docs for the exact rules).
///
/// # Errors
///
/// A [`PayloadError`] naming the first thing that is not allowed.
///
/// # Example
///
/// ```
/// use drfw::core::firewall::FirewallRuleset;
/// use drfw::core::root_payload::check_ruleset_json;
///
/// let json = serde_json::to_vec(&FirewallRuleset::new().to_nftables_json()).unwrap();
/// assert!(check_ruleset_json(&json).is_ok());
/// assert!(check_ruleset_json(br#"{"nftables":[{"flush":{"ruleset":null}}]}"#).is_err());
/// ```
pub fn check_ruleset_json(payload: &[u8]) -> Result<(), PayloadError> {
    let map = parse_canonical(payload)?;
    let list = command_list(&map, &[NFTABLES_KEY])?;
    check_commands(list)?;
    crate::core::nft_text::render_list(list, None)
        .map(drop)
        .map_err(unsupported)
}

/// Checks a `save-config` payload exactly like [`check_ruleset_json`] (plus
/// its sections) and renders the `nft -f` file to install. This is what the
/// root helper writes; [`SavePayload::render`] is the same function.
///
/// # Errors
///
/// A [`PayloadError`]: a command that is not allowed, a section that is not
/// one of the fixed headings (or not one per command), or an expression the
/// renderer does not support.
pub fn render_save_payload(payload: &[u8]) -> Result<String, PayloadError> {
    let map = parse_canonical(payload)?;
    let list = command_list(&map, &[NFTABLES_KEY, SECTIONS_KEY])?;
    check_commands(list)?;
    let sections = match map.get(SECTIONS_KEY) {
        None => None,
        Some(sections) => Some(parse_sections(sections, list.len())?),
    };
    crate::core::nft_text::render_list(list, sections.as_deref()).map_err(unsupported)
}

/// What Save to System sends: the canonical JSON bytes of a
/// [`render_save_payload`] payload.
///
/// Through the root helper these bytes are the stdin of `save-config` (it
/// renders the file as root); without the helper (development builds)
/// DRFW renders the same text itself ([`Self::render`]) and sends that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavePayload(Vec<u8>);

impl SavePayload {
    /// The payload for `ruleset`: its nftables JSON with every command's
    /// section, so the saved file is [`FirewallRuleset::to_nft_text`].
    pub fn of_ruleset(ruleset: &FirewallRuleset) -> Self {
        let commands = ruleset.build_commands();
        let sections: Vec<&str> = commands.iter().map(|command| command.section).collect();
        let list: Vec<Value> = commands.into_iter().map(|command| command.value).collect();
        let mut document = Map::new();
        document.insert(NFTABLES_KEY.to_string(), Value::Array(list));
        document.insert(SECTIONS_KEY.to_string(), sections.into());
        // `Display` of a `Value` is its compact serialization (cannot fail)
        Self(Value::Object(document).to_string().into_bytes())
    }

    /// The payload for recorded nftables JSON (the kept-ruleset record's
    /// bytes): the same commands, no sections. Checked here already, so a
    /// record that root would refuse fails before any prompt.
    ///
    /// # Errors
    ///
    /// `json` is not a `{"nftables": [ … ]}` document that
    /// [`check_ruleset_json`] accepts.
    pub fn of_recorded_json(json: &str) -> Result<Self, PayloadError> {
        let value: Value = serde_json::from_str(json)
            .map_err(|e| PayloadError::new(format!("the ruleset is not JSON: {e}")))?;
        // Canonical form (older records were written as nft read them)
        let bytes = value.to_string().into_bytes();
        check_ruleset_json(&bytes)?;
        Ok(Self(bytes))
    }

    /// The bytes sent to the helper.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The `nft -f` file this payload installs ([`render_save_payload`]).
    ///
    /// # Errors
    ///
    /// See [`render_save_payload`] (never for [`Self::of_ruleset`] of a
    /// ruleset DRFW generates).
    pub fn render(&self) -> Result<String, PayloadError> {
        render_save_payload(&self.0)
    }
}

/// A renderer error: the payload has something DRFW never generates.
fn unsupported(error: impl std::fmt::Display) -> PayloadError {
    PayloadError::new(format!(
        "the ruleset has something DRFW never sends: {error}"
    ))
}

/// Parses `payload` as a JSON object whose canonical serialization is
/// exactly `payload` (see the module docs).
fn parse_canonical(payload: &[u8]) -> Result<Map<String, Value>, PayloadError> {
    let value: Value = serde_json::from_slice(payload)
        .map_err(|e| PayloadError::new(format!("the ruleset is not JSON: {e}")))?;
    if value.to_string().as_bytes() != payload {
        return Err(PayloadError::new(
            "the ruleset is not in DRFW's JSON form (compact, each key once)",
        ));
    }
    match value {
        Value::Object(map) => Ok(map),
        _ => Err(PayloadError::new("the ruleset is not a JSON object")),
    }
}

/// The `nftables` command list of a top-level object that has no keys
/// other than `allowed` (the first of which is `nftables`).
fn command_list<'a>(
    map: &'a Map<String, Value>,
    allowed: &[&str],
) -> Result<&'a [Value], PayloadError> {
    if let Some(key) = map.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(PayloadError::new(format!(
            "the ruleset has an unexpected top-level key {key:?}"
        )));
    }
    map.get(NFTABLES_KEY)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| PayloadError::new("the ruleset has no \"nftables\" command list"))
}

/// The fixed section names of a save payload, one per command.
fn parse_sections(sections: &Value, commands: usize) -> Result<Vec<&'static str>, PayloadError> {
    let sections = sections
        .as_array()
        .filter(|sections| sections.len() == commands)
        .ok_or_else(|| PayloadError::new("the sections are not a list with one per command"))?;
    sections
        .iter()
        .map(|section| {
            section
                .as_str()
                .and_then(|name| SECTIONS.into_iter().find(|known| *known == name))
                .ok_or_else(|| PayloadError::new(format!("unknown section {section}")))
        })
        .collect()
}

/// Checks every command of the list (see the module docs).
fn check_commands(list: &[Value]) -> Result<(), PayloadError> {
    for (index, command) in list.iter().enumerate() {
        check_command(command).map_err(|reason| {
            PayloadError::new(format!(
                "command {} of the ruleset is not allowed: {reason}",
                index + 1
            ))
        })?;
    }
    Ok(())
}

/// Checks one command: `{verb: {object: spec}}` as DRFW writes it.
fn check_command(command: &Value) -> Result<(), String> {
    let (verb, body) = single_entry(command).ok_or("not a single command")?;
    let (object, spec) = single_entry(body).ok_or_else(|| format!("malformed `{verb}`"))?;
    let spec = spec
        .as_object()
        .ok_or_else(|| format!("`{verb} {object}` without an object"))?;
    let keys: &[&str] = match (verb, object) {
        ("add" | "delete" | "flush", "table") => {
            only_keys(spec, &TABLE_KEYS, object)?;
            return expect_field(spec, "family", NFT_FAMILY, object)
                .and_then(|()| expect_field(spec, "name", NFT_TABLE, object));
        }
        ("add", "chain") => &CHAIN_KEYS,
        ("add", "rule") => &RULE_KEYS,
        ("add", "set") => &SET_KEYS,
        _ => return Err(format!("`{verb} {object}` is not a command DRFW sends")),
    };
    only_keys(spec, keys, object)?;
    expect_field(spec, "family", NFT_FAMILY, object)?;
    expect_field(spec, "table", NFT_TABLE, object)
}

/// Fails if `spec` has a key outside `keys`.
fn only_keys(spec: &Map<String, Value>, keys: &[&str], object: &str) -> Result<(), String> {
    match spec.keys().find(|key| !keys.contains(&key.as_str())) {
        Some(key) => Err(format!("unexpected key {key:?} in a {object}")),
        None => Ok(()),
    }
}

/// Fails unless `spec[key]` is exactly the string `expected`.
fn expect_field(
    spec: &Map<String, Value>,
    key: &str,
    expected: &str,
    object: &str,
) -> Result<(), String> {
    match spec.get(key) {
        Some(Value::String(value)) if value == expected => Ok(()),
        Some(value) => Err(format!("{object} {key} {value} is not {expected:?}")),
        None => Err(format!("{object} without {key}")),
    }
}

/// The only key/value pair of a single-entry JSON object.
fn single_entry(value: &Value) -> Option<(&str, &Value)> {
    let map = value.as_object()?;
    if map.len() != 1 {
        return None;
    }
    map.iter().next().map(|(key, value)| (key.as_str(), value))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::core::firewall::{
        Action, Chain, EgressProfile, PortEntry, Protocol, RateLimit, RejectType, Rule, TimeUnit,
    };
    use crate::core::test_helpers::{create_full_test_rule, create_test_ruleset};

    /// A rule of every kind DRFW generates: all protocols, actions, reject
    /// types, both families, limits (per source too), logging, every chain.
    fn kitchen_sink_rules() -> Vec<Rule> {
        let mut rules = Vec::new();
        for (i, protocol) in [
            Protocol::Any,
            Protocol::Tcp,
            Protocol::Udp,
            Protocol::TcpAndUdp,
            Protocol::Icmp,
            Protocol::Icmpv6,
            Protocol::IcmpBoth,
        ]
        .into_iter()
        .enumerate()
        {
            let port = matches!(
                protocol,
                Protocol::Tcp | Protocol::Udp | Protocol::TcpAndUdp
            )
            .then_some(1000 + u16::try_from(i).expect("small"));
            let mut rule = create_full_test_rule(
                &format!("rule {i} \"include\" \\ #"),
                protocol,
                port,
                None,
                Some("eth0"),
            );
            rule.log_enabled = i % 2 == 0;
            rules.push(rule);
        }
        for (i, (action, reject_type)) in [
            (Action::Drop, RejectType::Default),
            (Action::Reject, RejectType::Default),
            (Action::Reject, RejectType::PortUnreachable),
            (Action::Reject, RejectType::HostUnreachable),
            (Action::Reject, RejectType::AdminProhibited),
            (Action::Reject, RejectType::TcpReset),
        ]
        .into_iter()
        .enumerate()
        {
            let mut rule = create_full_test_rule(
                &format!("action {i}"),
                Protocol::Tcp,
                Some(2000),
                Some(if i % 2 == 0 {
                    "10.0.0.0/8"
                } else {
                    "2001:db8::/32"
                }),
                None,
            );
            rule.action = action;
            rule.reject_type = reject_type;
            rules.push(rule);
        }
        // Limits: plain, per source (both families: one set per family)
        let mut limited = create_full_test_rule("ssh limit", Protocol::Tcp, Some(22), None, None);
        limited.rate_limit = Some(RateLimit {
            count: 3,
            unit: TimeUnit::Minute,
            burst: Some(5),
            per_source: true,
        });
        limited.connection_limit = 4;
        limited.connection_limit_per_source = true;
        rules.push(limited);
        let mut plain = create_full_test_rule("web limit", Protocol::Tcp, Some(443), None, None);
        plain.rate_limit = Some(RateLimit {
            count: 100,
            unit: TimeUnit::Second,
            burst: None,
            per_source: false,
        });
        plain.connection_limit = 50;
        rules.push(plain);
        // Destinations, ranges, output and forward chains
        let mut out = create_full_test_rule("dns out", Protocol::Udp, Some(53), None, None);
        out.chain = Chain::Output;
        out.destinations = vec!["192.0.2.1".parse().expect("ip")];
        out.output_interface = Some("wg*".to_string());
        rules.push(out);
        let mut forward = create_full_test_rule("vm web", Protocol::Tcp, None, None, None);
        forward.chain = Chain::Forward;
        forward.ports = vec![PortEntry::Range {
            start: 8000,
            end: 8100,
        }];
        forward.output_interface = Some("virbr0".to_string());
        rules.push(forward);
        rules
    }

    /// DRFW's real output for every kind of profile (named).
    fn profiles() -> Vec<(&'static str, FirewallRuleset)> {
        let mut all_settings = FirewallRuleset::new();
        all_settings.rules = kitchen_sink_rules();
        let advanced = &mut all_settings.advanced_security;
        advanced.strict_icmp = true;
        advanced.icmp_rate_limit = 10;
        advanced.enable_rpf = true;
        advanced.log_dropped = true;
        advanced.egress_profile = EgressProfile::Server;
        advanced.block_forwarding = true;
        advanced.local_discovery = true;

        let mut server = FirewallRuleset::new();
        server.advanced_security.egress_profile = EgressProfile::Server;
        server.rules = crate::core::templates::server_essentials();

        let mut per_source = FirewallRuleset::new();
        per_source.rules = kitchen_sink_rules()
            .into_iter()
            .filter(|rule| rule.rate_limit.is_some() || rule.connection_limit > 0)
            .collect();

        let mut discovery = create_test_ruleset();
        discovery.advanced_security.local_discovery = true;

        let mut forward = FirewallRuleset::new();
        forward.advanced_security.block_forwarding = true;
        forward.rules = kitchen_sink_rules()
            .into_iter()
            .filter(|rule| rule.chain == Chain::Forward)
            .collect();

        let mut kitchen_sink = FirewallRuleset::new();
        kitchen_sink.rules = kitchen_sink_rules();

        vec![
            ("default", FirewallRuleset::new()),
            ("one rule", create_test_ruleset()),
            ("all settings", all_settings),
            ("server mode", server),
            ("per source", per_source),
            ("discovery", discovery),
            ("forward", forward),
            ("kitchen sink", kitchen_sink),
        ]
    }

    fn bytes(value: &Value) -> Vec<u8> {
        serde_json::to_vec(value).expect("json")
    }

    fn ruleset_bytes(ruleset: &FirewallRuleset) -> Vec<u8> {
        bytes(&ruleset.to_nftables_json())
    }

    /// A payload with `commands`, canonical (so the shape check decides).
    fn with_commands(commands: &[Value]) -> Vec<u8> {
        bytes(&json!({ "nftables": commands }))
    }

    /// DRFW's default output followed by `extra` (the realistic attack: a
    /// valid ruleset with one more command).
    fn appended(extra: Value) -> Vec<u8> {
        let mut json = FirewallRuleset::new().to_nftables_json();
        json["nftables"]
            .as_array_mut()
            .expect("command list")
            .push(extra);
        bytes(&json)
    }

    fn drfw_rule(expr: &Value) -> Value {
        json!({ "add": { "rule": {
            "family": "inet", "table": "drfw", "chain": "input", "expr": expr,
        } } })
    }

    #[test]
    fn test_drfw_output_is_allowed() {
        for (name, ruleset) in profiles() {
            let payload = ruleset_bytes(&ruleset);
            assert_eq!(check_ruleset_json(&payload), Ok(()), "{name}");
            // Exactly what the helper's include check sees too
            assert_eq!(crate::helper::check_payload(&payload), Ok(()), "{name}");
        }
    }

    /// Every verb/object pair DRFW emits is one of the allowed shapes, and
    /// every allowed shape is emitted (no allowance without a user).
    #[test]
    fn test_allowed_shapes_are_what_drfw_emits() {
        let mut seen = std::collections::BTreeSet::new();
        for (_, ruleset) in profiles() {
            for command in ruleset.build_commands() {
                let (verb, body) = single_entry(&command.value).expect("command");
                let (object, spec) = single_entry(body).expect("body");
                let keys: std::collections::BTreeSet<String> =
                    spec.as_object().expect("spec").keys().cloned().collect();
                seen.insert((verb.to_string(), object.to_string(), keys));
            }
        }
        let shapes: std::collections::BTreeSet<(&str, &str)> = seen
            .iter()
            .map(|(verb, object, _)| (verb.as_str(), object.as_str()))
            .collect();
        assert_eq!(
            shapes,
            [
                ("add", "chain"),
                ("add", "rule"),
                ("add", "set"),
                ("add", "table"),
                ("delete", "table"),
            ]
            .into_iter()
            .collect()
        );
        // Each allowed key list is exactly the union of the emitted keys
        for (object, allowed) in [
            ("table", &TABLE_KEYS[..]),
            ("chain", &CHAIN_KEYS[..]),
            ("rule", &RULE_KEYS[..]),
            ("set", &SET_KEYS[..]),
        ] {
            let emitted: std::collections::BTreeSet<&str> = seen
                .iter()
                .filter(|(_, o, _)| o == object)
                .flat_map(|(_, _, keys)| keys.iter().map(String::as_str))
                .collect();
            let allowed: std::collections::BTreeSet<&str> = allowed.iter().copied().collect();
            assert_eq!(emitted, allowed, "{object}");
        }
    }

    #[test]
    fn test_payload_allow_deny_table() {
        let table = |family: &str, name: &str| json!({ "family": family, "name": name });
        let in_table = |family: &str, name: &str, extra: Value| {
            let mut spec = json!({ "family": family, "table": name });
            for (key, value) in extra.as_object().expect("extra") {
                spec[key] = value.clone();
            }
            spec
        };
        let chain = |family: &str, name: &str| {
            json!({ "add": { "chain": in_table(family, name, json!({
                "name": "input", "type": "filter", "hook": "input", "prio": -10, "policy": "drop",
            })) } })
        };
        let rule = |family: &str, name: &str| {
            json!({ "add": { "rule": in_table(family, name, json!({
                "chain": "input", "expr": [{ "accept": null }],
            })) } })
        };
        let set = |family: &str, name: &str| {
            json!({ "add": { "set": in_table(family, name, json!({
                "name": "s", "type": "ipv4_addr", "flags": ["dynamic"], "size": 10,
            })) } })
        };
        // (payload, allowed)
        let cases: Vec<(String, Vec<u8>, bool)> = vec![
            // Allowed: the shapes DRFW emits, and `flush table inet drfw`
            ("add table".into(), with_commands(&[json!({ "add": { "table": table("inet", "drfw") } })]), true),
            ("delete table".into(), with_commands(&[json!({ "delete": { "table": table("inet", "drfw") } })]), true),
            ("flush table".into(), with_commands(&[json!({ "flush": { "table": table("inet", "drfw") } })]), true),
            ("chain".into(), with_commands(&[chain("inet", "drfw")]), true),
            ("rule".into(), with_commands(&[rule("inet", "drfw")]), true),
            ("set".into(), with_commands(&[set("inet", "drfw")]), true),
            ("empty list".into(), with_commands(&[]), true),
            // Other tables, families, the whole ruleset
            ("flush ruleset".into(), appended(json!({ "flush": { "ruleset": null } })), false),
            ("delete ruleset".into(), appended(json!({ "delete": { "ruleset": null } })), false),
            ("delete ip filter".into(), appended(json!({ "delete": { "table": table("ip", "filter") } })), false),
            ("delete inet docker".into(), appended(json!({ "delete": { "table": table("inet", "docker") } })), false),
            ("flush inet docker".into(), appended(json!({ "flush": { "table": table("inet", "docker") } })), false),
            ("add ip drfw".into(), appended(json!({ "add": { "table": table("ip", "drfw") } })), false),
            ("delete ip6 drfw".into(), appended(json!({ "delete": { "table": table("ip6", "drfw") } })), false),
            ("trailing space".into(), appended(json!({ "delete": { "table": table("inet", "drfw ") } })), false),
            ("upper case name".into(), appended(json!({ "delete": { "table": table("inet", "DRFW") } })), false),
            ("upper case family".into(), appended(json!({ "delete": { "table": table("INET", "drfw") } })), false),
            ("numeric family".into(), appended(json!({ "delete": { "table": { "family": 1, "name": "drfw" } } })), false),
            ("table without family".into(), appended(json!({ "delete": { "table": { "name": "drfw" } } })), false),
            ("table with handle".into(), appended(json!({ "delete": { "table": { "family": "inet", "name": "drfw", "handle": 7 } } })), false),
            ("dormant table".into(), appended(json!({ "add": { "table": { "family": "inet", "name": "drfw", "flags": ["dormant"] } } })), false),
            ("chain in inet docker".into(), appended(chain("inet", "docker")), false),
            ("chain in ip drfw".into(), appended(chain("ip", "drfw")), false),
            ("rule in ip filter".into(), appended(rule("ip", "filter")), false),
            ("rule in inet docker".into(), appended(rule("inet", "docker")), false),
            ("set in inet docker".into(), appended(set("inet", "docker")), false),
            ("set in netdev drfw".into(), appended(set("netdev", "drfw")), false),
            ("table object as the rule's table".into(), appended(json!({ "add": { "rule": {
                "family": "inet", "table": table("inet", "drfw"), "chain": "input", "expr": [],
            } } })), false),
            // Verbs and objects DRFW never sends, even for its own table
            ("insert rule".into(), appended(json!({ "insert": { "rule": in_table("inet", "drfw", json!({ "chain": "input", "expr": [{ "accept": null }] })) } })), false),
            ("replace rule".into(), appended(json!({ "replace": { "rule": in_table("inet", "drfw", json!({ "chain": "input", "handle": 1, "expr": [{ "accept": null }] })) } })), false),
            ("create table".into(), appended(json!({ "create": { "table": table("inet", "drfw") } })), false),
            ("destroy table".into(), appended(json!({ "destroy": { "table": table("inet", "drfw") } })), false),
            ("delete chain".into(), appended(json!({ "delete": { "chain": in_table("inet", "drfw", json!({ "name": "input" })) } })), false),
            ("flush chain".into(), appended(json!({ "flush": { "chain": in_table("inet", "drfw", json!({ "name": "input" })) } })), false),
            ("list ruleset".into(), appended(json!({ "list": { "ruleset": null } })), false),
            ("list table".into(), appended(json!({ "list": { "table": table("inet", "drfw") } })), false),
            ("reset counters".into(), appended(json!({ "reset": { "counters": { "family": "inet", "table": "drfw" } } })), false),
            ("metainfo".into(), appended(json!({ "metainfo": { "json_schema_version": 1 } })), false),
            ("add element".into(), appended(json!({ "add": { "element": in_table("inet", "drfw", json!({ "name": "s", "elem": ["1.2.3.4"] })) } })), false),
            ("add map".into(), appended(json!({ "add": { "map": in_table("inet", "drfw", json!({ "name": "m", "type": "ipv4_addr", "map": "verdict" })) } })), false),
            ("add flowtable".into(), appended(json!({ "add": { "flowtable": in_table("inet", "drfw", json!({ "name": "f", "hook": "ingress", "prio": 0, "dev": ["eth0"] })) } })), false),
            ("add ct helper".into(), appended(json!({ "add": { "ct helper": in_table("inet", "drfw", json!({ "name": "h", "type": "ftp", "protocol": "tcp" })) } })), false),
            // Keys DRFW never writes
            ("rule with handle".into(), appended(json!({ "add": { "rule": in_table("inet", "drfw", json!({ "chain": "input", "handle": 1, "expr": [{ "accept": null }] })) } })), false),
            ("rule with position".into(), appended(json!({ "add": { "rule": in_table("inet", "drfw", json!({ "chain": "input", "position": 1, "expr": [{ "accept": null }] })) } })), false),
            ("chain with dev".into(), appended(json!({ "add": { "chain": in_table("inet", "drfw", json!({ "name": "ing", "type": "filter", "hook": "ingress", "prio": 0, "policy": "accept", "dev": "eth0" })) } })), false),
            ("set with elem".into(), appended(json!({ "add": { "set": in_table("inet", "drfw", json!({ "name": "s", "type": "ipv4_addr", "elem": ["1.2.3.4"] })) } })), false),
            // Statements DRFW never generates, in its own table
            ("dup statement".into(), appended(drfw_rule(&json!([{ "dup": { "addr": "192.0.2.9", "dev": "eth0" } }]))), false),
            ("queue statement".into(), appended(drfw_rule(&json!([{ "queue": { "num": 1 } }]))), false),
            ("mangle statement".into(), appended(drfw_rule(&json!([{ "mangle": { "key": { "meta": { "key": "mark" } }, "value": 1 } }]))), false),
            ("jump".into(), appended(drfw_rule(&json!([{ "jump": { "target": "input" } }]))), false),
            // Malformed commands
            ("two verbs".into(), appended(json!({ "add": { "table": table("inet", "drfw") }, "delete": { "table": table("inet", "docker") } })), false),
            ("two objects".into(), appended(json!({ "add": { "table": table("inet", "drfw"), "chain": in_table("inet", "docker", json!({ "name": "x" })) } })), false),
            ("string command".into(), appended(json!("flush ruleset")), false),
            ("null spec".into(), appended(json!({ "flush": { "table": null } })), false),
            // Not the document DRFW sends
            ("text".into(), b"table inet drfw\ndelete table inet drfw\n".to_vec(), false),
            ("flush ruleset text".into(), b"flush ruleset\n".to_vec(), false),
            ("empty".into(), Vec::new(), false),
            ("top-level array".into(), bytes(&json!([])), false),
            ("no list".into(), bytes(&json!({ "nftables": {} })), false),
            ("no nftables key".into(), bytes(&json!({ "nft": [] })), false),
            ("extra top-level key".into(), bytes(&json!({ "nftables": [], "x": 1 })), false),
            ("sections in an apply".into(), bytes(&json!({ "nftables": [], "sections": [] })), false),
            ("whitespace".into(), b"{ \"nftables\": [] }".to_vec(), false),
            ("trailing newline".into(), b"{\"nftables\":[]}\n".to_vec(), false),
            ("trailing text".into(), b"{\"nftables\":[]} flush ruleset".to_vec(), false),
            (
                "duplicate name, the last one drfw".into(),
                br#"{"nftables":[{"delete":{"table":{"family":"inet","name":"docker","name":"drfw"}}}]}"#.to_vec(),
                false,
            ),
            (
                "duplicate nftables key".into(),
                br#"{"nftables":[{"flush":{"ruleset":null}}],"nftables":[]}"#.to_vec(),
                false,
            ),
            ("not utf-8".into(), b"{\"nftables\":[\"\xff\"]}".to_vec(), false),
        ];
        for (name, payload, allowed) in &cases {
            let verdict = check_ruleset_json(payload);
            assert_eq!(verdict.is_ok(), *allowed, "{name}: {verdict:?}");
            // save-config refuses the same commands
            let save = render_save_payload(payload);
            if !allowed {
                assert!(
                    save.is_err() || *name == "sections in an apply",
                    "{name}: {save:?}"
                );
            }
        }
    }

    /// The text root installs is byte for byte the GUI's preview
    /// (`to_nft_text`), for every profile.
    #[test]
    fn test_save_payload_renders_exactly_the_preview() {
        for (name, ruleset) in profiles() {
            let payload = SavePayload::of_ruleset(&ruleset);
            // What the helper does with the bytes it reads
            let rendered = render_save_payload(payload.as_bytes()).expect(name);
            assert_eq!(rendered, ruleset.to_nft_text(), "{name}");
            assert_eq!(payload.render().as_deref(), Ok(rendered.as_str()), "{name}");
            assert_eq!(
                crate::helper::check_payload(rendered.as_bytes()),
                Ok(()),
                "{name}"
            );
            // The commands are exactly the applied JSON's
            let document: Value = serde_json::from_slice(payload.as_bytes()).expect("json");
            assert_eq!(
                document["nftables"],
                ruleset.to_nftables_json()["nftables"],
                "{name}"
            );
        }
    }

    /// The last kept rules: exactly the recorded JSON's text (no sections),
    /// what `ConfirmedRecord::nft_text` shows; older, non-compact records
    /// are sent in compact form.
    #[test]
    fn test_recorded_json_payload() {
        for (name, ruleset) in profiles() {
            let json = ruleset.to_nftables_json();
            let recorded = serde_json::to_string(&json).expect("json");
            let payload = SavePayload::of_recorded_json(&recorded).expect(name);
            assert_eq!(payload.as_bytes(), recorded.as_bytes(), "{name}");
            let text = payload.render().expect(name);
            assert_eq!(
                Ok(text.as_str()),
                crate::core::nft_text::render_json(&recorded).as_deref(),
                "{name}"
            );
            let pretty = serde_json::to_string_pretty(&json).expect("json");
            let from_pretty = SavePayload::of_recorded_json(&pretty).expect(name);
            assert_eq!(from_pretty, payload, "{name}");
        }
        // An older DRFW's `add` + `flush` replace still saves
        let old = r#"{"nftables":[{"add":{"table":{"family":"inet","name":"drfw"}}},{"flush":{"table":{"family":"inet","name":"drfw"}}}]}"#;
        assert!(SavePayload::of_recorded_json(old).is_ok());
        // A record that root would refuse fails before any prompt
        for bad in [
            r#"{"nftables":[{"flush":{"ruleset":null}}]}"#,
            r#"{"nftables":[{"delete":{"table":{"family":"inet","name":"docker"}}}]}"#,
            "flush ruleset",
            r#"{"nftables":[],"sections":[]}"#,
        ] {
            assert!(SavePayload::of_recorded_json(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn test_save_payload_sections_are_fixed_headings() {
        let ruleset = create_test_ruleset();
        let payload: Value =
            serde_json::from_slice(SavePayload::of_ruleset(&ruleset).as_bytes()).expect("json");
        let count = payload["nftables"].as_array().expect("list").len();
        let with_sections = |sections: Value| {
            let mut document = payload.clone();
            document["sections"] = sections;
            bytes(&document)
        };
        // Without sections: the recorded-JSON text, no headings
        let mut bare = payload.clone();
        bare.as_object_mut().expect("object").remove("sections");
        let text = render_save_payload(&bytes(&bare)).expect("no sections");
        assert!(!text.contains("# ---"), "{text}");
        assert!(ruleset.to_nft_text().contains("# --- User rules ---"));
        for (name, sections) in [
            ("one short", json!(vec!["Setup"; count - 1])),
            ("one too many", json!(vec!["Setup"; count + 1])),
            ("unknown", json!(vec!["Elsewhere"; count])),
            (
                "free text",
                json!(vec!["Setup\ninclude \"/etc/shadow\""; count]),
            ),
            ("empty", json!(vec![""; count])),
            ("not strings", json!(vec![1; count])),
            ("not a list", json!("Setup")),
        ] {
            let result = render_save_payload(&with_sections(sections));
            assert!(result.is_err(), "{name}: {result:?}");
        }
        // Every known heading is accepted
        let all_known: Vec<&str> = (0..count).map(|i| SECTIONS[i % SECTIONS.len()]).collect();
        assert!(render_save_payload(&with_sections(json!(all_known))).is_ok());
    }
}
