# Changelog

## Unreleased

Everything since 0.9.0. Most of DRFW was reworked: how rules are applied and reverted,
what the generated ruleset contains, and what the GUI and CLI tell you about it. Read
**Upgrading** first.

### Upgrading

- **Apply once after upgrading, and keep it** (confirm it in time, or apply with
  auto-revert off / `--no-confirm`). The ruleset DRFW generates around your rules
  changed (see [Changed baseline rules](#changed-baseline-rules)), and only an apply by
  this version arms the new root-side revert guard and writes the kept-ruleset record.
  Until then Save to System and `drfw save` report your rules as untested. A ruleset
  applied by an older version also differs from what this version generates (new
  comments "rate-limited reject" and "final counter" at the end of the input chain,
  and, with local network discovery on, new output rules), so the diff and `drfw save`
  show a change until you apply again.
- **Delete the old polkit rule if you installed it by hand.** Older versions shipped
  `50-drfw.rules`, which let the DRFW process run root `nft` without a password. DRFW
  no longer ships or needs it (see [Safety](#safety)), and the package no longer
  installs it, so a package upgrade removes `/usr/share/polkit-1/rules.d/50-drfw.rules`.
  If you copied it there or to `/etc/polkit-1/rules.d/` yourself, remove it.
- **Auto-revert is on by default** for new installs. A config saved by an older DRFW
  (whose default was off) keeps its value; the GUI asks once ("Auto-revert is off: if
  an apply locks you out, DRFW won't roll it back. [Turn on] [Keep off]") instead of
  changing it silently.
- **Exit codes changed.** The CLI used to exit with 0 or 1 (2 for usage errors); it now uses 0 to 9 (see
  [CLI](#cli)). Scripts must not treat 3 to 6 like 1: they mean "look at the firewall
  now". Unattended applies (e.g. a NetworkManager dispatcher script) need `--yes`
  besides `--no-confirm`, or a big change is refused with exit code 9.
- **drfw.service is generated now.** If you installed `contrib/drfw.service` by hand,
  replace it with the output of `drfw print-service-unit` (it fills in the paths this
  build uses and orders the unit `Before=network-pre.target` with
  `Wants=network-pre.target`).
- Profiles gain a `version` field; older profiles load unchanged. The `.sha256` files
  next to profiles and the snapshots in `~/.local/state/drfw/snapshots/` are no longer
  used and can be deleted.
- Building needs Rust 1.100 (pinned in `rust-toolchain.toml`).

### Safety

- **Root-side revert guard.** Apply runs one fixed, elevated script that saves the
  current `inet drfw` table (or the fact that there was none) in `/run/drfw`, starts a
  detached root watcher (a `drfw-revert-*` systemd unit, or a `setsid` process without
  systemd) and only then applies the new rules. The watcher reverts on time even if
  DRFW crashes or is closed, or the terminal or SSH session is lost. It counts time on
  the monotonic clock, so clock changes do not matter.
- **One password prompt per apply.** Confirm, "revert now" and the timeout need none:
  they are token files in your runtime directory (which must be yours, mode 0700), and
  the watcher only honours tokens you own. DRFW ships **no polkit rule** any more.
- **The first-apply lockout is fixed.** The old "snapshot" was taken inside the apply,
  so on a first apply it captured the new drop policies without any rules, and a
  revert left the machine offline. A revert now restores the previous table exactly,
  or removes DRFW's table if there was none. If restoring fails, the watcher removes
  the table rather than leave a locked-down ruleset in place.
- **No unguarded window.** The elevated scripts ignore hang-up, interrupt and terminate
  signals, and the watcher exists before the new rules go live, so an SSH drop or
  Ctrl-C right after the password can no longer leave unguarded rules behind. When
  DRFW cannot tell what happened after you authenticated, it says the new rules **may
  be active** (CLI exit code 6; in the GUI a short banner and an **Apply Details**
  panel) instead of "nothing was changed".
- **The revert snapshot is private.** In `/run/drfw` (mode 755) the saved table (the
  revert file), the watcher script and the lock are 0600, readable only by root; only
  the `status-*` files and `active`, which `drfw status` reads, are 0644.
- **Stopping the guard reverts.** A revert guard stopped by SIGTERM, SIGHUP or SIGINT
  (`systemctl stop`, `kill`, a shutdown) reverts at once. Only SIGKILL ends it without
  a revert; `drfw status` then reports "LOST since …" instead of PENDING (the rules
  stay active; apply again to keep or replace them).
- **Auto-revert is on by default**, with the one-time notice above for old configs.
- **The kept-ruleset record.** When you keep an apply (confirm it, or apply with
  auto-revert off or `--no-confirm`), DRFW records the exact applied JSON, the rules
  and the boot id in `~/.local/state/drfw/confirmed-ruleset.json`. GUI and CLI share
  it: it decides whether Save to System saves *tested* rules, what the diff and the
  Exposure view compare with, and what the retention guard protects.
- **Retention guard.** Apply and Save to System (GUI and CLI) ask for an explicit
  confirmation before a big change: removing or changing at least 3 and at least 40 % of
  the kept enabled rules (a kept rule edited to act differently counts: Accept turned
  into Drop, sources narrowed, moved to another chain, …; the warning then reads
  "Removes or changes N of the M …"), switching to Server Mode, or turning on **Block
  forwarded traffic**.
  The GUI lists the removed rules and needs a click on a red button; the CLI asks y/N,
  or needs `--yes` without a terminal (exit code 9 otherwise).
- **SSH lockout check.** Before Apply and Save to System, DRFW finds the current SSH
  sessions without privileges and checks whether the new rules would let their clients
  reconnect. A blocked or possibly blocked reconnect needs the same explicit
  confirmation; a reconnect that is only rate- or connection-limited is a note.
  `drfw status` and the Exposure view show the answer per session.
- **Fresh facts before you confirm.** "Commit Changes?" and the Save to System dialog
  re-read the SSH sessions and the kept record when they open (so a CLI apply made
  meanwhile counts) and wait for that ("Checking SSH sessions and the kept rules…"):
  until then their continue buttons are disabled and Enter does nothing. A late
  Exposure scan no longer overwrites fresher facts.
- **Invalid rules are never applied.** One validator checks every rule (ports, ranges,
  address families, interface names, limits, log prefixes, ...). Profiles keep invalid
  rules, marked INVALID, but Apply, Save to System and `drfw apply` refuse while an
  applied rule is invalid.
- **What you see is what is applied and what boots.** Apply (JSON), the preview,
  `drfw export` and Save to System (text) now come from one list of commands. Before,
  the text written to `/etc/nftables.conf` came from a second generator that disagreed
  with the applied rules, and the saved config did not load at boot. Loading the file
  again replaces DRFW's table instead of duplicating rules.
- **Save to System is safe.** One elevated script writes the new file next to the
  target, runs `nft -c` on exactly those bytes, keeps the previous file as `.drfw-bak`
  and the file DRFW first replaced as `.drfw-orig` (never overwritten), and flushes and
  renames atomically. A file nft rejects never replaces the current one.
- **Rules no longer do more than they say:**
  - an IPv4/IPv6 split no longer widens a rule (it used to drop an address list);
  - protocol Any with ports means TCP and UDP on those ports (the ports used to be
    dropped, which accepted everything);
  - Drop/Reject with a rate or connection limit drop what is *over* the limit (they
    used to drop exactly the traffic within it); with both limits they become two
    rules, so neither is skipped;
  - your rules come before the ICMP accept, so "drop everything from X" also stops X's
    pings, and ICMP Drop/Reject rules work;
  - closing a rule-form helper with Done or Esc keeps the typed value (a rule meant for
    port 22 used to become "All ports");
  - editing a rule keeps it disabled if it was;
  - interface names, labels and log prefixes are sanitized, so they cannot inject nft
    syntax.
- **No silent data loss.** A damaged, newer-version or oversized profile or config is
  copied to `<file>.corrupt-<timestamp>` and opened read-only, never overwritten.
  Create, Save As and Rename refuse existing names; a failed save is reported and
  retried; closing the window flushes pending saves; "Discard" really discards.
  Data and state directories are 0700 (fixed on existing installs).

### Changed baseline rules

These change what DRFW generates for every profile. Your rules and settings stay as they
are; the generated ruleset around them is different. Apply (and keep) once after
upgrading.

- **Forwarded traffic is accepted by default**, so Docker, libvirt and VPN routing keep
  working. The new **Block forwarded traffic** setting drops it (established and
  related traffic stays allowed) unless a Forwarded rule allows it. When IP forwarding
  is on and not blocked, `drfw status`, the Exposure view and the "Commit Changes?"
  dialog say so.
- **Server Mode no longer locks you out.** Its output chain accepts loopback, replies
  to accepted connections, IPv6 neighbor discovery, DHCP/DHCPv6 client requests, and
  IGMP/MLD membership reports. Before, loopback and every reply were dropped, and a
  DHCP-configured server lost its address at renewal time.
- **ICMP redirects are really blocked now.** A redirect that refers to one of your
  connections used to be let through as "related" traffic, so "Block ICMP redirects"
  did not stop the redirects that matter. The redirect drops now come first.
- **Multicast group membership (IGMP) is allowed.** IGMP was dropped, so switches with
  multicast snooping stopped sending multicast (UPnP/SSDP, IPTV) to this computer after a
  few minutes.
- **DHCP replies from a DHCP server (UDP port 67 to 68) are allowed explicitly**, and
  DHCPv6 replies from link-local addresses. Most DHCP clients did not need this, but
  clients that receive on an ordinary UDP socket do.
- **Anti-spoofing (RPF) only checks new connections and honours the packet mark.** It
  now runs after the accept of established connections and takes the firewall mark into
  account, so full-tunnel VPNs (wg-quick, Tailscale exit nodes) keep working with it on.
  It still drops spoofed source addresses. A VPN peer that contacts this computer first
  over the tunnel's underlay can still be blocked.
- **The ICMP rate limit now limits pings.** It used to limit only the start of new pings,
  so a ping flood was answered in full. Echo requests over the limit are now dropped;
  neighbor discovery and other ICMP are never limited.
- **Strict ICMP accepts all ICMPv6 messages IPv6 needs** (RFC 4890), including router
  advertisements and solicitations and multicast listener messages, so SLAAC, virtual
  machines and hotspot clients of this computer keep working.
- **Packets with loopback addresses (127.0.0.0/8) arriving from the network are dropped**
  (they only ever arrive when `route_localnet` is enabled, e.g. by kube-proxy).
- **Logging of dropped packets ignores broadcast and multicast**, so LAN noise no longer
  uses up the log rate.
- **Every base rule has a comment**, including the reject and the counter at the end
  of the input chain ("rate-limited reject", "final counter"), so each one can be told
  apart in the preview, `drfw export`, `nft list` and nft error messages.
- **The table is replaced, not flushed**, on every apply, so the sets and limit state
  of deleted or changed rules do not survive an apply.

### Rules

- **Per-source limits** (Accept rules): a rule's rate or connection limit can apply to
  every client address separately (IPv6: every /64), so one client that uses up its
  budget does not lock everyone else out. Up to 65535 clients are tracked per rule.
- **Forwarded rules:** with **Block forwarded traffic** on, rules in the "Forwarded
  (routed through)" chain allow routed traffic (for example to containers or virtual
  machines), matching the incoming and the outgoing interface. They are marked FWD and
  shown as inactive while forwarded traffic is not blocked (like Output rules in
  Desktop mode, which are now shown dimmed instead of hidden). The chain picker keeps
  the rule's original chain, so an inactive Forwarded or Output rule can be moved to
  Input and back while you edit it.
- **Local network discovery** (Settings, Desktop mode): find and be found by printers,
  TVs, speakers and other computers: it accepts mDNS multicast (224.0.0.251 / ff02::fb,
  UDP 5353) and SSDP/UPnP and WS-Discovery multicast (239.255.255.250 / ff02::c /
  ff05::c, UDP 1900 and 3702). Only genuine queries open a reply port, for 10 seconds:
  SSDP or WS-Discovery to 239.255.255.250 / ff02::c / ff05::c on 1900 or 3702, mDNS to
  224.0.0.251 / ff02::fb on 5353, LLMNR to 224.0.0.252 / ff02::1:3 on 5355, and NetBIOS
  name queries broadcast to 137 (seven output rules remember their source ports). Other
  broadcast or multicast never opens the sender's port, and replies are accepted only
  from 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, fe80::/10 and
  fc00::/7. NetBIOS datagrams (port 138) are not supported. On for profiles the GUI
  creates (the first profile, "New empty profile", "Start fresh"); off for existing
  profiles, where the GUI asks once (one notice in all, for the profile open at the
  time). Turn it off on networks you don't trust. The Exposure view and `drfw exposure`
  show UDP sockets on 1900, 3702, 5353, 5355 and 137 as "local network (discovery)", or
  "local network, for 10 s after it sends a discovery query" when only the replies
  reach them, not as open; other ports are not shown as reachable through discovery.
- **Server Mode offers the essentials.** Switching Server Mode on offers, pre-ticked,
  ordinary Output rules for DNS, DNS over TLS, time sync (NTP), web and updates (HTTP and
  HTTPS) and ping. With rules ticked, turning it on and adding them is one undo step:
  Ctrl+Z turns Server Mode off again and removes them, redo restores both. With nothing
  ticked only the setting changes. Rules you already have (enabled) are not offered
  twice. If the ticked rules don't fit under the rule limit, Server Mode is not turned
  on.
- **Rule templates:** "Add from template" (next to Add Access Rule) offers ready-made,
  ordinary rules for the interfaces this computer has: DHCP and DNS for virtual machines
  on libvirt bridges (`virbr*`), and for Tailscale "Tailscale: direct connections" (UDP
  41641) and "Trust tailscale0". The VM template notes that Server Mode also needs an
  Output rule for DHCP offers (UDP to port 68 on the bridge), and that with Block
  forwarded traffic on, guest traffic routed through this computer needs Forwarded
  rules. A template already in the profile shows "Already in this profile." and can't
  be added twice.
- The Port Unreachable and Host Unreachable reject types are offered in the form.
- Interface names may have 15 characters including `*` (nft's real limit).
- Labels and tags are trimmed and runs of spaces collapsed, also in existing profiles.

### GUI

- **Exposure view** (header button): the programs listening on this computer (TCP and
  UDP, IPv4 and IPv6) and who can reach each under your rules: everyone (red),
  everyone on some interfaces only, such as a VPN (amber), specific networks, nobody,
  or local only, with the deciding rule one click away. It compares the editor with
  the applied or kept rules, and is read without privileges. Ports Docker publishes are
  marked PUBLISHED BY DOCKER: "not filtered by DRFW's rules", or, with Block forwarded
  traffic on, "decided by your Forwarded rules (blocked unless one allows it)" (the
  same in `drfw exposure`, JSON key `docker_forward_filtered`; the container-network
  notice likewise says "decided by your Forwarded rules"). A `docker-proxy` only counts
  when it runs as root (real and effective user id 0) and the socket is root's, so a
  program merely named `docker-proxy` cannot hide a port.
- **nft errors name the rule.** When nft rejects a ruleset, a panel lists each error
  with the rule's name, nft's message and the offending line, and "Edit Rule" opens the
  rule. Errors in DRFW's own rules name the base rule.
- **Diff from startup:** until the GUI applies something itself, the diff compares the
  editor with the kept-ruleset record ("vs last applied", "vs last kept, earlier
  session"). The diff has a +/- gutter.
- **Save to System:** shows whether the rules will load at boot, and offers **Also
  enable nftables.service at boot** (same prompt). When the editor differs from the
  last kept rules, the main button is **Save the last kept rules** (banner "Last kept
  rules saved") and the editor's rules need a click on the red **Save untested rules**;
  a retention warning then says it is about "Save untested rules". "Save the last kept
  rules" writes the text of exactly the recorded JSON, not the rules generated again,
  so a newer DRFW cannot change what it saves.
- **"Commit Changes?" and Save to System scroll** on small windows, so their buttons
  stay reachable.
- **Keyboard:** Enter runs the top-most dialog's main action; the danger buttons ("…
  anyway", and the strict RPF, strict ICMP and Server Mode warnings) need a click.
  Plain Enter never confirms the auto-revert countdown; Ctrl+Enter does. Tab and
  Shift+Tab move between the dialog's fields. Esc closes only the top-most layer and
  never cancels an apply or the countdown. Ctrl shortcuts are ignored while a text
  field has the focus (Ctrl+Z in the search box no longer undoes rule edits). Template
  entries, essentials checkboxes and notice buttons are mouse-only (an iced 0.14
  limitation); the F1 help says so.
- **Banners:** shown above dialogs, with a severity word. Persistent banners ("Revert
  FAILED…", "New rules MAY BE ACTIVE…") are no longer pushed out by later banners, and
  the Apply Details panel of an apply with an unknown outcome survives a profile switch.
- Undo and redo say what they did. Edits are locked while an apply runs. Clicking the
  active profile no longer reloads it. "Start fresh" on a read-only profile asks first.
  Apply (Ctrl+S) closes an open template menu.
- Diagnostics shows times in local time and refreshes cheaply; Clear Log asks first.
- Light themes style carets, selections and unstyled widgets correctly (the iced theme
  follows the app theme).
- The GUI no longer polls or computes in every frame: lower CPU use when idle.

### CLI

- **New commands:** `drfw check <profile>` (validate and `nft --check` without
  privileges or prompts), `drfw save <profile> [--enable-at-boot] [--yes]` (Save to
  System for headless machines), `drfw exposure [profile] [--json]` (the Exposure view
  as a table or JSON), and the hidden `drfw print-service-unit` for packagers.
- **`drfw apply --yes`** goes ahead when the retention guard or the SSH lockout check
  warns; `--no-confirm` counts as kept.
- **`drfw status` reports only what it can know** without root: active profile, rule
  and invalid-rule counts, mode, forwarding, one SSH line per session, a pending
  auto-revert, whether the boot config was written by DRFW, whether a unit loads it at
  boot, and a "Kernel" line pointing to `sudo nft list table inet drfw`.
- **Exit codes:**

  | Code | Meaning |
  |------|---------|
  | 0 | Success: applied and kept, reverted (on timeout or on request), saved |
  | 1 | Failed, nothing was changed (or `drfw check` found problems) |
  | 2 | Usage error |
  | 3 | `apply`: the previous rules could not be restored, so the drfw table was removed: nothing is filtered |
  | 4 | `apply`: the revert failed: the new, unconfirmed rules are still active |
  | 5 | `apply`: another apply replaced these rules before they were confirmed |
  | 6 | `apply`: the outcome is unknown: the new rules may be active |
  | 7 | `save`: not saved, the rules are not the ones last applied and kept (confirmed, or applied with `--no-confirm`) with `drfw apply` or the GUI (use `--yes`) |
  | 8 | `save`: saved, but the boot service could not be enabled |
  | 9 | `apply`/`save`: not done, the retention guard or the SSH lockout check asks for a confirmation (use `--yes`) |

- **Countdown:** Ctrl-C and Esc revert (Ctrl-C used to *confirm*, because raw mode
  reports it as `c`). Keys typed before the countdown starts, such as an Enter typed
  during the password prompt, are discarded. A countdown whose apply was replaced by
  another one stops at once.
- `--confirm` values outside 5 to 120 seconds are a usage error (exit 2) instead of
  silently clamped. The GUI clamps a hand-edited `auto_revert_timeout_secs` into the
  same range.
- Output into a closed pipe (`drfw status | head -1`) no longer panics (it used to
  exit with 101).
- `drfw save` says how the ruleset was kept: "applied and kept (confirmed)" or
  "applied and kept (without auto-revert)".
- Without git metadata (a release tarball) the version is plain "0.9.0", and
  `drfw --version` reports commit and branch as "unknown".
- Colour is used only on a terminal; piped output has no escape codes.
- `DRFW_ELEVATION_METHOD` (`sudo`, `run0`, `pkexec`) chooses the elevation tool; see
  the README.

### Packaging

- **Compile-time distribution settings**, checked at build time:
  `DRFW_SYSTEM_NFT_PATH` (the file Save to System writes), `DRFW_SYSTEM_NFT_SERVICE`
  (the unit that loads it at boot) and `DRFW_NFT_PATH` (the `nft` binary). The README
  has a per-distribution table.
- **Boot persistence:** the Save to System dialog and `drfw status` say whether a unit
  loads the rules at boot (asked without privileges); the dialog's checkbox and
  `drfw save --enable-at-boot` enable it in the same prompt (never `start`).
- **Generated `drfw.service`:** `drfw print-service-unit` fills `contrib/drfw.service.in`
  with this build's paths, so the unit always loads the file Save to System writes. It
  is ordered `Before=network-pre.target` (with `Wants=network-pre.target`), so the
  rules are loaded before networking comes up. Stop removes only DRFW's table.
- The generated file's `#!` line uses the build's `nft` path.
- `contrib/PKGBUILD` sets Arch's paths, installs no polkit rule, respects the pinned
  toolchain and runs the test suite in `check()` (no root needed).

### Internal

- Rust 1.100 (pinned); dependencies updated, `cargo deny` in CI.
- `chrono` replaced by `jiff` (RUSTSEC-2026-0543). Stored timestamps stay compatible in
  both directions.
- The profile and snapshot checksums (`sha2`) and the on-disk snapshot history are
  gone; so is the emergency ruleset.
- Every module is compiled once (the GUI lives in the library; `main.rs` is the CLI).
- Every generated nft command carries its origin, for error attribution.
- Tests: real `nft` in unprivileged namespaces (JSON and text load identical kernel
  rulesets, revert guard, Save to System script), the rule evaluator checked against
  the kernel with real packets, the base rules tested across veth pairs, a root
  end-to-end kit for a disposable VM or container (`tools/e2e/`), and tests that can
  never elevate or touch the host firewall. CI also runs the suite with packager paths.
- Formatting with a pinned nightly rustfmt (grouped imports).

### Corrected descriptions

- **Anti-spoofing (RPF)** now reads "Drop new connections whose source address could not
  have arrived on that interface. Useful with rules that trust a source address. May
  block peers that contact a full-tunnel VPN first." Docker and libvirt bridges and VPNs
  are no longer said to break.
- **Strict ICMP** no longer claims to break network diagnostics: ping, traceroute and MTU
  discovery keep working; only rarely used types such as timestamp and address-mask
  requests are blocked.
- **ICMP rate limiting** says what it does: "Limit incoming ping requests to N per
  second".
- **Server Mode** is no longer "recommended for servers"; it says that outgoing
  connections need rules, and offers the essential ones.
- **Block forwarded traffic** says that Docker, VMs and VPN routing need Forwarded rules
  with it on (they can now be written).
- Success messages no longer claim the rules are saved or permanent.
