# DRFW — Dumb Rust Firewall

A minimal, safe, stateful nftables GUI for desktop Linux.

<p align="center">
  <a href="https://github.com/ledati16/drfw/actions/workflows/ci.yml"><img src="https://github.com/ledati16/drfw/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/Rust-1.100-orange.svg" alt="Rust: 1.100"></a>
  <a href="Cargo.toml#L9-L34"><img src="https://img.shields.io/badge/Pedantic-40_allows-green?logo=rust&logoColor=white" alt="Clippy Pedantic: 40 allows"></a>
  <a href="https://github.com/iced-rs/iced"><img src="https://img.shields.io/badge/Iced-0.14-blue?logo=iced&logoColor=white" alt="Iced 0.14"></a>
  <a href="#appendix-llm-generated-code"><img src="https://img.shields.io/badge/Vibe-Coded-blueviolet" alt="Vibe Coded"></a>
</p>

## Philosophy

DRFW follows the "dumb firewall" principle: **explicit is better than implicit**. No magic, no auto-detection, no surprises. You control exactly what's allowed through your firewall.

- **GUI-first**: Simple, focused interface for managing firewall rules
- **JSON-first**: Applies through nftables' JSON API (no shell interpolation, no command injection risks); the boot file is rendered from the very same commands
- **Safety-first**: Pre-apply verification and a root-side dead-man switch that auto-reverts even if DRFW or your SSH session dies
- **Desktop-friendly**: Conservative defaults that work out-of-the-box for most users

## Screenshots

<p align="center">
  <img src="assets/screenshot-oxide.png" width="600" alt="DRFW in Oxide theme">
</p>

## Features

### Core Functionality
- **Add/edit/delete firewall rules** via clean GUI
- **Protocol filtering**: TCP, UDP, TCP+UDP, ICMP (v4), ICMPv6, ICMP (both), or Any
- **Port matching**: Single port, range (`8000-8080`), or multiple (`22, 80, 443, 8000-8080`)
- **Source/Destination IP filtering**: Allow traffic from/to specific networks (CIDR notation, multiple IPs per rule)
- **Interface filtering**: Exact match (`eth0`) or wildcards (`docker*`, `veth*`)
- **Rule reordering**: Drag-and-drop to change rule priority
- **Enable/disable toggles**: Disable rules without deleting them
- **Tag-based organization**: Add multiple tags per rule, filter by tag
- **Search**: Real-time fuzzy search across all rule fields

### Advanced Rule Options
- **Action types**: Accept, Drop, or Reject (with type: port-unreachable, host-unreachable, admin-prohibited, tcp-reset)
- **Rate limiting**: Per-rule rate limits with optional burst (e.g., `5/minute burst 10`)
- **Connection limiting**: Max simultaneous connections per rule
- **Per-source limits** (Accept rules only): Optionally give every client IP (IPv6: every /64) its own rate or connection budget, so one client that uses up its budget does not use up everyone else's. Up to 65535 clients are tracked per rule; a flood from more distinct (e.g. spoofed) addresses than that blocks *new* clients until it stops, while known clients keep their budgets. Not offered for Drop/Reject rules: there a full table would let new sources through
- **Per-rule logging**: Toggle to log matched packets with auto-generated prefix
- **Chain selection**: Input or Output (Output only in Server Mode)
- **Output interface**: Filter outbound traffic by interface (Server Mode only)

### Safety Features
- **Rule validation**: Every rule is checked by one validator (ports, ranges, address families, interfaces, limits, ...). Invalid rules are kept in the profile and marked INVALID, but nothing is applied or saved while an applied rule is invalid
- **Pre-apply verification**: `nft --check` validates the generated ruleset before applying (unprivileged, in a private namespace, when possible)
- **Dead-man switch**: Configurable countdown (5-120s, on by default) with auto-revert if not confirmed. The revert is armed as root when the rules are applied, so it still happens if DRFW is closed or crashes, or the terminal/SSH session is lost, and it needs no second password prompt
- **Exact rollback**: The previous `inet drfw` table is restored exactly (or removed, if there was none)
- **Manual revert**: One-click rollback during the countdown
- **One generator**: Apply (JSON), the preview, `drfw export` and Save to System (text) all render the same command list, so what you see is what is applied and what boots
- **No silent data loss**: A damaged or newer-version profile/config is copied aside and opened read-only, never overwritten
- **Undo/Redo**: Full history for all rule modifications (Ctrl+Z / Ctrl+Shift+Z)
- **SSH lockout check**: Before Apply and Save to System, DRFW checks whether the new rules would keep the client of a current SSH session from reconnecting, and asks for an explicit confirmation if so (see [SSH lockout check](#ssh-lockout-check))

See [Safety Model](#safety-model) for how Apply, Confirm and the revert guard work.

### Default Protection (Always On)
DRFW is a **stateful firewall** with sensible defaults that require no configuration:

| Rule | Purpose |
|------|---------|
| Allow loopback | Local services always work (`127.0.0.1`) |
| Drop invalid packets | Malformed connections rejected early |
| Allow established/related | Return traffic for your connections works automatically |
| Allow DHCPv6 replies | IPv6 address configuration keeps working |
| Block ICMP redirects | Prevents classic MITM attacks |
| *(your rules)* | In the order you give them |
| Allow ICMP | Ping and network diagnostics work |
| Default deny | Everything else is blocked (INPUT chain) |

That is also the order in which they are checked. Your rules come before "Allow ICMP",
so a Drop or Reject rule (say, "drop everything from 203.0.113.7") also stops that
host's pings. They come after "Allow established/related", as in any stateful firewall:
a Drop rule stops **new** connections; connections that are already open (and ICMP
errors that belong to them) keep working until they close.

A Drop/Reject rule with both a rate limit and a connection limit drops what is over
either limit (it becomes two rules in the preview, one per limit).

Forwarded (routed) traffic is accepted by default so Docker, libvirt and VPN
routing keep working; see **Block forwarding** below.

These base rules are **not configurable** — they represent security best practices that 99%+ of users need. Without stateful filtering, you'd need explicit rules for every connection's return traffic.

### Advanced Security Settings
All disabled by default for maximum compatibility:

| Setting | Purpose | Warning |
|---------|---------|---------|
| **Strict ICMP** | Allow only ping + MTU discovery | Breaks network diagnostics |
| **ICMP Rate Limiting** | Prevent ping floods (IPv6 neighbor discovery, router advertisements and MLD queries are never limited) | May affect monitoring tools |
| **Anti-spoofing (RPF)** | Drop packets with spoofed source IPs | **Breaks Docker, VPNs, complex routing** |
| **Dropped Packet Logging** | Log filtered traffic to syslog | Can fill logs quickly |
| **Server Mode** | Block all outbound by default | Requires explicit egress rules |
| **Block forwarding** | Forward chain policy drop (established/related still accepted) | **Breaks Docker, libvirt and VPN routing**; for routers that want default-deny forwarding |

### Desktop vs Server Mode

| | Desktop (default) | Server |
|---|---|---|
| Incoming | Default deny + your rules | Default deny + your rules |
| Outgoing | Everything allowed | Default deny + your OUTPUT rules |
| Always allowed outgoing | - | Loopback, replies to accepted connections, IPv6 neighbor discovery, DHCP/DHCPv6 client requests |
| Rule chain choice | Input only | Input or Output |

Server Mode keeps loopback, established connections and address renewal (DHCP)
working, so switching it on does not cut off an SSH session or lose the lease.
OUTPUT rules in a profile are ignored (and not validated as applied) in Desktop
mode.

### User Experience
- **27 color themes**: Oxide, Dracula, Tokyo Night, Catppuccin, Nord, Gruvbox, Monochrome, and more
- **Accessibility options**: Monochrome theme and reduced syntax colors mode (2-level highlighting)
- **Custom fonts**: Select UI and monospace fonts from system fonts
- **Live preview**: Syntax-highlighted nftables output
- **Diff view**: See exactly what changes before applying
- **In-app notifications**: Success, warning, and error banners
- **Diagnostics viewer**: Built-in event log browser with filter and search, times in local time (with the date for older events)
- **Exposure view**: Lists the programs listening for connections on this computer (TCP and UDP, IPv4 and IPv6) and, for each, who can reach it through your rules: everyone, specific source networks, nobody, or local only (bound to loopback). Sockets open to everyone are flagged, rate- or interface-limited access is spelled out, and the deciding rule opens in the editor with one click. It compares the rules in the editor with the ones DRFW applied, so you can see what a change would expose before applying it. The socket list is read without privileges; process names are shown only for your own processes, because naming the processes behind other users' (e.g. system services') sockets needs root, which DRFW deliberately does not use for this. It also says, for each current SSH session, whether its client could open a new connection under the editor's rules (see [SSH lockout check](#ssh-lockout-check)). `drfw exposure` prints the same from the command line
- **Keyboard shortcuts**: Ctrl+N (new rule), Ctrl+S (apply), Ctrl+E (export), F1 (help)

### Profile Management
- **Multiple profiles**: Save different rule configurations
- **Quick switching**: Change profiles with unsaved-changes detection
- **Import/Export**: Export as nftables text or JSON

### CLI Interface
Full command-line support for scripting and automation:

```bash
drfw              # Launch GUI
drfw --help       # Show all commands
drfw list         # List all profiles
drfw status       # Active profile, rule/invalid counts, mode, pending auto-revert, boot config + service
drfw check <profile>                 # Validate + nft --check without privileges; changes nothing
drfw apply <profile>                 # Apply with 15s auto-revert safety
drfw apply <profile> --confirm 30    # Apply with 30s timeout (5-120)
drfw apply <profile> --no-confirm    # Apply without auto-revert (until reboot)
drfw apply <profile> --yes           # ... even if the retention guard or the SSH lockout check warns
drfw save <profile>                  # Save to System: the boot config (one prompt)
drfw save <profile> --enable-at-boot # ... and enable the boot service if needed
drfw export <profile> --format nft   # Export as nftables text (default)
drfw export <profile> --format json  # Export as nftables JSON
drfw exposure [profile]              # Who can reach the listening services (default: active profile)
drfw exposure [profile] --json       # ... as JSON, for scripts
```

- `drfw check` exits with 0 when the profile can be applied and 1 otherwise. It
  never asks for a password: the nft check runs in a private user + network
  namespace (`unshare -rn`).
- `drfw status` only reports what an unprivileged user can read: the profile, whether
  an apply is still waiting for confirmation (`/run/drfw`), whether
  `/etc/nftables.conf` was written by DRFW, and whether a systemd unit loads it at
  boot ("Boot persistence", from `systemctl is-enabled`). It does **not** read the live
  kernel ruleset (that needs root); run `sudo nft list table inet drfw` for that.
- `drfw apply` changes the running ruleset only. Use `drfw save` (or **Save to System**
  in the GUI) to make rules survive a reboot.
- `drfw save` writes the same file as the GUI's Save to System. The saved rules load at
  the next boot **without** a dead-man switch, so if the profile is not exactly what you
  last applied *and kept* on this machine (see [The kept-ruleset
  record](#the-kept-ruleset-record)), it warns and asks (or, without a terminal,
  refuses unless you pass `--yes`). The safe sequence on a server is `drfw apply web`,
  confirm, `drfw save web`. It warns when the boot service is not enabled;
  `--enable-at-boot` enables it in the same prompt.
- `drfw apply` and `drfw save` ask before a big change (see [Retention
  guard](#retention-guard)) and before rules that would lock out a current SSH session's
  client (see [SSH lockout check](#ssh-lockout-check)); without a terminal they need
  `--yes`.
- `drfw status` also has an "SSH" line per SSH session: "you are connected from X to port
  22; new connections from X would be accepted by rule "SSH"" (or BLOCKED, and by what),
  under the rules of the active profile.
- `drfw exposure` prints the Exposure view as a table: socket (protocol, port, family),
  process, bind address, who can reach it, and the deciding rule. Sockets every address
  can reach are marked `OPEN TO EVERYONE` (in red on a terminal; plain text when piped).
  The SSH lines of `drfw status` follow. `--json` prints an object with `profile`,
  `sockets` (one object per socket: `transport`, `port`, `families`, `bind`,
  `bind_display`, `local_only`, `uid`, `process`, `processes`, `reachable_from`,
  `open_to_everyone`, `nobody`, `decided_by`, `decided_by_rule_id`) and `ssh_sessions`
  (`client`, `client_port`, `server`, `server_port`, `source`, `new_connections` =
  `accepted`/`may_be_blocked`/`blocked`, `outcome`). It evaluates the profile's rules,
  not the kernel's (listing those needs root).
- During the `drfw apply` countdown, if another apply replaces the pending one, the
  countdown stops at once and reports it.

Exit codes (also in `drfw --help`):

| Code | Meaning |
|------|---------|
| 0 | Success: applied, confirmed, reverted (on timeout or on request), saved |
| 1 | Failed, nothing was changed (or `drfw check` found problems) |
| 2 | Usage error |
| 3 | `apply`: the previous rules could not be restored, so the drfw table was **removed**: drfw is not filtering anything |
| 4 | `apply`: the revert **failed**: the new, unconfirmed rules are still active |
| 5 | `apply`: another apply replaced these rules before they were confirmed |
| 6 | `apply`: the outcome is **unknown**: the new rules may be active (e.g. the apply was interrupted after authentication) |
| 7 | `save`: not saved, the rules are not the ones last applied and confirmed (use `--yes`) |
| 8 | `save`: saved, but the boot service could not be enabled |
| 9 | `apply`/`save`: not done, the retention guard or the SSH lockout check asks for a confirmation (use `--yes`) |

A timed-out revert exits 0: that is the dead-man switch doing its job. Codes 3 to 6 mean
"look at the firewall now"; scripts must not treat them like 1.
- Run `drfw` as your user, not with `sudo`: it asks for elevation itself, and under
  `sudo` it would look for profiles in root's home.

## Installation

### Prerequisites

**Required:**
- Linux kernel 4.14+ with nftables support
- `nftables` package installed
- Privilege escalation: `run0` (systemd v256+), `sudo`, or `pkexec`
- Rust 1.100 (2024 edition; pinned in `rust-toolchain.toml`) — Install via [rustup](https://rustup.rs)

**Check nftables:**
```bash
nft --version
```

**Install nftables:**
```bash
# Arch Linux
sudo pacman -S nftables

# Debian/Ubuntu
sudo apt install nftables

# Fedora
sudo dnf install nftables

# openSUSE
sudo zypper install nftables
```

### Building from Source

```bash
git clone https://github.com/ledati16/drfw.git
cd drfw
cargo build --release
./target/release/drfw
```

### System-wide Installation

```bash
sudo cp target/release/drfw /usr/local/bin/
drfw
```

## Usage

### Basic Workflow

1. **Launch DRFW**: `drfw`
2. **Add a rule**: Click **[+ Add Rule]**, configure protocol/port/source/interface
3. **Preview**: View syntax-highlighted nftables output in the preview pane
4. **Apply**: Click **[Apply]** — DRFW verifies, then applies with one elevation prompt
5. **Confirm**: Click **[Confirm]** within the countdown, or rules auto-revert
6. **Persist** (optional): **Save to System** (or `drfw save`) writes the rules to `/etc/nftables.conf` for boot

## Safety Model

**One prompt per apply.** Apply runs one fixed, elevated script that saves the
current `inet drfw` table (or notes that there is none) as a revert batch in
root-owned `/run/drfw`, starts a detached root watcher and only then applies the new
ruleset. Nothing else needs a password (DRFW ships no polkit rule that would cache an
authorization):

| Step | Prompt | What happens |
|------|--------|--------------|
| Verify | none (normally) | `nft --check` in a private namespace; only if that is inconclusive is the elevated check used |
| Apply | **one** | Save current table, apply, arm the revert guard |
| Confirm | none | DRFW creates a token file in your runtime directory; the watcher sees it |
| Revert now / timeout | none | The watcher restores the saved table |

**Works over SSH.** The watcher runs as root on its own (a `drfw-revert-*`
systemd unit, or a `setsid` process without systemd) and times out on the
monotonic clock. If you lock yourself out, the terminal closes, the SSH
connection drops or DRFW crashes, the previous rules come back on time. In a
terminal DRFW elevates with `run0` or `sudo`, so `drfw apply` works over SSH;
the GUI always uses `pkexec` (a graphical dialog), even when started from a terminal.

**No unguarded window.** The elevated script ignores hang-up, interrupt and terminate
signals, so an SSH drop or Ctrl-C right after the password cannot stop it halfway, and
the watcher exists before the new rules go live, so even a killed script leaves them
guarded. If DRFW cannot tell what happened after you authenticated (the script was
killed, or took more than 90 seconds), it says the state is **unknown** and that the
new rules may be active, instead of "nothing was changed"; a guarded apply then still
reverts when its countdown ends. In the GUI the banner stays short and opens **Apply
Details** with the full explanation (reopen it from the header button).

**Who can confirm.** Confirm and revert tokens are files in your `$XDG_RUNTIME_DIR`
(or DRFW's state directory), which must belong to you and be closed to other users
(mode 0700); the watcher only counts tokens owned by you. The guard's id is not a
secret (other local users can see it), so ownership is what protects it.

**Fail-safe revert.** If the saved table cannot be restored, the watcher removes the
`inet drfw` table instead (DRFW then filters nothing) rather than leave a locked-down
ruleset in place. Only if even that fails are the new rules reported as still active.

A new apply during a pending countdown replaces the earlier guard and keeps its
revert point: a timeout always goes back to the last *confirmed* rules.

### The kept-ruleset record

When you keep an apply (confirm it in time, or apply with auto-revert off, in the GUI or
with `drfw apply --no-confirm`), DRFW records it in
`~/.local/state/drfw/confirmed-ruleset.json` (mode 0600, written atomically): the exact
nftables JSON that was applied, the rules it came from, and the boot id. The GUI loads it
at startup and the CLI reads it, so both agree on what was last applied and kept.
Reverted, superseded or failed applies never change it. A profile counts as *tested*
when its nftables JSON is byte for byte the recorded one.

The record says what was **applied**, not what is running now: a reboot without Save to
System, `nft flush ruleset` or another tool can change the kernel's rules. When the
record is from an earlier boot (or from an older DRFW that did not store the boot id),
the Save to System dialog and `drfw save` say that it was kept in an earlier session and
may not be what is running.

`--no-confirm` counts as kept on purpose: it is the same explicit choice as turning
auto-revert off in the GUI, and a record left at an older ruleset would describe rules
that are no longer in place (and would make the retention guard compare against them).

### Retention guard

Before **Apply** and **Save to System** (GUI, `drfw apply`, `drfw save`), DRFW compares
the ruleset with the last one applied and kept, and asks for an explicit confirmation
when it:

- removes at least 3 of the enabled rules, and at least 40 % of them (rules are matched
  by id; disabling a rule counts as removing it);
- switches from Desktop to Server mode (outgoing connections need allow rules);
- turns on **Block forwarded traffic**.

The GUI lists the removed rules (the first 10, then "+N more") in the "Commit
Changes?" or Save to System dialog; applying then takes a click on **Apply anyway**
(Enter does not do it), and saving the editor's rules a click on a red button. The CLI
prints the same lines and asks y/N on a terminal; without one it needs `--yes` (exit
code 9 otherwise, nothing changed). With no record yet, only the two mode changes ask.

### SSH lockout check

Open SSH sessions survive any apply: established connections are accepted before any
of your rules (and before the output rules in Server mode, so Server mode cannot cut a
session's replies either). The risk is the **next** connection. Before **Apply** and
**Save to System** (GUI, `drfw apply`, `drfw save`) DRFW finds the current SSH sessions
into this computer without privileges and asks the rules about to be used what they do
with a new connection from each session's client address to the session's port:

- the session DRFW runs in, from `SSH_CONNECTION`;
- other sessions, from the established TCP connections in `/proc/net/tcp{,6}`: those
  held by a process named `sshd*`/`dropbear` (your own sessions are found this way), and
  those to port 22 (or to a port a readable `sshd` listens on) whose process belongs to
  another user. Other users' sessions on a non-standard port whose server is not
  readable are not found.

If a new connection would be dropped or rejected, or is accepted only under a
condition with a drop or reject behind it (a rate or connection limit, an interface the
check cannot know), the "Commit Changes?" (or Save to System) dialog shows why and takes
a click on **Apply anyway** (or the red save button); the CLI prints the same lines and
asks y/N on a terminal, or needs `--yes` (exit code 9, nothing changed). The interface
of a session is not known, so a rule that allows SSH only on one interface counts as
"blocked in some cases". The Exposure view and `drfw status` show the same per-session
answer.

## Save to System

**Save to System** makes the rules load at boot. Before you confirm, the dialog shows
whether the boot service (`nftables.service` by default) is enabled, asked without
privileges (`systemctl is-enabled`). If it is disabled, an **Also enable
nftables.service at boot** checkbox is offered, checked by default. Saving runs one
fixed, elevated script (one prompt) that:

1. writes the new file next to the target, then runs `nft -c -f` on **exactly those
   bytes** — a file nft rejects never replaces the current one;
2. copies the current file to `/etc/nftables.conf.drfw-bak` (the previous save);
3. the first time only, copies it to `/etc/nftables.conf.drfw-orig`, which is never
   overwritten, so your distribution's or hand-written config can always be recovered;
4. flushes the new file to disk and renames it into place atomically;
5. if the checkbox is checked, runs `systemctl enable nftables.service` (never `start`:
   that would reload the rules in the middle of your session). If enabling fails, the
   file is still saved and you get a warning.

Afterwards a banner says either "Loaded at boot by nftables.service" or that the rules
will **not** load at boot (service disabled, masked or missing).

The file starts with `table inet drfw` / `delete table inet drfw`, so loading it
(`nft -f /etc/nftables.conf`, `systemctl reload`) replaces only DRFW's table and never
duplicates rules. Enable `nftables.service` or the bundled `drfw.service` to load it at
boot (see [contrib/README.md](contrib/README.md)); DRFW counts either one as loading it.
`drfw status` tells you whether the current `/etc/nftables.conf` was written by DRFW
and whether it is loaded at boot.

To go back to the original config:

```bash
sudo cp -p /etc/nftables.conf.drfw-orig /etc/nftables.conf
```

### From the Command Line

`drfw save <profile>` does the same on a headless machine (one prompt). Because saved
rules load at boot without a dead-man switch, it warns loudly and asks (or needs
`--yes` without a terminal) unless the profile is exactly what you last applied and
kept (see [The kept-ruleset record](#the-kept-ruleset-record)); the [retention
guard](#retention-guard) applies too. It warns when the boot service is not enabled;
`--enable-at-boot` enables it in the same prompt. See the exit codes under [CLI
Interface](#cli-interface).

### Example Rules

**Allow SSH:**
- Protocol: TCP, Port: `22`

**Allow web server (HTTP + HTTPS in one rule):**
- Protocol: TCP, Port: `80, 443`

**Allow Minecraft from LAN only:**
- Protocol: TCP, Port: `25565`, Source: `192.168.1.0/24`

**Allow all Tailscale VPN traffic:**
- Protocol: Any, Interface: `tailscale0`

**Allow all Docker container traffic:**
- Protocol: Any, Interface: `docker*` (wildcard)

**Rate-limited SSH with burst (prevent brute force):**
- Protocol: TCP, Port: `22`, Rate Limit: `3/minute burst 5`, Per source address: on

**Block port scanners with admin-prohibited:**
- Protocol: TCP, Port: `23`, Action: Reject (admin-prohibited)

### NetworkManager Integration

DRFW's CLI makes automatic profile switching trivial. Create a dispatcher script:

```bash
# /etc/NetworkManager/dispatcher.d/99-drfw
#!/bin/bash
case "$2" in
    up)
        case "$1" in
            wlan0) /usr/local/bin/drfw apply public --no-confirm ;;
            eth0)  /usr/local/bin/drfw apply home --no-confirm ;;
        esac
        ;;
esac
```

```bash
sudo chmod +x /etc/NetworkManager/dispatcher.d/99-drfw
```

Dispatcher scripts run as root, so `drfw` reads root's profiles
(`/root/.local/share/drfw/profiles/`): copy the profiles there. `--no-confirm` is needed
because nobody is there to confirm.

### VPN Compatibility

DRFW creates its own nftables table (`drfw`) at **priority -10**, evaluated before other applications. VPN rules from Tailscale, WireGuard, etc. are preserved but DRFW has priority.

**Common VPN interfaces:**

| Application | Interface |
|-------------|-----------|
| Tailscale | `tailscale0` |
| WireGuard | `wg0` |
| OpenVPN | `tun0` / `tap0` |
| Docker | `docker0` |
| libvirt/KVM | `virbr0` |

**Warning:** Do NOT enable "Anti-spoofing (RPF)" if you use Docker or VPNs.

## Recovery

### Auto-Revert
If you don't confirm within the countdown (default 15s), rules automatically
revert. The revert runs as a separate root process (a `drfw-revert-*` systemd
unit, or a detached process without systemd), so closing DRFW or losing the
SSH connection does not stop it. Its outcome is recorded in
`/run/drfw/status-<id>`; `drfw status` shows whether one is still pending.

### Manual Revert
Click **[Rollback]** in the confirmation dialog (or press `r`/Esc/Ctrl-C in the CLI).

### Remove DRFW's Rules
```bash
# Removes only DRFW's table; other tables (docker, libvirt, ...) stay
sudo nft delete table inet drfw
```

### Restore the Boot Config
```bash
sudo cp -p /etc/nftables.conf.drfw-bak /etc/nftables.conf   # previous save
sudo cp -p /etc/nftables.conf.drfw-orig /etc/nftables.conf  # config before DRFW
```

### Audit Logs
```bash
jq . ~/.local/state/drfw/audit.log
```
The Diagnostics view (event log) shows the same events; **Clear Log** asks first and
leaves a "log cleared" entry as the first line of the new log.

## Configuration Files

| Purpose | Location |
|---------|----------|
| App config | `~/.local/share/drfw/config.json` |
| Profiles | `~/.local/share/drfw/profiles/*.json` |
| App log | `~/.local/state/drfw/drfw.log` (rotated to `drfw.log.1` past 5 MiB) |
| Audit log | `~/.local/state/drfw/audit.log` (rotated to `audit.log.old` past 1 MiB, at startup) |
| Revert guard state (root, tmpfs) | `/run/drfw/` (`active`, `status-<id>`, revert batches) |
| Confirm/revert tokens | `$XDG_RUNTIME_DIR` (else the state directory); must be yours, mode 0700 |
| Last ruleset applied and kept (GUI and CLI) | `~/.local/state/drfw/confirmed-ruleset.json` |
| Boot config (Save to System) | `/etc/nftables.conf`, plus `.drfw-bak` and `.drfw-orig` |

All files in your home are created with `0o600` permissions, directories with `0o700`. A
profile or config file that can't be read (damaged, or saved by a newer DRFW) is never
overwritten silently: it is copied to `<file>.corrupt-<timestamp>` first, and the profile
opens read-only.

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| **Ctrl+N** | Add new rule |
| **Ctrl+S** | Apply changes |
| **Ctrl+E** | Export rules |
| **Ctrl+Z** | Undo |
| **Ctrl+Shift+Z** / **Ctrl+Y** | Redo |
| **Enter** | Save the rule form (when it is the top-most dialog) |
| **Esc** | Close the top-most dialog only (never cancels a running apply or countdown) |

Shortcuts are ignored while you are typing in a text field inside a dialog.
| **F1** | Show shortcuts |

## Known Limitations

These are intentional design decisions:

- **Single table**: DRFW manages `drfw` table only, doesn't modify others
- **No custom chains**: All rules in input/output/forward chains
- **No ICMP type filtering**: Only strict (essential types) or permissive (all)
- **No MAC filtering**: Easily spoofed, LAN-only
- **No time-based rules**: Use cron/systemd timers with CLI instead

### IPv4 vs IPv6

DRFW uses the `inet` family (dual-stack by default). Rules automatically apply to the correct IP version based on your source/destination addresses:

| Source/Dest IP | Applies To |
|----------------|------------|
| `192.168.1.0/24` | IPv4 only |
| `fd00::/8` | IPv6 only |
| `0.0.0.0/0` | IPv4 only (explicit wildcard) |
| `::/0` | IPv6 only (explicit wildcard) |
| *(empty)* | Both IPv4 and IPv6 |

This means most rules "just work" for both protocols without extra configuration.

## Packaging

### Compile-Time Configuration

Distro packagers adapt DRFW to the distribution's layout with environment variables
read at **build** time (see `src/distro.rs`):

| Variable | Default | Purpose |
|----------|---------|---------|
| `DRFW_SYSTEM_NFT_PATH` | `/etc/nftables.conf` | File Save to System writes |
| `DRFW_SYSTEM_NFT_SERVICE` | `nftables.service` | systemd unit that loads that file at boot (reported, and optionally enabled) |
| `DRFW_NFT_PATH` | unset | Absolute `nft` path. Unset: the no-prompt check searches `/usr/sbin`, `/sbin`, `/usr/bin`, and elevated commands run plain `nft` |

Values are checked at compile time and a bad one fails the build: paths must be
absolute and use only `A-Z a-z 0-9 / . _ @ + -` (the characters DRFW's root scripts
accept), the service must be a unit name ending in `.service`. An empty value counts
as unset.

```bash
# Arch, Debian, Ubuntu (defaults; DRFW_NFT_PATH recommended, see the table below)
cargo build --release

# Fedora/RHEL
DRFW_SYSTEM_NFT_PATH=/etc/sysconfig/nftables.conf DRFW_NFT_PATH=/usr/sbin/nft \
cargo build --release

# Custom setup: DRFW's own file, loaded by DRFW's own unit
DRFW_SYSTEM_NFT_PATH=/etc/drfw/rules.nft \
DRFW_SYSTEM_NFT_SERVICE=drfw.service \
cargo build --release
./target/release/drfw print-service-unit | sudo tee /etc/systemd/system/drfw.service
```

In the custom setup, Save to System creates `/etc/drfw/` if needed, and its **Also
enable drfw.service at boot** checkbox enables the unit you just installed.

### The systemd Unit

`contrib/drfw.service.in` is a template with `@SYSTEM_NFT_PATH@` and `@NFT_PATH@`.
Generate the unit from the **built binary**, which fills in its own compile-time values,
so the unit and Save to System can never disagree about the file:

```bash
target/release/drfw print-service-unit > drfw.service   # hidden command, for packagers
install -Dm644 drfw.service "$pkgdir/usr/lib/systemd/system/drfw.service"
```

`@NFT_PATH@` becomes `DRFW_NFT_PATH`, or `/usr/sbin/nft` when that is unset.
`print-service-unit` creates no files or directories, so it is safe to run in
`package()`.

### Per-Distribution Notes

| Distribution | Config (`DRFW_SYSTEM_NFT_PATH`) | Service | `nft` (`DRFW_NFT_PATH`) | Caveats |
|--------------|-------------------------------|---------|-------------------------|---------|
| Arch | `/etc/nftables.conf` (default) | `nftables.service` (default; not enabled after install) | `/usr/bin/nft` | `contrib/PKGBUILD` sets these. `/usr/sbin` is a symlink to `/usr/bin`. |
| Debian / Ubuntu | `/etc/nftables.conf` (default) | `nftables.service` (default) | `/usr/sbin/nft` | Set `DRFW_NFT_PATH`: `/usr/sbin` is not on a normal user's `PATH`, so a bare `pkexec nft` (the elevated fallback check) may not find nft. Ubuntu ships `ufw`, which is a second firewall if it is active (`sudo ufw status`). |
| Fedora / RHEL | `/etc/sysconfig/nftables.conf` | `nftables.service` (default) | `/usr/sbin/nft` | The distribution's file holds only comments and `include` lines for the samples in `/etc/nftables/`. Save to System replaces the whole file, so those includes are no longer loaded; the original stays in `/etc/sysconfig/nftables.conf.drfw-orig`. `firewalld` is enabled by default and manages its own tables; decide which one owns the firewall. |
| openSUSE | check your distro | check your distro | `/usr/sbin/nft` | `firewalld` is the usual default firewall. Check which file and unit the `nftables` package ships before overriding the defaults. |
| NixOS | see below | see below | `/run/current-system/sw/bin/nft` | Declarative `networking.nftables` owns the ruleset; see below. |

**NixOS.** With `networking.nftables.enable`, NixOS generates the ruleset and its
own `nftables.service` from your configuration: an imperatively written
`/etc/nftables.conf` is not what it loads, and the units NixOS manages are not meant to
be changed with `systemctl enable`. The recommended way is to keep DRFW for designing and testing rules
(Apply works on the live kernel) and put the exported rules into your configuration:

```bash
drfw export my-profile --format nft > /etc/nixos/drfw.nft
```

```nix
networking.nftables.enable = true;
networking.nftables.ruleset = builtins.readFile ./drfw.nft;
```

Note that the NixOS firewall (`networking.firewall`) adds its own tables when
nftables is enabled. If you prefer Save to System on NixOS, build with
`DRFW_SYSTEM_NFT_PATH=/var/lib/drfw/rules.nft DRFW_SYSTEM_NFT_SERVICE=drfw.service
DRFW_NFT_PATH=/run/current-system/sw/bin/nft`, leave `networking.nftables` off, and
declare `drfw.service` in your configuration (from `drfw print-service-unit`, with
`wantedBy = [ "multi-user.target" ]`) instead of using the "enable at boot" checkbox.
This setup is untested: DRFW's elevated scripts call coreutils and `systemctl` by name,
and some elevation tools reset `PATH` to directories that are empty on NixOS; check
your setup.

## Development

### Project Structure

```
src/
├── main.rs              # CLI front end (commands, countdown); everything else is the library
├── lib.rs               # Library root: all modules, `run_gui()`
├── distro.rs            # Compile-time paths/service for packagers, `print-service-unit`
├── build_info.rs        # Version strings (git commit, build time) from build.rs
├── app/                 # GUI application (private to the library)
│   ├── mod.rs          # State machine, messages
│   ├── view/           # UI components (sidebar, workspace, forms, modals)
│   └── handlers/       # Message handlers by domain
├── core/               # Firewall logic (GUI-independent)
│   ├── firewall.rs     # Rule model, command list, JSON output
│   ├── nft_text.rs     # Text (`nft -f`) rendering of the same commands
│   ├── validate.rs     # The rule/ruleset validator
│   ├── verify.rs       # Pre-apply `nft --check`
│   ├── apply_guard.rs  # Apply + root-side revert guard
│   ├── confirmed.rs    # Record of the last ruleset applied and kept
│   ├── retention.rs    # Confirmation before a big change
│   ├── evaluate.rs     # What the input chain does with a new connection
│   ├── exposure.rs     # Listening sockets (/proc) and who can reach them
│   ├── lockout.rs      # SSH sessions and the lockout check
│   ├── system_config.rs # Save to System
│   ├── boot.rs         # Boot persistence (`systemctl is-enabled`, unprivileged)
│   └── profiles.rs     # Profile persistence
├── theme/              # 27 color themes + accessibility
├── config.rs           # Application configuration
├── validators.rs       # Input validation
├── audit.rs            # Audit logging
└── elevation.rs        # Privilege escalation, fixed apply/watcher/save scripts
tests/
├── integration_tests.rs # Mock-nft flows, save script + fake systemctl, CLI binary (`status`, `check`, `apply`, `save`, `exposure`)
├── evaluate.rs          # Rule evaluator vs. the real kernel (unshare -rn)
├── profile_storage.rs   # Profile/config files on disk
└── real_nft.rs          # Real nft in an unprivileged namespace (unshare -rn)
```

### Running Tests

```bash
cargo test                    # All tests (mock nft; real-nft tests skip if unavailable)
DRFW_REQUIRE_REAL_NFT=1 cargo test  # Fail instead of skipping the real-nft tests (CI)
cargo test --test integration_tests # Integration tests only
cargo clippy --all-targets -- -D warnings  # Lint (pedantic enabled in Cargo.toml)
cargo +nightly-2026-11-14 fmt --check  # Format check (nightly rustfmt)
cargo deny check              # Advisories and licenses (deny.toml)
```

The real-nft tests need `nft` and unprivileged user namespaces; they never need root
and never touch the host firewall. The toolchain is pinned in `rust-toolchain.toml`.

### Code Quality

DRFW maintains strict standards:
- Unit, integration, property-based and real-nft tests (JSON vs text output are checked to load identical kernel rulesets)
- Clippy pedantic with 40 documented allows
- Security-first: no shell interpolation, allowlist validation, atomic writes
- Performance: cached rendering, debounced saves, pre-computed display strings

## Security

### Threat Model

DRFW protects against:
- Command injection (JSON API only, no shell interpolation)
- Path traversal (validated paths, XDG directories)
- Unicode bypass attacks (ASCII-only for system identifiers)
- TOCTOU races (atomic file writes)
- Privilege escalation abuse (explicit elevation, argument validation, fixed elevated scripts that never interpolate user data)
- Lockout (root-side auto-revert that needs no second prompt)
- Broken boot config (the exact bytes are checked with `nft -c` before replacing it; the original is kept)

## License

MIT License — see [LICENSE](LICENSE)

## Acknowledgments

- [Iced](https://github.com/iced-rs/iced) — GUI framework (also used by COSMIC DE)
- [nftables](https://netfilter.org/projects/nftables/) — Modern Linux firewall
- Inspired by UFW's simplicity and firewalld's safety features

---

**DRFW**: Keep it simple. Keep it safe. Keep it dumb.

---

## Appendix: LLM-Generated Code

> ⚠️ **Important Disclosure**

This project was **entirely generated by LLMs** (mainly Claude models) by someone without Rust experience.

**Key facts:**
- **100% LLM-generated**, no peer review by Rust developers
- Works as intended with no malicious code, but use with caution
- Personal tool, not production-grade software
- **Do not package for distributions** without peer review

**Code quality:**
- **Pedantic clippy** with only 40 documented allows (strict linting enforced)
- **Safe architecture**: JSON API only, atomic config writes, pre-apply verification with auto-revert
- Comprehensive test suite with strict isolation (mock nft, temp dirs, private network namespaces)
- See [CLAUDE.md](CLAUDE.md) for development standards

[Discussions](https://github.com/ledati16/drfw/discussions) open for community review.

**Fork and rename** if you want to maintain/improve this project (link back appreciated).

---

**License:** [LICENSE](LICENSE) • **Discussions:** [GitHub](https://github.com/ledati16/drfw/discussions)
