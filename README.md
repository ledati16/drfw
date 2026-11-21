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

See [Safety Model](#safety-model) for how Apply, Confirm and the revert guard work.

### Default Protection (Always On)
DRFW is a **stateful firewall** with sensible defaults that require no configuration:

| Rule | Purpose |
|------|---------|
| Allow loopback | Local services always work (`127.0.0.1`) |
| Drop invalid packets | Malformed connections rejected early |
| Allow established/related | Return traffic for your connections works automatically |
| Block ICMP redirects | Prevents classic MITM attacks |
| Allow ICMP | Ping and network diagnostics work |
| Allow DHCPv6 replies | IPv6 address configuration keeps working |
| Default deny | Everything else is blocked (INPUT chain) |

Forwarded (routed) traffic is accepted by default so Docker, libvirt and VPN
routing keep working; see **Block forwarding** below.

These base rules are **not configurable** — they represent security best practices that 99%+ of users need. Without stateful filtering, you'd need explicit rules for every connection's return traffic.

### Advanced Security Settings
All disabled by default for maximum compatibility:

| Setting | Purpose | Warning |
|---------|---------|---------|
| **Strict ICMP** | Allow only ping + MTU discovery | Breaks network diagnostics |
| **ICMP Rate Limiting** | Prevent ping floods | May affect monitoring tools |
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
drfw status       # Active profile, rule/invalid counts, mode, pending auto-revert, boot config
drfw check <profile>                 # Validate + nft --check without privileges; changes nothing
drfw apply <profile>                 # Apply with 15s auto-revert safety
drfw apply <profile> --confirm 30    # Apply with 30s timeout (5-120)
drfw apply <profile> --no-confirm    # Apply without auto-revert (until reboot)
drfw export <profile> --format nft   # Export as nftables text (default)
drfw export <profile> --format json  # Export as nftables JSON
```

- `drfw check` exits with 0 when the profile can be applied and 1 otherwise. It
  never asks for a password: the nft check runs in a private user + network
  namespace (`unshare -rn`).
- `drfw status` only reports what an unprivileged user can read: the profile, whether
  an apply is still waiting for confirmation (`/run/drfw`), and whether
  `/etc/nftables.conf` was written by DRFW. It does **not** read the live kernel
  ruleset (that needs root); run `sudo nft list table inet drfw` for that.
- `drfw apply` changes the running ruleset only. Use **Save to System** (GUI) to make
  rules survive a reboot.
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
6. **Persist** (optional): **Save to System** writes the rules to `/etc/nftables.conf` for boot

## Safety Model

**One prompt per apply.** Apply runs one fixed, elevated script that saves the
current `inet drfw` table (or notes that there is none) as a revert batch in
root-owned `/run/drfw`, applies the new ruleset and starts a detached root
watcher. Nothing else needs a password:

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
`pkexec` is used for the GUI.

**Fail-safe revert.** If the saved table cannot be restored, the watcher removes the
`inet drfw` table instead (DRFW then filters nothing) rather than leave a locked-down
ruleset in place. Only if even that fails are the new rules reported as still active.

A new apply during a pending countdown replaces the earlier guard and keeps its
revert point: a timeout always goes back to the last *confirmed* rules.

## Save to System

**Save to System** makes the rules load at boot. It runs one fixed, elevated
script (one prompt) that:

1. writes the new file next to the target, then runs `nft -c -f` on **exactly those
   bytes** — a file nft rejects never replaces the current one;
2. copies the current file to `/etc/nftables.conf.drfw-bak` (the previous save);
3. the first time only, copies it to `/etc/nftables.conf.drfw-orig`, which is never
   overwritten, so your distribution's or hand-written config can always be recovered;
4. flushes the new file to disk and renames it into place atomically.

The file starts with `table inet drfw` / `delete table inet drfw`, so loading it
(`nft -f /etc/nftables.conf`, `systemctl reload`) replaces only DRFW's table and never
duplicates rules. Enable `nftables.service` or the bundled `contrib/drfw.service` to
load it at boot (see [contrib/README.md](contrib/README.md)). `drfw status` tells you
whether the current `/etc/nftables.conf` was written by DRFW.

To go back to the original config:

```bash
sudo cp -p /etc/nftables.conf.drfw-orig /etc/nftables.conf
```

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
- Protocol: TCP, Port: `22`, Rate Limit: `3/minute burst 5`

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
| Confirm/revert tokens | `$XDG_RUNTIME_DIR` (else the state directory) |
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

Distro packagers can customize paths at build time using environment variables:

| Variable | Default | Purpose |
|----------|---------|---------|
| `DRFW_SYSTEM_NFT_PATH` | `/etc/nftables.conf` | System nftables config path |
| `DRFW_SYSTEM_NFT_SERVICE` | `nftables.service` | Systemd service name |

**Examples:**

```bash
# Debian/Ubuntu/Arch (default)
cargo build --release

# Fedora/RHEL
DRFW_SYSTEM_NFT_PATH=/etc/sysconfig/nftables.conf cargo build --release

# Custom setup
DRFW_SYSTEM_NFT_PATH=/etc/drfw/rules.nft \
DRFW_SYSTEM_NFT_SERVICE=drfw.service \
cargo build --release
```

The configured path is baked into the binary at compile time and shown in the UI when using "Save to System".

## Development

### Project Structure

```
src/
├── main.rs              # CLI front end (commands, countdown); everything else is the library
├── lib.rs               # Library root: all modules, `run_gui()`, compile-time paths
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
│   ├── system_config.rs # Save to System
│   └── profiles.rs     # Profile persistence
├── theme/              # 27 color themes + accessibility
├── config.rs           # Application configuration
├── validators.rs       # Input validation
├── audit.rs            # Audit logging
└── elevation.rs        # Privilege escalation, fixed apply/watcher/save scripts
tests/
├── integration_tests.rs # Mock-nft flows, CLI binary (`status`, `check`)
├── profile_storage.rs   # Profile/config files on disk
└── real_nft.rs          # Real nft in an unprivileged namespace (unshare -rn)
```

### Running Tests

```bash
cargo test                    # All tests (mock nft; real-nft tests skip if unavailable)
DRFW_REQUIRE_REAL_NFT=1 cargo test  # Fail instead of skipping the real-nft tests (CI)
cargo test --test integration_tests # Integration tests only
cargo clippy --all-targets -- -D warnings  # Lint (pedantic enabled in Cargo.toml)
cargo fmt --check             # Format check
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
