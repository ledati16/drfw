# DRFW — Dumb Rust Firewall

A minimal, safe, stateful nftables GUI for desktop Linux.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Rust](https://img.shields.io/badge/rust-1.83%2B-orange.svg)

## Philosophy

DRFW follows the "dumb firewall" principle: **explicit is better than implicit**. No magic, no auto-detection, no surprises. You control exactly what's allowed through your firewall.

- **GUI-first**: Simple, focused interface for managing firewall rules
- **JSON-first**: Uses nftables' JSON API exclusively (no shell interpolation, no command injection risks)
- **Safety-first**: Automatic snapshots, pre-apply verification, and dead-man switch with auto-revert
- **Desktop-friendly**: Conservative defaults that work out-of-the-box for most users

## Features

### Core Functionality
- ✅ **Add/edit/delete firewall rules** via clean GUI
- ✅ **Service presets** (SSH, HTTP, HTTPS, DNS, Minecraft, Plex, WireGuard)
- ✅ **Protocol filtering** (TCP, UDP, ICMP, ICMPv6, or Any)
- ✅ **Port ranges** (single port or range)
- ✅ **Source IP/CIDR filtering** (allow from specific networks)
- ✅ **Interface filtering** (allow traffic on specific network interfaces)
- ✅ **Rule reordering** and enable/disable toggles

### Safety Features
- ✅ **Pre-apply verification** using `nft --check` before applying rules
- ✅ **Automatic snapshot** before every apply
- ✅ **Dead-man switch**: 15-second countdown with auto-revert if not confirmed
- ✅ **Manual revert**: One-click restore to previous snapshot
- ✅ **Audit logging**: All privileged operations logged to `~/.local/state/drfw/audit.log`

### Advanced Security (Optional, All Disabled by Default)
- ⚙️ **Strict ICMP filtering** (essential types only)
- ⚙️ **ICMP rate limiting** (prevent ping floods)
- ⚙️ **Anti-spoofing (RPF)** - ⚠️ Breaks Docker/VPNs
- ⚙️ **Dropped packet logging** with rate limiting
- ⚙️ **Egress filtering** (Desktop vs Server profiles)
- ⚙️ **ICMP redirect blocking** (prevents MITM attacks)

### User Experience
- 🎨 **Modern dark theme** with syntax-highlighted nftables preview
- 📋 **Live preview** of generated rules (both nftables text and JSON)
- ⚡ **Inline validation** with helpful error messages
- 💾 **Persistent configuration** saved to `~/.local/share/drfw/ruleset.json`

## Installation

### Prerequisites

**Required:**
- Linux kernel 4.14+ with nftables support
- `nftables` package installed
- Privilege escalation: `run0` (preferred, systemd v256+) OR `pkexec` (GUI) OR `sudo` (CLI)
- Rust 1.83+ (for building from source)

**Check if nftables is installed:**
```bash
nft --version
```

**Install nftables if needed:**
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
# Clone the repository
git clone https://github.com/yourusername/drfw.git
cd drfw

# Build release binary
cargo build --release

# Run
./target/release/drfw
```

### Installation (System-wide)

```bash
# After building, install to /usr/local/bin
sudo cp target/release/drfw /usr/local/bin/

# Run from anywhere
drfw
```

## Usage

### Basic Workflow

1. **Launch DRFW**
   ```bash
   drfw
   ```

2. **Add a rule**
   - Click **[+ Add Rule]**
   - Select a preset (e.g., SSH) or configure manually:
     - **Protocol**: TCP, UDP, ICMP, or Any
     - **Ports**: Single port (e.g., `22`) or range (e.g., `8000-8080`)
     - **Source**: Leave empty for "Any", or specify CIDR (e.g., `192.168.1.0/24`)
     - **Interface**: Leave empty or specify (e.g., `eth0`, `tailscale0`)
     - **Label**: Optional description (e.g., "SSH from home network")
   - Click **Add**

3. **Preview rules**
   - View syntax-highlighted nftables text in the **Nftables Preview** tab
   - View raw JSON in the **JSON View** tab

4. **Apply changes**
   - Click **[Apply]**
   - DRFW will:
     - Verify rules using `nft --check`
     - Create a snapshot of current rules
     - Apply new rules with `pkexec`
     - Start a 15-second countdown
   - **Confirm** within 15 seconds, or rules will **auto-revert**

5. **Save to system** (optional)
   - If you want rules to persist across reboots
   - Settings → **Save to System** (writes to `/etc/nftables.conf`)

### Example Rules

**Allow SSH from anywhere:**
- Protocol: TCP
- Port: 22
- Label: "SSH"

**Allow HTTP/HTTPS for web server:**
- Protocol: TCP
- Ports: 80 (add another rule for 443)
- Label: "Web Server"

**Allow Minecraft server from local network only:**
- Protocol: TCP
- Port: 25565
- Source: `192.168.1.0/24`
- Label: "Minecraft (LAN only)"

**Allow all traffic from Tailscale VPN:**
- Protocol: Any
- Interface: `tailscale0`
- Label: "Tailscale VPN"

## VPN and Network Application Compatibility

### How DRFW Interacts with Other Applications

DRFW creates its own nftables table (`drfw`) at **priority -10**, which means DRFW rules are evaluated **FIRST**, before other applications like Tailscale, Docker, or WireGuard.

**This is intentional**: DRFW is your primary firewall. Other applications' nftables rules are **NOT destroyed**, but DRFW has priority in rule evaluation.

### Using DRFW with VPNs (Tailscale, WireGuard, etc.)

To allow VPN traffic, create an **interface-based rule**:

1. Click **[+ Add Rule]**
2. Set **Protocol** to "Any"
3. Set **Interface** to your VPN interface (see table below)
4. Leave **Ports** and **Source** empty
5. Set **Label** to describe the VPN (e.g., "Tailscale VPN")
6. Click **Add**

This creates a rule: `iifname "tailscale0" accept`

**Common VPN interfaces:**

| Application | Interface Name | Alternative |
|-------------|----------------|-------------|
| Tailscale   | `tailscale0`   | -           |
| WireGuard   | `wg0`          | `wg1`, etc. |
| OpenVPN     | `tun0`         | `tap0`      |
| Docker      | `docker0`      | -           |
| libvirt/KVM | `virbr0`       | -           |

**Alternatively**, you can allow specific VPN ports:
- Tailscale: UDP 41641
- WireGuard: UDP 51820 (or your configured port)
- OpenVPN: UDP 1194 or TCP 443 (varies by config)

### ⚠️ Docker Compatibility

**Do NOT enable "Anti-spoofing (RPF)"** in Advanced Settings if you use Docker. RPF breaks Docker's network routing.

To allow Docker containers to communicate:
- Add an interface rule for `docker0`
- Or add specific port rules for services running in containers

### Why No Auto-Detection?

DRFW follows the "dumb firewall" philosophy: **explicit is better than implicit**. You control exactly what's allowed. No magic, no surprises, no security holes from auto-allowing things you didn't know about.

## Recovery Procedures

### If You Lock Yourself Out

**Scenario**: You applied rules that blocked your SSH connection or can't confirm within 15 seconds.

**Solution 1: Auto-revert**
- Wait 15 seconds. DRFW will automatically revert to the previous snapshot.

**Solution 2: Manual revert via GUI**
- If the GUI is accessible, click **[Revert]** in the confirmation dialog.

**Solution 3: Manual revert via console**
1. Access the machine physically or via console
2. Find the latest snapshot:
   ```bash
   ls -lt ~/.local/state/drfw/
   ```
3. Restore the snapshot:
   ```bash
   sudo nft -f ~/.local/state/drfw/snapshot-<UUID>.nft
   ```
   Or if you have the JSON snapshot:
   ```bash
   sudo nft --json -f ~/.local/state/drfw/snapshot-<UUID>.json
   ```

**Solution 4: Emergency flush**
If snapshots are corrupted or unavailable:
```bash
# WARNING: This removes ALL firewall rules (allows everything)
sudo nft flush ruleset
```

Then reboot or restart networking to restore default distro firewall rules.

### Check Audit Logs

DRFW logs all operations to `~/.local/state/drfw/audit.log`:
```bash
cat ~/.local/state/drfw/audit.log | jq
```

Logs include timestamps, rule counts, snapshot locations, and error messages.

## Configuration Files

DRFW uses the XDG Base Directory specification:

| File/Directory | Location | Purpose |
|----------------|----------|---------|
| Configuration | `~/.local/share/drfw/ruleset.json` | Persistent rule configuration |
| Snapshots | `~/.local/state/drfw/snapshot-*.json` | Pre-apply snapshots for recovery |
| Audit log | `~/.local/state/drfw/audit.log` | JSON-lines log of all operations |
| Application log | `~/.local/state/drfw/drfw.log` | Debug/error logs |

All files have `0o600` (user-only) permissions for security.

## Advanced Settings

Access via **Settings** tab in the GUI.

### ⚠️ Warning: Advanced Settings Can Break Things

All advanced settings are **OFF by default** for desktop compatibility. Only enable if you understand the implications.

| Setting | Default | What It Breaks |
|---------|---------|----------------|
| **Strict ICMP** | OFF | Network diagnostics, some games |
| **ICMP Rate Limiting** | 0 (disabled) | High-frequency ping tools |
| **Anti-spoofing (RPF)** | OFF | Docker, VPNs, complex routing |
| **Dropped Packet Logging** | OFF | Fills logs, impacts performance |
| **Egress Filtering (Server mode)** | Desktop | All outbound connections must be explicitly allowed |

### When to Use Server Mode

**Desktop mode** (default): All outbound connections are allowed. Suitable for workstations, gaming PCs, laptops.

**Server mode**: All outbound connections are blocked by default. You must explicitly allow outbound traffic. Suitable for public-facing servers where you want tight control.

## Development

### Project Structure

```
src/
  main.rs              # Entry point
  app/                 # GUI (Iced)
    mod.rs             # State machine, message handling
    view.rs            # UI layout and rendering
    ui_components.rs   # Reusable widgets
  core/                # Firewall logic (GUI-independent)
    firewall.rs        # Rule model, JSON generation
    nft_json.rs        # nftables JSON API integration
    verify.rs          # Pre-apply verification
    error.rs           # Error handling and translation
    tests.rs           # Unit + integration + property tests
  config.rs            # Persistent configuration
  validators.rs        # Input validation/sanitization
  audit.rs             # Audit logging
  elevation.rs         # Privilege escalation (pkexec)
  utils.rs             # Helpers
```

### Running Tests

```bash
# Run all tests
cargo test

# Run with privileges (for integration tests)
sudo -E cargo test

# Run specific test suite
cargo test --test core

# Run property-based tests (fuzzing)
cargo test proptest
```

**Test coverage**: 67 tests (unit + integration + property-based)

### Code Quality

```bash
# Format code
cargo fmt

# Lint with Clippy (pedantic mode)
cargo clippy -- -D warnings

# Build for release
cargo build --release
```

### Contributing

DRFW follows strict coding standards documented in `CLAUDE.md`:
- Security-first: No shell interpolation, allowlist-based validation, atomic file writes
- Test coverage: Unit tests, integration tests, property-based tests for all validators
- Documentation: Public APIs documented with examples
- Error handling: User-friendly translations for all errors

## Security

### Threat Model

DRFW is designed to protect against:
- ✅ Command injection (via JSON-first nftables API, no shell interpolation)
- ✅ Path traversal (validated paths, XDG directories)
- ✅ Shell metacharacter injection (comprehensive input sanitization)
- ✅ Unicode bypass attacks (ASCII-only validation for system identifiers)
- ✅ TOCTOU races (atomic file writes with permissions set before data)
- ✅ Privilege escalation abuse (explicit pkexec, argument validation)

### Reporting Security Issues

If you discover a security vulnerability, please email: [your-email@example.com]

Do NOT open a public issue for security vulnerabilities.

## Known Limitations

- **No IPv4/IPv6 split rules**: Rules apply to both IPv4 and IPv6 (inet family)
- **Input chain only**: Only filters incoming traffic (no OUTPUT or FORWARD chain rules)
- **Single table**: DRFW manages one table (`drfw`), doesn't modify other tables
- **No stateful tracking configuration**: Established/related tracking is always enabled
- **No custom chains**: All rules go in the `input` chain

Most of these are intentional design decisions to keep DRFW simple and safe.

## Roadmap

See `PLAN_DRFW.md` and `FUTURE_PLAN.md` for detailed development plans.

**Upcoming features:**
- Desktop notifications with action buttons
- Diff view (current vs pending rules)
- Diagnostics modal (audit log viewer)
- Export functionality (save rules to file)
- Multiple snapshot generations (keep last 5)
- Keyboard shortcuts

## License

MIT License - see [LICENSE](LICENSE) for details

## Acknowledgments

- Built with [Iced](https://github.com/iced-rs/iced) GUI framework
- Uses [nftables](https://netfilter.org/projects/nftables/) for firewall management
- Inspired by UFW's simplicity and firewalld's safety features

## Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/drfw/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/drfw/discussions)
- **Documentation**: See `PLAN_DRFW.md` for architecture details

---

**DRFW**: Keep it simple. Keep it safe. Keep it dumb.
