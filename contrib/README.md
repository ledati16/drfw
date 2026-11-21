# DRFW Contrib Files

This directory contains distribution packaging and system integration files.

## Contents

- `PKGBUILD` - Arch Linux package build file (fill in the `Maintainer` line)
- `drfw.service` - systemd service for boot-time firewall
- `drfw.desktop` - Desktop entry for application menus
- `50-drfw.rules` - polkit rule: caches the `nft --check` fallback, never `/bin/sh`
- `icons/` - application icons (`drfw-<size>.png` to install, `drfw.svg` is the
  editing source only; see `icons/README.md`)

## Arch Linux (PKGBUILD)

Build and install from source using the provided PKGBUILD:

```bash
cd contrib
makepkg -si
```

This installs:
- `/usr/bin/drfw` - the main binary
- `/usr/share/applications/drfw.desktop` - desktop entry
- `/usr/share/icons/hicolor/<N>x<N>/apps/drfw.png` - icons, N = 16 24 32 48 64 128 256 512
- `/usr/lib/systemd/system/drfw.service` - systemd service (not enabled)
- `/usr/share/polkit-1/rules.d/50-drfw.rules` - polkit rule
- `/usr/share/licenses/drfw-git/LICENSE` - license file

`check()` runs `cargo test` as the build user. It needs `jq` (for the mock nft)
and uses the real `nft` only inside an unprivileged user + network namespace
(`unshare -rn`); where that is unavailable those tests skip themselves.

### Prompts with the polkit rule

| Operation | Prompts |
|-----------|---------|
| Verify (before Apply) | none normally (checked in a private namespace); the elevated `nft --check` fallback is cached |
| Apply | one |
| Confirm, auto-revert, "revert now" | none (handled by the root-side guard started by Apply) |
| Save to System | one |

Caching `/bin/sh` would let anything that can drive DRFW run arbitrary root
commands without a prompt, so Apply and Save to System always ask.

## Boot-Time Firewall

### Option 1: nftables.service (System Standard)

Use the standard nftables service with DRFW's export feature:

1. Configure your rules in DRFW
2. Click **Save to System** (writes `/etc/nftables.conf`; the previous file is kept as
   `/etc/nftables.conf.drfw-bak`, and the file DRFW first replaced as `.drfw-orig`)
3. Enable the standard nftables service:

```bash
sudo systemctl enable nftables.service
sudo systemctl start nftables.service
```

**Note:** `nftables.service` flushes the entire ruleset on stop, which may affect other tables (docker, libvirt, etc.). Loading DRFW's file itself only replaces the `inet drfw` table.

### Option 2: drfw.service (DRFW Alternative)

The `drfw.service` is an alternative to `nftables.service` that only manages the DRFW table:

1. Configure your rules in DRFW
2. Click **Save to System** (exports to `/etc/nftables.conf`)
3. Enable the DRFW service:

```bash
sudo systemctl enable drfw.service
sudo systemctl start drfw.service
```

**Key difference:** On stop, `drfw.service` only deletes the `inet drfw` table, preserving other tables like docker or libvirt.

The file DRFW writes begins with `table inet drfw` / `delete table inet drfw`, so
start and reload replace the drfw table atomically and never duplicate rules.
`drfw status` shows whether `/etc/nftables.conf` was written by DRFW; if it was
not (e.g. a distribution default starting with `flush ruleset`), `drfw.service`
would load it as it is.

### Service Commands

```bash
# Check service status
systemctl status drfw.service

# View service logs
journalctl -u drfw.service

# Reload firewall rules (after Save to System)
sudo systemctl reload drfw.service

# Stop the firewall (removes drfw table only)
sudo systemctl stop drfw.service

# Disable boot-time loading
sudo systemctl disable drfw.service
```

## Comparison: nftables.service vs drfw.service

| Feature | nftables.service | drfw.service |
|---------|------------------|--------------|
| Config source | `/etc/nftables.conf` | `/etc/nftables.conf` |
| On start/reload | Loads the file (DRFW's replaces only `inet drfw`) | Same |
| On stop | Flushes entire ruleset | Deletes only `inet drfw` table |
| Other tables | Removed on stop | Preserved on stop |
| Conflicts with | drfw.service | nftables.service |
| Recommended for | Single-purpose firewall | Systems with docker/libvirt/etc. |

## Troubleshooting

**Service fails to start:**
```bash
# Was the file written by DRFW? (no root needed)
drfw status

# Check if nftables.conf exists
sudo cat /etc/nftables.conf

# Test loading manually
sudo nft -f /etc/nftables.conf

# Check for syntax errors
sudo nft -c -f /etc/nftables.conf
```

**Firewall not applying:**
```bash
# View detailed logs
journalctl -u drfw.service -n 50

# List current ruleset
sudo nft list ruleset

# Verify drfw table exists
sudo nft list table inet drfw
```
