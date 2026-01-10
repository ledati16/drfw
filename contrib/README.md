# DRFW Contrib Files

This directory contains distribution packaging and system integration files.

## Contents

- `PKGBUILD` - Arch Linux package build file
- `drfw.service` - systemd service for boot-time firewall
- `drfw.desktop` - Desktop entry for application menus
- `drfw.svg` - Application icon

## Arch Linux (PKGBUILD)

Build and install from source using the provided PKGBUILD:

```bash
cd contrib
makepkg -si
```

This installs:
- `/usr/bin/drfw` - the main binary
- `/usr/share/applications/drfw.desktop` - desktop entry
- `/usr/share/icons/hicolor/scalable/apps/drfw.svg` - application icon
- `/usr/lib/systemd/system/drfw.service` - systemd service
- `/usr/share/licenses/drfw-git/LICENSE` - license file

## Boot-Time Firewall

### Option 1: nftables.service (System Standard)

Use the standard nftables service with DRFW's export feature:

1. Configure your rules in DRFW
2. Click **Save to System** (exports to `/etc/nftables.conf`)
3. Enable the standard nftables service:

```bash
sudo systemctl enable nftables.service
sudo systemctl start nftables.service
```

**Note:** `nftables.service` flushes the entire ruleset on stop, which may affect other tables (docker, libvirt, etc.).

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
| On stop | Flushes entire ruleset | Deletes only `inet drfw` table |
| Other tables | Removed on stop | Preserved on stop |
| Conflicts with | drfw.service | nftables.service |
| Recommended for | Single-purpose firewall | Systems with docker/libvirt/etc. |

## Troubleshooting

**Service fails to start:**
```bash
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
