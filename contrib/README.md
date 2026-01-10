# DRFW Contrib Files

This directory contains distribution packaging and system integration files.

## Arch Linux (PKGBUILD)

Build and install from source using the provided PKGBUILD:

```bash
cd contrib
makepkg -si
```

This installs:
- `/usr/bin/drfw` - the main binary
- `/usr/lib/systemd/system/drfw.service` - optional boot service

For AUR submission, update the maintainer line in `PKGBUILD`.

## Boot-Time Firewall

### Recommended Approach: Save to System

The simplest way to apply firewall rules at boot is using DRFW's built-in export:

1. Configure your rules in DRFW
2. Click **Save to System** (exports to `/etc/nftables.conf`)
3. Enable the standard nftables service:

```bash
sudo systemctl enable nftables.service
sudo systemctl start nftables.service
```

This integrates with the system's native nftables configuration.

### Alternative: DRFW Service

If you prefer a DRFW-managed approach, use the provided service file.

#### Setup

1. Create a "boot" profile in DRFW with your desired rules
2. Copy the profile to root's XDG directory:

```bash
sudo mkdir -p /root/.local/share/drfw/profiles
sudo cp ~/.local/share/drfw/profiles/your-profile.json /root/.local/share/drfw/profiles/boot.json
```

3. Install and enable the service:

```bash
sudo cp contrib/drfw.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable drfw.service
sudo systemctl start drfw.service
```

#### Usage

```bash
# Check service status
systemctl status drfw.service

# View service logs
journalctl -u drfw.service

# Reload firewall rules
sudo systemctl reload drfw.service

# Stop the firewall
sudo systemctl stop drfw.service

# Disable boot-time loading
sudo systemctl disable drfw.service
```

#### How It Works

The `drfw.service` unit:

1. Runs `drfw apply boot --no-confirm` at boot
2. Loads the "boot" profile from `/root/.local/share/drfw/profiles/boot.json`
3. Applies rules using the elevation layer (runs as root, so no pkexec needed)
4. Logs all operations to systemd journal

#### Keeping Boot Rules Updated

After modifying rules in DRFW, update the boot profile:

```bash
sudo cp ~/.local/share/drfw/profiles/your-profile.json /root/.local/share/drfw/profiles/boot.json
sudo systemctl reload drfw.service
```

## Prerequisites

- DRFW installed at `/usr/bin/drfw` (or update the service file path)
- A "boot" profile in root's XDG data directory

## Troubleshooting

**Service fails to start:**
```bash
# Check if boot profile exists
sudo ls -la /root/.local/share/drfw/profiles/boot.json

# Verify drfw binary location
which drfw

# Test manual apply as root
sudo drfw apply boot --no-confirm
```

**Firewall not applying:**
```bash
# View detailed logs
journalctl -u drfw.service -n 50

# List available profiles (as root)
sudo drfw list
```

## Comparison: nftables.service vs drfw.service

| Feature | nftables.service | drfw.service |
|---------|------------------|--------------|
| Config format | nftables text | DRFW JSON profile |
| Update method | Save to System | Copy profile to root |
| Integration | System standard | DRFW-specific |
| Recommended for | Most users | Advanced setups |
