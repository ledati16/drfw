# DRFW systemd Service

This directory contains systemd service files for managing DRFW firewall rules at boot.

## Installation

### Automatic (via DRFW UI)

The easiest way to enable DRFW at boot is through the UI:

1. Open DRFW
2. Navigate to Settings tab
3. Click "Enable on Boot"  (Implemented in future UI update)

### Manual Installation

If you prefer to install manually:

```bash
# Copy the service file to systemd directory
sudo cp contrib/drfw.service /etc/systemd/system/

# Reload systemd to recognize the new service
sudo systemctl daemon-reload

# Enable DRFW to start at boot
sudo systemctl enable drfw.service

# Start DRFW immediately (optional)
sudo systemctl start drfw.service
```

## Usage

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

## How It Works

The `drfw.service` unit:

1. Runs `drfw apply --system-config` on boot
2. Loads rules from `/etc/drfw/config.toml`
3. Applies them using elevated privileges (via pkexec/polkit)
4. Logs all operations to systemd journal

## Advantages Over nftables.service

- **Clean separation**: DRFW owns its config, no conflicts with system nftables
- **Easier rollback**: `systemctl disable drfw` to disable firewall
- **Better logging**: Integrated with systemd journal
- **GUI integration**: Enable/disable from DRFW UI
- **Atomic updates**: Changes applied in one operation

## Prerequisites

- DRFW installed at `/usr/bin/drfw`
- Configuration saved at `/etc/drfw/config.toml`
- Polkit configured for elevated privileges

## Troubleshooting

**Service fails to start:**
```bash
# Check if config file exists
ls -la /etc/drfw/config.toml

# Verify drfw binary location
which drfw

# Check polkit permissions
pkexec drfw --version
```

**Firewall not applying:**
```bash
# View detailed logs
journalctl -u drfw.service -n 50

# Test manual apply
sudo drfw apply --system-config
```
