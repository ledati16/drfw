# DRFW root end-to-end kit

`cargo test` never needs root: it uses a mock `nft`, or the real `nft` inside
`unshare -rn`. This kit covers the rest: the real elevation tools, the
root-side revert guard under systemd, Save to System on the real config file,
boot persistence and Server Mode on a real network interface.

**Run it only in a disposable container or VM.** It creates a user, installs
sudoers and polkit rules, applies firewall rules, replaces the system nftables
config and enables the nftables service. It restores all of that on exit, but
a crash or power cut mid-run can leave changes behind.

## Files

| File | Purpose |
|------|---------|
| `run.sh` | The kit. Runs inside the disposable environment, as root |
| `lib.sh` | Helpers sourced by `run.sh` |
| `nspawn.sh` | Builds a throwaway systemd-nspawn container on your machine and runs the kit in it |
| `../../tests/root_e2e.rs` | `#[ignore]`d helper tests: Save to System through the library, the GUI's exact code path (`drfw save` covers the CLI) |

## Safety rails

`run.sh` refuses to do anything unless all of these hold:

- `DRFW_E2E_DISPOSABLE=1` is set;
- `systemd-detect-virt` reports a VM or container, or you pass
  `--i-know-this-is-not-my-workstation`;
- it runs as root, or it can re-run itself through `sudo`/`run0`.

The `root_e2e` helper tests check `DRFW_E2E_DISPOSABLE=1` and
`systemd-detect-virt` again before they write anything, so
`cargo test -- --ignored` on a workstation does nothing.

What the kit never does:

- touch an nftables table other than `inet drfw`;
- set `DRFW_NFT_COMMAND` (it unsets it), because the real elevation and the
  real `nft` are what it tests;
- start or stop the nftables service (its `ExecStop` flushes the whole
  ruleset); it only enables and disables it;
- kill processes by name: every process is killed by its PID.

On exit (`trap`), it restores `SYSTEM_NFT_PATH` plus `.drfw-orig` and
`.drfw-bak` (or removes them if they did not exist), the enablement of the
service and the `inet drfw` table as it was before the run. It also removes
the test user, the sudoers file and the polkit rule. The backup lives in
`/var/lib/drfw-e2e/backup` until the restore succeeds; a later run reuses an
existing backup instead of overwriting it. The only exception is
`--phase boot-prep`, which leaves its changes in place for the reboot (see
scenario 9).

`--dry-run` prints the plan and runs the safety checks, the requirement
checks and a profile self-check (`drfw check` on the kit's profiles, without
privileges, in a throwaway data dir). It changes nothing and never elevates.

```bash
DRFW_E2E_DISPOSABLE=1 tools/e2e/run.sh --dry-run
```

## Running it

### systemd-nspawn (recommended)

On your own machine, as your normal user:

```bash
tools/e2e/nspawn.sh --dry-run all   # print what would happen
tools/e2e/nspawn.sh all             # create, run all scenarios, boot test
```

`nspawn.sh` builds `drfw` and the `root_e2e` test binary with cargo, then
re-runs itself through `sudo` and:

1. `create`: bootstraps `/var/lib/machines/drfw-e2e` with `pacstrap` (Arch) or
   `debootstrap` (Debian/Ubuntu; `--suite`, default `trixie`) and disables the
   distribution's `nftables.service` (its default config adds a filter table
   that would get in the way). It marks the directory so that `destroy` only
   ever deletes a root filesystem it created.
2. Loads the nftables kernel modules on the host (`--no-modprobe` to skip):
   a container cannot load modules.
3. Boots the container as a transient unit: `systemd-nspawn --boot
   --private-network` with systemd as PID 1. All nftables changes happen in
   the container's own network namespace, never in the host's.
4. Copies `run.sh`, `lib.sh` and the binaries (`drfw`, `drfw-helper`, `root_e2e`) to `/opt/drfw-e2e/tools/e2e`
   and runs `run.sh` with `systemd-run -M drfw-e2e --wait --pipe`.
5. `boot`: `--phase boot-prep`, `systemctl -M drfw-e2e reboot` (nspawn exits
   with 133, the unit restarts it), then `--phase boot-check`.

Other commands: `run [-- run.sh options]`, `boot`, `shell`, `stop`,
`destroy`. `--keep` leaves the container running.

The binaries are built on the host, so the container should be the same
distribution as the host (or have a glibc at least as new). For other
combinations, build inside the container (`nspawn.sh shell`, install rustup)
or use a VM.

Note that a container without `--private-users` is not a security boundary:
its root is the host's root with fewer capabilities. It is disposable, not
sandboxed. Use a VM if that matters to you.

#### Without pacstrap/debootstrap

- **mkosi**: `mkosi -d arch -p systemd,nftables,sudo,polkit,socat,python,iputils
  -t directory -o /var/lib/machines/drfw-e2e build` (adjust the distribution and
  package names), then `touch /var/lib/machines/drfw-e2e/.drfw-e2e-rootfs` and
  use `nspawn.sh run`.
- **Manual**: any root filesystem with systemd, dbus, nftables, sudo, polkit
  (and pkexec), util-linux (`script`, `runuser`), iproute2 and socat or
  python3 works. Disable its `nftables.service`, create the marker file, then
  `nspawn.sh run`.

### A VM

Any distribution with systemd as PID 1, nftables, sudo and util-linux;
polkit/pkexec, run0, socat or python3 and iproute2 enable more checks.
Disable any other firewall in the VM (firewalld, ufw, the distribution's
`nftables.conf`): scenario 10 expects only DRFW to filter.

```bash
# On the host
cargo build --release                           # drfw and drfw-helper
cargo test --release --test root_e2e --no-run   # prints the test binary path
# Copy tools/e2e/ to the VM, put the binaries at tools/e2e/bin/drfw,
# tools/e2e/bin/drfw-helper and tools/e2e/bin/root_e2e (or pass --drfw /
# --helper / --e2e-bin), then in the VM:
sudo DRFW_E2E_DISPOSABLE=1 tools/e2e/run.sh --dry-run
sudo DRFW_E2E_DISPOSABLE=1 tools/e2e/run.sh
sudo DRFW_E2E_DISPOSABLE=1 tools/e2e/run.sh --phase boot-prep
sudo reboot
sudo DRFW_E2E_DISPOSABLE=1 tools/e2e/run.sh --phase boot-check
```

Take a VM snapshot first if you want to be able to roll back exactly.

### run.sh options

`--only 2,4,6` runs some scenarios; `--method pkexec|run0` elevates the guard
scenarios 2 to 7 with something other than sudo; `--helper PATH` names the
`drfw-helper` release binary for scenario 11; `--nft-conf` and `--service`
override the compiled-in paths (normally discovered from the `root_e2e`
binary, else from `drfw status`); `--strict` counts skips as failures.

Exit status: 0 all passed, 1 a scenario failed, 2 refused or a requirement
is missing. Logs (CLI output of every step, the sudo log) are kept in
`/var/lib/drfw-e2e/logs`.

## The test environment

- Test user `drfw-e2e`, home `/var/lib/drfw-e2e/home`, `XDG_RUNTIME_DIR`
  `/run/drfw-e2e-rt`, profiles in `/var/lib/drfw-e2e/user/data`
  (`DRFW_TEST_DATA_DIR`). Every CLI call runs as this user through `runuser`
  with a clean environment.
- `/etc/sudoers.d/90-drfw-e2e`: `NOPASSWD` for `/bin/sh`, `nft` and the helper
  path compiled into `drfw`, for this user only, logging every call to
  `/var/log/drfw-e2e-sudo.log`. The kit
  counts those entries to prove how often (and for what) DRFW elevated. This
  is effectively root for the test user, which is fine in a throwaway
  environment and is exactly what DRFW must never recommend on a real host.
- `/etc/polkit-1/rules.d/10-drfw-e2e.rules`: `pkexec` of `/bin/sh` and `nft`
  and systemd unit management (for `run0`), for this user only. For
  `org.drfw.helper` it never answers YES: an active local session gets the
  action's own default (`auth_admin_keep`); the kit's processes have no seat,
  which polkit treats like a remote session (the action says `auth_admin`
  there), so the rule returns `AUTH_ADMIN_KEEP` for them, what a desktop session
  gets. It also makes the test user its own polkit administrator
  (`addAdminRule`), so the prompt asks for the test user's password.
- Profiles `e2e-a`, `e2e-b`, `e2e-c` (Desktop mode, one input rule each,
  labelled `e2e-A`/`e2e-B`/`e2e-C`, so the live table can be identified by the
  rule comment) and `e2e-srv` (Server Mode, one rule for an unused port).
- The CLI's countdown needs a terminal: the kit runs it under `script` (a
  PTY) and feeds keys through a FIFO.
- Table comparisons use `nft list table inet drfw` with counter values
  removed.

## Scenarios

Each prints `PASS`/`FAIL` with the evidence for every sub-check.

1. **Elevation as a real user.** Whether unprivileged user namespaces work for
   the test user decides the expectation. `drfw check` must pass with no sudo
   call at all. `drfw apply --no-confirm` via sudo must leave `e2e-A` live, and
   the sudo log must show exactly one elevation (`/bin/sh`, the apply script)
   and no `nft` call, which proves verify used the unprivileged namespace
   check (with namespaces disabled: an elevated `nft` check instead). Then the
   same apply via pkexec and run0 (if polkit runs), and with no
   `DRFW_ELEVATION_METHOD` in a PTY (the CLI picks run0, else sudo).
2. **Guard timeout, systemd path.** (a) baseline `e2e-A`, then
   `apply e2e-b --confirm 6` and no keys: the `active` file names the
   `systemd` launcher, `drfw-revert-<nonce>.service` is active during the
   countdown, `e2e-B` is live, `status-<nonce>` becomes `reverted` 6 s (+-) after
   arming, the table equals the baseline, the unit is gone and the CLI printed
   "Reverted to the previous rules.". (b) the same with no previous table: no
   `inet drfw` table afterwards.
3. **SSH drop.** `apply e2e-b --confirm 8`; 2 s in, the CLI is killed by PID
   with SIGHUP, with SIGKILL, and (third case) by killing the PTY's owner so
   the kernel hangs up the terminal, as sshd does. The CLI is gone, the rules
   stay live, and the watcher still reverts on time to the baseline.
4. **Confirm.** The `c` key: `status` is `confirmed` within 3 s, the CLI
   printed "Changes confirmed"; 4 s after the original deadline `e2e-B` is
   still live, the table did not change, the status is still `confirmed`, the
   unit and the revert file are gone.
5. **Revert now.** With a 60 s timeout, the `r` key: `reverted` within 3 s and
   the baseline is back.
6. **Supersede.** Baseline `e2e-A` (unguarded = confirmed), `e2e-b` with a
   60 s guard, then `e2e-c` with a 6 s guard during that countdown: the first
   guard becomes `superseded` and its unit stops; a late confirm for it
   changes nothing (its CLI reports "Another apply replaced these rules" and
   the second guard stays pending); the second guard times out and the table
   is back to `e2e-A`, not `e2e-B`.
7. **First apply without a table, timeout (the original lockout bug).** No
   `inet drfw` table, then Server Mode `e2e-srv` with a 6 s guard: during the
   countdown the output policy is drop and loopback TCP still works; after
   the timeout the status is `reverted` (or `removed:`), no `inet drfw` table
   is left, and loopback TCP and ping work.
8. **Save to System** (needs the `root_e2e` binary), through
   `system_config::write_config_file`, the GUI's code path, as the test user.
   The config is first replaced by a known comment-only file and the
   `.drfw-*` files are removed. Save `e2e-a` via sudo: the file is exactly
   `to_nft_text()`, root-owned 644, `.drfw-orig` and `.drfw-bak` equal the
   original, no temp file, `drfw status` says "written by DRFW". Save `e2e-b`
   via pkexec without a terminal (the GUI path; sudo if no polkit):
   `.drfw-orig` unchanged, `.drfw-bak` = the first save. `nft -c -f` passes.
   Loading the file twice gives the same table with `e2e-B` once. A broken
   save (valid file plus a garbage line) exits 3 and leaves the config,
   `.drfw-bak` and `.drfw-orig` untouched, with no temp file left.
9. **Boot persistence**, two phases:
   - `--phase boot-prep` backs up the config, its `.drfw-*` files, the
     service enablement and the table to `/var/lib/drfw-e2e/boot/backup`.
     It saves `e2e-b` to the config as root (the save script with the real
     `nft -c`; without the test binary, `drfw export` instead), records the
     table that file produces (loaded in a throwaway network namespace) and
     the boot id, enables the service and deletes the live table.
   - **Reboot** (`systemctl reboot`; `nspawn.sh boot` does it for you).
   - `--phase boot-check` checks that the boot id changed, that the service
     is enabled and succeeded at boot, and that the live `inet drfw` table
     equals the recorded one. Then it restores everything boot-prep changed.
   Until boot-check runs, the environment keeps the saved config and the
   enabled service.
10. **Server Mode over the network.** A network namespace `drfw-e2e-peer`
    joined by a veth pair (`10.213.47.1` here, `.2` there), with TCP echo
    servers on `10.213.47.1:47501` and `127.0.0.1:47502` (socat or python3).
    A new connection from the peer works (control). A session opened from the
    peer before the apply echoes once, then `e2e-srv` (Server Mode, no rule
    for 47501) is applied: the established session still echoes, a new
    connection from the peer is blocked, and loopback TCP works.

11. **Root helper and polkit action** (needs a `drfw-helper` release binary and
    a `drfw` with `print-polkit-policy`). Installs the helper at the path from
    `drfw print-polkit-policy` (root:root 755) and that output as
    `/usr/share/polkit-1/actions/org.drfw.helper.policy`; both are removed at
    the end and on exit (an identical copy installed before the run is used
    and left alone; a different one makes the scenario fail without touching
    it).
    - (a) `pkaction --verbose` shows the action's defaults (`auth_admin_keep`
      for active local sessions, `auth_admin` otherwise) and the exec path.
    - (b) Refusals: as the test user (not root); as root without
      pkexec/sudo/run0; the release build ignoring the test-mode variables as
      root; and, as root through sudo, an unknown request, no request, `check`
      with a file argument, `apply` with another state dir, a bad nonce,
      another uid or another `nft`, `save-config` to `/etc/passwd` or enabling
      another service, and `check`/`apply` of a payload that `include`s a
      root-only secret file (the control shows plain root `nft -j -c` prints
      the secret). Every refusal exits 1 without printing the secret; the
      ruleset and `/etc/passwd` are unchanged.
    - (c) `drfw apply` via sudo elevates only the helper (sudo log: no
      `/bin/sh`, no `nft`); a guarded apply through the helper times out and
      reverts on the systemd path (as scenario 2); Save to System goes through
      the helper.
    - (d) **Prompt count.** The test user gets a random password. In a PTY, a
      shell starts `pkttyagent --process $$` (a text polkit agent for that one
      process) and then `exec`s the `root_e2e` binary, which keeps the PID and
      start time polkit identifies the subject by. That process applies
      `e2e-a` and then `e2e-b` exactly like the GUI (`pkexec`, `apply_guarded`).
      The kit types the password whenever the agent prints `Password:` and
      counts the prompts: exactly **one** for both applies, for
      `org.drfw.helper`, with the text "Authentication is required to change
      the firewall rules". A second process applying `e2e-c` is asked again
      (the authorization is kept for the process that asked, not the user).
      Skipped without `pkttyagent`, `chpasswd`, pkexec or polkit.

## What this kit cannot cover

- Interactive authentication with a graphical agent: scenario 11 types the
  password into the text agent `pkttyagent`; the other scenarios grant the
  test user access without one. The cancel/refuse paths (exit 126/127) are
  covered by unit tests.
- The GUI. Its Apply and Save to System handlers call the same library
  functions the kit drives (`apply_guarded`, `write_config_file`).
- The `setsid` watcher launcher (systemd not PID 1): `tests/real_nft.rs`
  covers it in a namespace.
