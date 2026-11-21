#!/usr/bin/env bash
# Runs the DRFW root e2e kit (run.sh) inside a throwaway systemd-nspawn
# container with its own network namespace and systemd as PID 1.
#
# Run it on your own machine as your normal user; it builds drfw with cargo
# and then re-runs itself through sudo for the container part. The container
# gets --private-network, so every nftables change the kit makes happens in
# the container's network namespace, never in the host's.
#
#   tools/e2e/nspawn.sh all                  # create (once), run.sh, boot test
#   tools/e2e/nspawn.sh run -- --only 2,4    # run.sh with arguments
#   tools/e2e/nspawn.sh boot                 # boot-prep, reboot, boot-check
#   tools/e2e/nspawn.sh shell | stop | destroy
#   tools/e2e/nspawn.sh --dry-run all        # print what would happen
#
# See tools/e2e/README.md.

set -u -o pipefail
export LC_ALL=C

KIT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
SELF="$KIT_DIR/$(basename -- "${BASH_SOURCE[0]}")"
REPO_DIR=$(cd -- "$KIT_DIR/../.." && pwd -P)

MACHINE=drfw-e2e
ROOTFS=/var/lib/machines/drfw-e2e
DISTRO=
SUITE=trixie
MIRROR=http://deb.debian.org/debian
DRFW_BIN=
E2E_BIN=
HELPER_BIN=
NO_BUILD=0
NO_MODPROBE=0
KEEP=0
DRY_RUN=0
MARKER=.drfw-e2e-rootfs
INNER=/opt/drfw-e2e

die() {
    printf 'nspawn.sh: %s\n' "$*" >&2
    exit 2
}
say() { printf '%s\n' "$*"; }

# run CMD...: runs (or, with --dry-run, prints) a command
run() {
    if [ "$DRY_RUN" = 1 ]; then
        printf '  would run:'
        printf ' %q' "$@"
        printf '\n'
        return 0
    fi
    "$@"
}

usage() {
    cat <<'EOF'
Usage: tools/e2e/nspawn.sh [options] COMMAND [-- run.sh options]

Commands:
  create     Bootstrap the container root filesystem (pacstrap or debootstrap)
  run        Start the container, copy drfw + the kit in, run run.sh, stop
  boot       Scenario 9: run.sh --phase boot-prep, reboot the container,
             run.sh --phase boot-check
  all        create (if needed), run, boot
  shell      Open a root shell in the running container
  stop       Power the container off
  destroy    Stop and delete the root filesystem (only one this script created)

Options:
  --machine NAME     Machine name (default: drfw-e2e)
  --dir DIR          Root filesystem (default: /var/lib/machines/drfw-e2e)
  --distro D         arch or debian (default: whichever bootstrap tool exists)
  --suite S          Debian/Ubuntu suite for debootstrap (default: trixie)
  --mirror URL       debootstrap mirror (default: http://deb.debian.org/debian)
  --drfw PATH        Use this drfw binary instead of building
  --e2e-bin PATH     Use this root_e2e test binary instead of building
  --helper PATH      Use this drfw-helper binary instead of building
  --no-build         Do not run cargo; find the binaries in the target dir
  --no-modprobe      Do not load nftables kernel modules on the host
  --keep             Leave the container running after run/boot
  --dry-run          Print what would be done; build, bootstrap and start nothing
  -h, --help         This help

The binaries are built on the host, so the container should be the same
distribution (or one with a glibc at least as new). Build inside the
container or use a VM for other combinations (see README.md).
EOF
}

ORIG_ARGS=("$@")
CMD=
KIT_ARGS=()
while [ $# -gt 0 ]; do
    case $1 in
        --machine) MACHINE=${2:?}; shift ;;
        --dir) ROOTFS=${2:?}; shift ;;
        --distro) DISTRO=${2:?}; shift ;;
        --suite) SUITE=${2:?}; shift ;;
        --mirror) MIRROR=${2:?}; shift ;;
        --drfw) DRFW_BIN=${2:?}; shift ;;
        --e2e-bin) E2E_BIN=${2:?}; shift ;;
        --helper) HELPER_BIN=${2:?}; shift ;;
        --no-build) NO_BUILD=1 ;;
        --no-modprobe) NO_MODPROBE=1 ;;
        --keep) KEEP=1 ;;
        --dry-run) DRY_RUN=1 ;;
        -h | --help)
            usage
            exit 0
            ;;
        --)
            shift
            KIT_ARGS=("$@")
            break
            ;;
        -*) die "unknown option: $1" ;;
        *)
            [ -z "$CMD" ] || die "only one command, got '$CMD' and '$1'"
            CMD=$1
            ;;
    esac
    shift
done
[ -n "$CMD" ] || {
    usage
    exit 2
}
case $CMD in
    create | run | boot | all | shell | stop | destroy) ;;
    *) die "unknown command: $CMD" ;;
esac
case $MACHINE in
    *[!A-Za-z0-9_-]* | '') die "--machine: use letters, digits, _ and -" ;;
esac
case $ROOTFS in
    /*) ;;
    *) die "--dir must be an absolute path" ;;
esac
[ "$ROOTFS" != / ] || die "--dir must not be /"
UNIT="drfw-e2e-nspawn-$MACHINE"

if [ -z "$DISTRO" ]; then
    if command -v pacstrap >/dev/null 2>&1; then
        DISTRO=arch
    elif command -v debootstrap >/dev/null 2>&1; then
        DISTRO=debian
    fi
fi

# ----------------------------------------------------------------------------
# Build (as the invoking user, before elevating)
# ----------------------------------------------------------------------------

target_dir() { printf '%s\n' "${CARGO_TARGET_DIR:-$REPO_DIR/target}"; }

find_built() {
    local t
    t=$(target_dir)
    [ -n "$DRFW_BIN" ] || { [ -x "$t/release/drfw" ] && DRFW_BIN=$t/release/drfw; }
    [ -n "$HELPER_BIN" ] || { [ -x "$t/release/drfw-helper" ] && HELPER_BIN=$t/release/drfw-helper; }
    if [ -z "$E2E_BIN" ] && [ -d "$t/release" ]; then
        E2E_BIN=$(find "$t/release" -type f -name 'root_e2e-*' -perm -u+x -printf '%T@ %p\n' 2>/dev/null |
            sort -rn | head -n1 | cut -d' ' -f2-)
    fi
}

build() {
    local out
    say "Building drfw, drfw-helper and the root_e2e test binary (cargo, as $(id -un))..."
    if [ "$DRY_RUN" = 1 ]; then
        run cargo build --release --bin drfw --bin drfw-helper
        run cargo test --release --test root_e2e --no-run
        return 0
    fi
    (cd -- "$REPO_DIR" && cargo build --release --bin drfw --bin drfw-helper) || die "cargo build failed"
    out=$(cd -- "$REPO_DIR" && cargo test --release --test root_e2e --no-run 2>&1) || {
        printf '%s\n' "$out" >&2
        die "cargo test --no-run failed"
    }
    E2E_BIN=$(sed -n 's/.*Executable .*root_e2e\.rs (\(.*\))$/\1/p' <<<"$out" | tail -n1)
    DRFW_BIN=$(target_dir)/release/drfw
    HELPER_BIN=$(target_dir)/release/drfw-helper
}

needs_binaries() { case $CMD in run | boot | all) return 0 ;; esac; return 1; }

if [ "$EUID" -ne 0 ]; then
    if needs_binaries; then
        if [ "$NO_BUILD" = 0 ] && [ -z "$DRFW_BIN" ]; then
            build
        fi
        find_built
    fi
    if [ "$DRY_RUN" = 1 ]; then
        say "Not root: the steps below would run through sudo."
    else
        command -v sudo >/dev/null 2>&1 || die "run as root (sudo not found)"
        extra=()
        [ -n "$DRFW_BIN" ] && extra+=(--drfw "$DRFW_BIN")
        [ -n "$E2E_BIN" ] && extra+=(--e2e-bin "$E2E_BIN")
        [ -n "$HELPER_BIN" ] && extra+=(--helper "$HELPER_BIN")
        exec sudo -- bash "$SELF" --no-build "${extra[@]}" "${ORIG_ARGS[@]}"
    fi
else
    needs_binaries && find_built
fi

if needs_binaries && [ "$DRY_RUN" = 0 ]; then
    [ -x "${DRFW_BIN:-}" ] || die "no drfw binary (build first or pass --drfw)"
fi

# ----------------------------------------------------------------------------
# Container
# ----------------------------------------------------------------------------

machine_running() {
    [ "$(machinectl show "$MACHINE" -p State --value 2>/dev/null)" = running ]
}

create() {
    if [ -e "$ROOTFS/$MARKER" ]; then
        say "Root filesystem $ROOTFS exists (created by this script); reusing it."
        return 0
    fi
    if [ -e "$ROOTFS" ] && [ -n "$(ls -A -- "$ROOTFS" 2>/dev/null)" ]; then
        die "$ROOTFS exists, is not empty and was not created by this script"
    fi
    say "Bootstrapping $DISTRO into $ROOTFS..."
    run mkdir -p -- "$ROOTFS"
    case $DISTRO in
        arch)
            # base has systemd, util-linux (script, runuser), iproute2, dbus
            run pacstrap -K -c "$ROOTFS" base nftables sudo polkit socat python iputils ||
                die "pacstrap failed"
            ;;
        debian)
            run debootstrap --variant=minbase \
                --include=systemd,systemd-sysv,dbus,libpam-systemd,nftables,sudo,polkitd,pkexec,iproute2,socat,python3,iputils-ping,procps \
                "$SUITE" "$ROOTFS" "$MIRROR" || die "debootstrap failed"
            ;;
        *) die "no pacstrap or debootstrap found; see README.md (mkosi, manual bootstrap)" ;;
    esac
    # nftables.service must not load the distribution config at the first boot
    # (the distribution configs add their own filter table, which would get in
    # the way of the kit's network scenario)
    run systemctl --root="$ROOTFS" disable --quiet nftables.service
    run touch -- "$ROOTFS/$MARKER"
}

# Kernel modules cannot be loaded from inside the container
load_modules() {
    [ "$NO_MODPROBE" = 1 ] && return 0
    local m
    for m in nf_tables nf_conntrack nft_ct nft_limit nft_log nft_reject_inet nft_fib_inet \
        nft_connlimit nft_counter veth; do
        run modprobe -q "$m" 2>/dev/null || true
    done
}

stage() {
    local dest="$ROOTFS$INNER/tools/e2e"
    say "Copying the kit and binaries to $dest..."
    run rm -rf -- "$ROOTFS$INNER"
    run install -d -m 0755 -- "$dest/bin"
    run install -m 0755 -- "$KIT_DIR/run.sh" "$dest/run.sh"
    run install -m 0644 -- "$KIT_DIR/lib.sh" "$KIT_DIR/README.md" "$dest/"
    run install -m 0755 -- "$DRFW_BIN" "$dest/bin/drfw"
    if [ -n "$E2E_BIN" ]; then
        run install -m 0755 -- "$E2E_BIN" "$dest/bin/root_e2e"
    else
        say "  (no root_e2e test binary: scenario 8 will be skipped)"
    fi
    if [ -n "$HELPER_BIN" ]; then
        run install -m 0755 -- "$HELPER_BIN" "$dest/bin/drfw-helper"
    else
        say "  (no drfw-helper binary: scenario 11 will be skipped)"
    fi
}

start() {
    if [ "$DRY_RUN" = 0 ] && machine_running; then
        return 0
    fi
    load_modules
    say "Booting container $MACHINE (private network, systemd as PID 1)..."
    # Exit status 133 means "reboot": restart nspawn, like systemd-nspawn@.service
    run systemd-run --unit="$UNIT" --description="drfw e2e container $MACHINE" \
        --property=Type=notify --property=NotifyAccess=all \
        --property=RestartForceExitStatus=133 --property=SuccessExitStatus=133 \
        --property=KillMode=mixed --property=Delegate=yes \
        systemd-nspawn --quiet --keep-unit --boot --notify-ready=yes \
        --directory="$ROOTFS" --machine="$MACHINE" --private-network \
        --link-journal=no --resolv-conf=off --timezone=off
    wait_ready
}

wait_ready() {
    [ "$DRY_RUN" = 1 ] && {
        run systemctl -M "$MACHINE" is-system-running --wait
        return 0
    }
    local i state
    for i in $(seq 120); do
        machine_running && break
        sleep 0.5
        : "$i"
    done
    machine_running || die "container $MACHINE did not start (journalctl -u $UNIT)"
    state=$(timeout 120 systemctl -M "$MACHINE" is-system-running --wait 2>/dev/null)
    case $state in
        running | degraded) say "  container is up ($state)" ;;
        *) die "container $MACHINE is not ready (state: ${state:-unknown})" ;;
    esac
}

# kit ARGS...: runs run.sh as root inside the container; returns its status
kit() {
    run systemd-run -M "$MACHINE" --wait --pipe --quiet --collect \
        --setenv=DRFW_E2E_DISPOSABLE=1 --setenv=TERM=xterm-256color \
        /bin/bash "$INNER/tools/e2e/run.sh" "$@"
}

stop() {
    if [ "$DRY_RUN" = 0 ] && ! machine_running; then
        return 0
    fi
    say "Stopping container $MACHINE..."
    run machinectl poweroff "$MACHINE"
    local i
    for i in $(seq 60); do
        [ "$DRY_RUN" = 1 ] && break
        machine_running || break
        sleep 0.5
        : "$i"
    done
    run systemctl stop "$UNIT" 2>/dev/null
}

reboot_container() {
    say "Rebooting container $MACHINE..."
    run systemctl -M "$MACHINE" reboot
    if [ "$DRY_RUN" = 0 ]; then
        # Wait until the old instance is gone, then for the new one
        local i
        for i in $(seq 60); do
            machine_running || break
            sleep 0.5
            : "$i"
        done
    fi
    wait_ready
}

do_run() {
    local rc
    stage
    start
    kit "${KIT_ARGS[@]}"
    rc=$?
    return "$rc"
}

do_boot() {
    local rc
    stage
    start
    kit --phase boot-prep || return 1
    reboot_container
    kit --phase boot-check
    rc=$?
    return "$rc"
}

[ "$EUID" -eq 0 ] || [ "$DRY_RUN" = 1 ] || die "must run as root"
command -v systemd-nspawn >/dev/null 2>&1 || [ "$DRY_RUN" = 1 ] ||
    die "systemd-nspawn not found (install systemd-container)"

rc=0
case $CMD in
    create) create ;;
    run)
        [ -e "$ROOTFS/$MARKER" ] || [ "$DRY_RUN" = 1 ] || die "no container yet: run '$0 create' first"
        do_run
        rc=$?
        [ "$KEEP" = 1 ] || stop
        ;;
    boot)
        [ -e "$ROOTFS/$MARKER" ] || [ "$DRY_RUN" = 1 ] || die "no container yet: run '$0 create' first"
        do_boot
        rc=$?
        [ "$KEEP" = 1 ] || stop
        ;;
    all)
        create
        do_run
        rc=$?
        do_boot || rc=1
        [ "$KEEP" = 1 ] || stop
        ;;
    shell) run machinectl shell "$MACHINE" ;;
    stop) stop ;;
    destroy)
        stop
        if [ -e "$ROOTFS/$MARKER" ]; then
            say "Deleting $ROOTFS..."
            run rm -rf --one-file-system -- "$ROOTFS"
        else
            die "$ROOTFS was not created by this script (no $MARKER); not deleting it"
        fi
        ;;
esac
if [ "$rc" -eq 0 ]; then
    say "nspawn.sh: $CMD finished OK"
else
    say "nspawn.sh: $CMD FAILED (exit $rc)"
fi
exit "$rc"
