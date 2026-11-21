#!/usr/bin/env bash
# DRFW root end-to-end test kit.
#
# RUN THIS ONLY INSIDE A DISPOSABLE CONTAINER OR VM. It creates a test user,
# installs sudoers/polkit rules for it, applies firewall rules for real,
# replaces the system nftables config and enables the nftables service.
# Everything is restored on exit, but a crash mid-run can leave changes.
#
# See tools/e2e/README.md. Quick reference:
#   DRFW_E2E_DISPOSABLE=1 tools/e2e/run.sh --dry-run      # plan + safety checks only
#   DRFW_E2E_DISPOSABLE=1 tools/e2e/run.sh                # scenarios 1-8, 10 and 11
#   DRFW_E2E_DISPOSABLE=1 tools/e2e/run.sh --phase boot-prep    # scenario 9, then reboot
#   DRFW_E2E_DISPOSABLE=1 tools/e2e/run.sh --phase boot-check   # after the reboot
#
# Exit status: 0 all scenarios passed, 1 a scenario failed (or was skipped
# with --strict), 2 refused (safety checks, usage, missing requirements).

# Checks are written as `check WHAT eval '...'` so that the condition is
# evaluated by check() (SC2016), and scenario_N / on_exit are dispatched
# dynamically or through trap (SC2329).
# shellcheck disable=SC2016,SC2329

set -u -o pipefail
export LC_ALL=C
umask 022

KIT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
SELF="$KIT_DIR/$(basename -- "${BASH_SOURCE[0]}")"
REPO_DIR=$(cd -- "$KIT_DIR/../.." 2>/dev/null && pwd -P) || REPO_DIR=

# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$KIT_DIR/lib.sh"

# ----------------------------------------------------------------------------
# Fixed names (all kit-owned)
# ----------------------------------------------------------------------------

TEST_USER=drfw-e2e
WORK=/var/lib/drfw-e2e
BIN_DIR=$WORK/bin
LOG_DIR=$WORK/logs
BACKUP_DIR=$WORK/backup
BOOT_DIR=$WORK/boot
USER_ROOT=$WORK/user
USER_DATA=$USER_ROOT/data
USER_STATE=$USER_ROOT/state
PTY_ROOT=$USER_ROOT/pty
USER_HOME=$WORK/home
RT_DIR=/run/drfw-e2e-rt
LOCK_FILE=/run/drfw-e2e.lock
SUDOERS_FILE=/etc/sudoers.d/90-drfw-e2e
SUDO_LOG=/var/log/drfw-e2e-sudo.log
POLKIT_RULE=/etc/polkit-1/rules.d/10-drfw-e2e.rules
POLKIT_ACTION=/usr/share/polkit-1/actions/org.drfw.helper.policy
GUARD_DIR=/run/drfw
PEER_NS=drfw-e2e-peer
VETH_A=drfwe2e0
VETH_B=drfwe2e1
IP_A=10.213.47.1
IP_B=10.213.47.2
ECHO_PORT=47501
LO_PORT=47502
ALL_SCENARIOS="1 2 3 4 5 6 7 8 10 11"

# ----------------------------------------------------------------------------
# Options
# ----------------------------------------------------------------------------

DRY_RUN=0
PHASE=all
ONLY=
OVERRIDE_VIRT=0
STRICT=0
GUARD_METHOD=sudo
OPT_DRFW=
OPT_E2E_BIN=
OPT_HELPER=
OPT_NFT_CONF=
OPT_SERVICE=
ORIG_ARGS=("$@")

usage() {
    cat <<'EOF'
Usage: DRFW_E2E_DISPOSABLE=1 run.sh [options]

DRFW root end-to-end kit. Only for a disposable container or VM.

Options:
  --dry-run              Print the plan and run the safety checks; change nothing
  --phase PHASE          all (default), boot-prep or boot-check (scenario 9)
  --only LIST            Run only these scenarios (comma separated, e.g. 2,4,6)
  --method METHOD        Elevation for the guard scenarios 2-7: sudo (default),
                         pkexec or run0
  --drfw PATH            drfw release binary (default: tools/e2e/bin/drfw,
                         then the cargo target dir, then drfw on PATH)
  --e2e-bin PATH         Test binary built from tests/root_e2e.rs (needed for
                         Save to System; default: tools/e2e/bin/root_e2e or the
                         newest root_e2e-* in the cargo target dir)
  --helper PATH          drfw-helper release binary for scenario 11 (default:
                         tools/e2e/bin/drfw-helper, then the cargo target dir)
  --nft-conf PATH        System nftables config (default: as compiled into drfw)
  --service NAME         Boot service (default: as compiled into drfw)
  --strict               Count skipped scenarios as failures
  --i-know-this-is-not-my-workstation
                         Allow running when systemd-detect-virt reports "none"
  -h, --help             This help

Safety: refuses unless DRFW_E2E_DISPOSABLE=1 is set, systemd-detect-virt
reports a VM or container (or the override flag is given) and it runs as root
or can elevate with sudo/run0. Never sets DRFW_NFT_COMMAND.
EOF
}

while [ $# -gt 0 ]; do
    case $1 in
        --dry-run) DRY_RUN=1 ;;
        --phase)
            [ $# -ge 2 ] || die "--phase needs a value"
            PHASE=$2
            shift
            ;;
        --only)
            [ $# -ge 2 ] || die "--only needs a value"
            ONLY=$2
            shift
            ;;
        --method)
            [ $# -ge 2 ] || die "--method needs a value"
            GUARD_METHOD=$2
            shift
            ;;
        --drfw)
            [ $# -ge 2 ] || die "--drfw needs a value"
            OPT_DRFW=$2
            shift
            ;;
        --e2e-bin)
            [ $# -ge 2 ] || die "--e2e-bin needs a value"
            OPT_E2E_BIN=$2
            shift
            ;;
        --helper)
            [ $# -ge 2 ] || die "--helper needs a value"
            OPT_HELPER=$2
            shift
            ;;
        --nft-conf)
            [ $# -ge 2 ] || die "--nft-conf needs a value"
            OPT_NFT_CONF=$2
            shift
            ;;
        --service)
            [ $# -ge 2 ] || die "--service needs a value"
            OPT_SERVICE=$2
            shift
            ;;
        --strict) STRICT=1 ;;
        --i-know-this-is-not-my-workstation) OVERRIDE_VIRT=1 ;;
        -h | --help)
            usage
            exit 0
            ;;
        *) die "unknown option: $1 (see --help)" ;;
    esac
    shift
done

case $PHASE in
    all | boot-prep | boot-check) ;;
    *) die "--phase must be all, boot-prep or boot-check" ;;
esac
case $GUARD_METHOD in
    sudo | pkexec | run0) ;;
    *) die "--method must be sudo, pkexec or run0" ;;
esac

SCENARIOS=$ALL_SCENARIOS
if [ -n "$ONLY" ]; then
    SCENARIOS=${ONLY//,/ }
    for s in $SCENARIOS; do
        case " $ALL_SCENARIOS 9 " in
            *" $s "*) ;;
            *) die "--only: unknown scenario $s (valid: $ALL_SCENARIOS, 9)" ;;
        esac
    done
fi

# The real elevation path and the real nft are the point of this kit
if [ -n "${DRFW_NFT_COMMAND:-}" ]; then
    warn "DRFW_NFT_COMMAND is set in the environment; unsetting it (the kit tests the real nft)"
fi
unset DRFW_NFT_COMMAND DRFW_GUARD_STATE_DIR DRFW_ELEVATION_METHOD

# ----------------------------------------------------------------------------
# Binaries and compiled-in paths
# ----------------------------------------------------------------------------

target_dirs() {
    [ -n "${CARGO_TARGET_DIR:-}" ] && printf '%s\n' "$CARGO_TARGET_DIR"
    [ -n "$REPO_DIR" ] && printf '%s\n' "$REPO_DIR/target"
}

find_drfw() {
    local dir
    if [ -n "$OPT_DRFW" ]; then
        printf '%s\n' "$OPT_DRFW"
        return
    fi
    if [ -x "$KIT_DIR/bin/drfw" ]; then
        printf '%s\n' "$KIT_DIR/bin/drfw"
        return
    fi
    while IFS= read -r dir; do
        if [ -x "$dir/release/drfw" ]; then
            printf '%s\n' "$dir/release/drfw"
            return
        fi
    done < <(target_dirs)
    command -v drfw 2>/dev/null
}

find_e2e_bin() {
    local dir
    if [ -n "$OPT_E2E_BIN" ]; then
        printf '%s\n' "$OPT_E2E_BIN"
        return
    fi
    if [ -x "$KIT_DIR/bin/root_e2e" ]; then
        printf '%s\n' "$KIT_DIR/bin/root_e2e"
        return
    fi
    while IFS= read -r dir; do
        [ -d "$dir/release" ] || continue
        find "$dir/release" -type f -name 'root_e2e-*' -perm -u+x \
            -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -n1 | cut -d' ' -f2-
    done < <(target_dirs) | head -n1
}

find_helper() {
    local dir
    if [ -n "$OPT_HELPER" ]; then
        printf '%s\n' "$OPT_HELPER"
        return
    fi
    if [ -x "$KIT_DIR/bin/drfw-helper" ]; then
        printf '%s\n' "$KIT_DIR/bin/drfw-helper"
        return
    fi
    while IFS= read -r dir; do
        if [ -x "$dir/release/drfw-helper" ]; then
            printf '%s\n' "$dir/release/drfw-helper"
            return
        fi
    done < <(target_dirs)
}

DRFW=$(find_drfw)
E2E_BIN=$(find_e2e_bin)
[ -n "$E2E_BIN" ] && [ ! -x "$E2E_BIN" ] && E2E_BIN=
HELPER_BIN=$(find_helper)
[ -n "$HELPER_BIN" ] && [ ! -x "$HELPER_BIN" ] && HELPER_BIN=

# e2e_bin_run TESTNAME: runs one ignored test of the e2e binary
e2e_bin_run() {
    "$1" --ignored --exact "$2" --nocapture --test-threads=1
}

# Discovers the compiled SYSTEM_NFT_PATH / SYSTEM_NFT_SERVICE: from the test
# binary (same build), else from `drfw status`, else the defaults
discover_paths() {
    local out conf='' svc='' tmp
    if [ -n "$E2E_BIN" ]; then
        out=$(e2e_bin_run "$E2E_BIN" e2e_print_paths 2>/dev/null)
        conf=$(sed -n 's/^.*E2E SYSTEM_NFT_PATH=//p' <<<"$out" | head -n1)
        svc=$(sed -n 's/^E2E SYSTEM_NFT_SERVICE=//p' <<<"$out" | head -n1)
    fi
    if [ -z "$conf" ] && [ -x "$DRFW" ]; then
        # Throwaway dirs: drfw creates its data/state dirs on start
        tmp=$(mktemp -d "${TMPDIR:-/tmp}/drfw-e2e-status.XXXXXX")
        out=$(DRFW_TEST_DATA_DIR=$tmp/data DRFW_TEST_STATE_DIR=$tmp/state "$DRFW" status 2>/dev/null)
        rm -rf -- "${tmp:?}"
        conf=$(sed -n 's/^Boot config: *\(\/[^ ]*\) .*/\1/p' <<<"$out" | head -n1)
    fi
    NFT_CONF=${OPT_NFT_CONF:-${conf:-/etc/nftables.conf}}
    SERVICE=${OPT_SERVICE:-${svc:-nftables.service}}
    PATHS_FROM=${conf:+compiled}
    PATHS_FROM=${PATHS_FROM:-default}
    [ -n "$OPT_NFT_CONF$OPT_SERVICE" ] && PATHS_FROM="$PATHS_FROM, overridden"
}
discover_paths

# The helper path compiled into drfw: the exec path of its polkit action
# (`drfw print-polkit-policy`); empty for a drfw without the helper
HELPER_PATH=
POLICY_XML=
if [ -x "$DRFW" ]; then
    POLICY_XML=$("$DRFW" print-polkit-policy 2>/dev/null)
    HELPER_PATH=$(sed -n 's|.*<annotate key="org.freedesktop.policykit.exec.path">\(/[^<]*\)</annotate>.*|\1|p' \
        <<<"$POLICY_XML" | head -n1)
fi

have_cmd() { command -v "$1" >/dev/null 2>&1; }
polkit_active() { systemctl is-active --quiet polkit.service 2>/dev/null; }
have_pkexec() { have_cmd pkexec && polkit_active; }
have_run0() { have_cmd run0 && polkit_active; }

# ----------------------------------------------------------------------------
# Safety checks
# ----------------------------------------------------------------------------

VIRT=
safety_checks() {
    local bad=0
    say "Safety checks:"
    if [ "${DRFW_E2E_DISPOSABLE:-}" = 1 ]; then
        say "  [ok] DRFW_E2E_DISPOSABLE=1"
    else
        say "  [NO] DRFW_E2E_DISPOSABLE=1 is not set"
        bad=1
    fi

    VIRT=$(systemd-detect-virt 2>/dev/null)
    VIRT=${VIRT:-unknown}
    if [ "$VIRT" != none ] && [ "$VIRT" != unknown ]; then
        say "  [ok] systemd-detect-virt: $VIRT"
    elif [ "$OVERRIDE_VIRT" = 1 ]; then
        say "  [ok] systemd-detect-virt: $VIRT, accepted because of --i-know-this-is-not-my-workstation"
    else
        say "  [NO] systemd-detect-virt: $VIRT (not a VM or container; see --help)"
        bad=1
    fi

    if [ "$EUID" -eq 0 ]; then
        say "  [ok] running as root"
    elif have_cmd sudo; then
        say "  [ok] not root; would re-run itself through sudo"
    elif have_cmd run0; then
        say "  [ok] not root; would re-run itself through run0"
    else
        say "  [NO] not root and neither sudo nor run0 is available"
        bad=1
    fi
    return "$bad"
}

# Requirements for a real run (not safety, but without them nothing works)
requirements() {
    local bad=0 cmd
    say "Requirements:"
    for cmd in nft systemctl systemd-run script runuser useradd userdel unshare \
        sha256sum flock mkfifo timeout find; do
        if have_cmd "$cmd"; then
            say "  [ok] $cmd"
        else
            say "  [NO] $cmd not found"
            bad=1
        fi
    done
    if [ -d /run/systemd/system ]; then
        say "  [ok] systemd is PID 1 (the guard uses systemd-run)"
    else
        say "  [NO] systemd is not PID 1 (boot the container with systemd, e.g. nspawn --boot)"
        bad=1
    fi
    if [ -x "$DRFW" ]; then
        say "  [ok] drfw: $DRFW ($("$DRFW" --version 2>/dev/null | head -n1))"
    else
        say "  [NO] drfw binary not found (use --drfw PATH)"
        bad=1
    fi
    if [ -n "$E2E_BIN" ]; then
        say "  [ok] e2e test binary: $E2E_BIN"
    else
        say "  [--] e2e test binary not found: scenario 8 is skipped, scenario 9 falls back"
        say "       to 'drfw export'. Build: cargo test --release --test root_e2e --no-run"
    fi
    if have_cmd sudo && have_cmd visudo; then
        say "  [ok] sudo + visudo"
    else
        say "  [NO] sudo/visudo not found (scenario 1 and the guard scenarios elevate with sudo)"
        bad=1
    fi
    if [ -n "$HELPER_BIN" ] && [ -n "$HELPER_PATH" ]; then
        say "  [ok] drfw-helper: $HELPER_BIN (installed as $HELPER_PATH for scenario 11)"
    elif [ -z "$HELPER_PATH" ]; then
        say "  [--] drfw has no print-polkit-policy (built before the helper): scenario 11 is skipped"
    else
        say "  [--] drfw-helper binary not found (use --helper PATH): scenario 11 is skipped."
        say "       Build: cargo build --release --bin drfw-helper"
    fi
    if have_pkexec; then say "  [ok] pkexec + polkit"; else say "  [--] pkexec or polkit missing: pkexec checks skipped"; fi
    if have_cmd pkttyagent && have_cmd chpasswd; then
        say "  [ok] pkttyagent + chpasswd (scenario 11 counts real password prompts)"
    else
        say "  [--] pkttyagent or chpasswd missing: scenario 11 skips the prompt count"
    fi
    if have_run0; then say "  [ok] run0 + polkit"; else say "  [--] run0 or polkit missing: run0 checks skipped"; fi
    if have_echo_tool; then say "  [ok] socat or python3 (TCP echo)"; else say "  [--] neither socat nor python3: scenarios 7 and 10 are skipped"; fi
    if have_cmd ip; then say "  [ok] ip (iproute2)"; else say "  [--] ip not found: scenario 10 is skipped"; fi
    return "$bad"
}

print_plan() {
    say "DRFW root e2e kit, phase: $PHASE"
    say "  drfw binary:        ${DRFW:-<not found>}"
    say "  e2e test binary:    ${E2E_BIN:-<not found>}"
    say "  drfw-helper:        ${HELPER_BIN:-<not found>} -> ${HELPER_PATH:-<not in this drfw>}"
    say "  system config:      $NFT_CONF ($PATHS_FROM)"
    say "  boot service:       $SERVICE"
    say "  guard elevation:    $GUARD_METHOD"
    say "  test user:          $TEST_USER (home $USER_HOME, runtime dir $RT_DIR)"
    say "  work dir:           $WORK (logs in $LOG_DIR)"
    say ""
    say "Changes made during the run (all undone on exit unless noted):"
    case $PHASE in
        all)
            say "  - create user $TEST_USER (deleted on exit if the kit created it)"
            say "  - $SUDOERS_FILE: NOPASSWD /bin/sh, nft and the helper for $TEST_USER only, logging to $SUDO_LOG"
            say "  - $POLKIT_RULE: pkexec (/bin/sh, nft) and systemd units for $TEST_USER only;"
            say "    $TEST_USER is its own polkit admin (scenario 11 authenticates with a random password)"
            say "  - scenario 11: install the helper at ${HELPER_PATH:-<helper path>} and $POLKIT_ACTION"
            say "    (removed again unless an identical copy was already installed)"
            say "  - back up $NFT_CONF{,.drfw-orig,.drfw-bak}, the enablement of $SERVICE and the"
            say "    inet drfw table; restored on exit"
            say "  - apply/delete the nftables table inet drfw (no other table is touched)"
            say "  - network namespace $PEER_NS with veth $VETH_A/$VETH_B ($IP_A, $IP_B)"
            ;;
        boot-prep)
            say "  - back up $NFT_CONF{,.drfw-orig,.drfw-bak} and the enablement of $SERVICE"
            say "    into $BOOT_DIR/backup (restored by --phase boot-check, NOT on exit)"
            say "  - Save to System a test profile into $NFT_CONF and enable $SERVICE"
            ;;
        boot-check)
            say "  - compare the live inet drfw table with the one recorded by boot-prep"
            say "  - restore $NFT_CONF, its backups and the enablement of $SERVICE"
            ;;
    esac
    say ""
    say "Scenarios:"
    local s
    if [ "$PHASE" = all ]; then
        for s in $SCENARIOS; do
            case $s in
                1)
                    say "   1  elevation as a real user: drfw check without privileges; apply via sudo,"
                    say "      pkexec, run0 and auto-detection in a PTY; verify uses the namespace check"
                    ;;
                2) say "   2  guard timeout (systemd path): previous table restored / no table removed" ;;
                3) say "   3  SSH drop: SIGHUP, SIGKILL and PTY hangup of the CLI; watcher reverts on time" ;;
                4) say "   4  confirm key keeps the rules; status confirmed; no revert later" ;;
                5) say "   5  revert-now key restores immediately" ;;
                6) say "   6  supersede: second apply during a countdown; timeout returns to the last confirmed state" ;;
                7) say "   7  first apply with no table (Server Mode), timeout: loopback works, no table left" ;;
                8) say "   8  Save to System: .drfw-orig once, .drfw-bak each save, nft -c, idempotent load, broken save rejected" ;;
                9) say "   9  boot persistence: run --phase boot-prep, reboot, --phase boot-check" ;;
                10) say "  10  Server Mode over a veth: established inbound TCP survives, new one blocked, loopback works" ;;
                11)
                    say "  11  root helper: installed helper and polkit action, DRFW elevates only the helper"
                    say "      (sudo log), guard timeout and Save to System through it, refusals as root, and"
                    say "      two GUI applies from one process prompt for a password once (pkttyagent)"
                    ;;
            esac
        done
    else
        say "   9  boot persistence ($PHASE)"
    fi
    say ""
}

# Validates the kit's profiles against this drfw build without privileges
# (`drfw check` runs nft in a private user+network namespace)
profile_selfcheck() {
    local tmp name out rc line bad=0
    tmp=$(mktemp -d "${TMPDIR:-/tmp}/drfw-e2e-profiles.XXXXXX") || return 1
    write_profiles "$tmp/data"
    say "Profile self-check (unprivileged drfw check in a throwaway data dir):"
    for name in e2e-a e2e-b e2e-c e2e-srv; do
        out=$(DRFW_TEST_DATA_DIR=$tmp/data DRFW_TEST_STATE_DIR=$tmp/state \
            "$DRFW" check "$name" 2>&1)
        rc=$?
        if [ "$rc" -eq 0 ]; then
            say "  [ok] $name: $(tail -n1 <<<"$out")"
        else
            say "  [NO] $name (exit $rc):"
            while IFS= read -r line; do say "       $line"; done <<<"$out"
            bad=1
        fi
    done
    rm -rf -- "${tmp:?}"
    return "$bad"
}

# ----------------------------------------------------------------------------
# Dry run / refusal / elevation
# ----------------------------------------------------------------------------

print_plan
if ! safety_checks; then
    say ""
    say "REFUSED: the safety checks above failed; nothing was changed."
    exit 2
fi
say ""

if [ "$DRY_RUN" = 1 ]; then
    requirements
    req=$?
    say ""
    if [ -x "$DRFW" ]; then
        profile_selfcheck
        req=$((req | $?))
        say ""
    fi
    if [ "$req" -ne 0 ]; then
        say "DRY RUN: safety checks passed, but requirements are missing (see above). Nothing was changed."
        exit 2
    fi
    say "DRY RUN: safety checks and requirements passed. Nothing was changed."
    exit 0
fi

if [ "$EUID" -ne 0 ]; then
    extra=()
    [ "$OVERRIDE_VIRT" = 1 ] && extra=(DRFW_E2E_ALLOW_BARE_METAL=1)
    say "Re-running as root..."
    if have_cmd sudo; then
        exec sudo -- env DRFW_E2E_DISPOSABLE=1 "${extra[@]}" bash "$SELF" "${ORIG_ARGS[@]}"
    fi
    exec run0 env DRFW_E2E_DISPOSABLE=1 "${extra[@]}" bash "$SELF" "${ORIG_ARGS[@]}"
fi

requirements || die "requirements missing (see above)"
say ""
if [ "$OVERRIDE_VIRT" = 1 ]; then
    export DRFW_E2E_ALLOW_BARE_METAL=1
fi

exec {LOCK_FD}>"$LOCK_FILE" || die "cannot open $LOCK_FILE"
flock -n "$LOCK_FD" || die "another run of the kit is in progress"

# ----------------------------------------------------------------------------
# Backup / restore of the system state the kit changes
# ----------------------------------------------------------------------------

conf_files() { printf '%s\n' "$NFT_CONF" "$NFT_CONF.drfw-orig" "$NFT_CONF.drfw-bak"; }

# backup_system DIR: keeps an existing complete backup (never overwrites the
# original state with an intermediate one)
backup_system() {
    local dir=$1 f key
    if [ -e "$dir/.complete" ]; then
        note "reusing the existing backup in $dir"
        return 0
    fi
    rm -rf -- "${dir:?}"
    install -d -m 700 -- "$dir" || return 1
    while IFS= read -r f; do
        key=$(basename -- "$f")
        if [ -e "$f" ]; then
            cp -a -- "$f" "$dir/$key" || return 1
        else
            : >"$dir/$key.absent"
        fi
    done < <(conf_files)
    systemctl is-enabled -- "$SERVICE" >"$dir/service.enabled" 2>/dev/null
    if drfw_table_exists; then
        nft list table inet drfw >"$dir/drfw-table.nft" || return 1
    fi
    touch -- "$dir/.complete"
}

# restore_system DIR [table]: files and service enablement; with "table"
# also the inet drfw table as it was at backup time
restore_system() {
    local dir=$1 f key was now bad=0
    [ -e "$dir/.complete" ] || return 0
    while IFS= read -r f; do
        key=$(basename -- "$f")
        if [ -e "$dir/$key" ]; then
            cp -a -- "$dir/$key" "$f" || bad=1
        elif [ -e "$dir/$key.absent" ]; then
            rm -f -- "$f" || bad=1
        fi
    done < <(conf_files)
    rm -f -- "$(dirname -- "$NFT_CONF")/.$(basename -- "$NFT_CONF").drfw-tmp"
    was=$(cat -- "$dir/service.enabled" 2>/dev/null)
    now=$(systemctl is-enabled -- "$SERVICE" 2>/dev/null)
    # Never start or stop the service: its ExecStop flushes the whole ruleset
    if [ "$was" = enabled ] && [ "$now" != enabled ]; then
        systemctl enable --quiet -- "$SERVICE" || bad=1
    elif [ "$was" != enabled ] && [ "$now" = enabled ]; then
        systemctl disable --quiet -- "$SERVICE" || bad=1
    fi
    if [ "${2:-}" = table ]; then
        drfw_table_delete || bad=1
        if [ -f "$dir/drfw-table.nft" ]; then
            nft -f "$dir/drfw-table.nft" || bad=1
        fi
    fi
    [ "$bad" -eq 0 ] && rm -rf -- "${dir:?}"
    return "$bad"
}

# ----------------------------------------------------------------------------
# Environment setup / teardown
# ----------------------------------------------------------------------------

SETUP_DONE=0
NET_UP=0
CLIENT_PID=

write_sudoers() {
    local tmp
    tmp=$(mktemp "$WORK/sudoers.XXXXXX") || return 1
    cat >"$tmp" <<EOF
# drfw e2e kit (tools/e2e/run.sh); removed on exit. Test user only.
Defaults:$TEST_USER logfile=$SUDO_LOG, loglinelen=0, !lecture
$TEST_USER ALL=(root) NOPASSWD: /bin/sh, /usr/bin/sh, /usr/bin/nft, /usr/sbin/nft, /sbin/nft${HELPER_PATH:+, $HELPER_PATH}
EOF
    if ! visudo -cqf "$tmp"; then
        rm -f -- "$tmp"
        return 1
    fi
    install -m 0440 -o root -g root -- "$tmp" "$SUDOERS_FILE"
    rm -f -- "$tmp"
}

write_polkit_rule() {
    [ -d "$(dirname -- "$POLKIT_RULE")" ] || return 0
    cat >"$POLKIT_RULE" <<EOF
// drfw e2e kit (tools/e2e/run.sh); removed on exit. Test user only.
polkit.addRule(function(action, subject) {
    if (subject.user != "$TEST_USER") {
        return polkit.Result.NOT_HANDLED;
    }
    if (action.id == "org.freedesktop.policykit.exec") {
        var p = action.lookup("program");
        if (p == "/bin/sh" || p == "/usr/bin/sh" || p == "/usr/bin/nft" ||
            p == "/usr/sbin/nft" || p == "/sbin/nft") {
            return polkit.Result.YES;
        }
    }
    // run0 asks for systemd unit management
    if (action.id.indexOf("org.freedesktop.systemd1.") == 0) {
        return polkit.Result.YES;
    }
    // org.drfw.helper (scenario 11, with a real password): an active local
    // session gets the action's own default, auth_admin_keep. The kit's
    // processes (runuser, no seat) count as non-local, for which the action
    // says auth_admin; give them what an active local session gets so the
    // prompts can be counted (the defaults themselves are checked with pkaction)
    if (action.id == "org.drfw.helper") {
        if (subject.local && subject.active) {
            return polkit.Result.NOT_HANDLED;
        }
        polkit.log("drfw e2e: org.drfw.helper for a non-local subject: auth_admin_keep");
        return polkit.Result.AUTH_ADMIN_KEEP;
    }
    return polkit.Result.NOT_HANDLED;
});
// The test user authenticates as itself for auth_admin (scenario 11), so
// pkttyagent asks for its password and nothing else
polkit.addAdminRule(function(action, subject) {
    if (subject.user == "$TEST_USER") {
        return ["unix-user:$TEST_USER"];
    }
    return null;
});
EOF
    chmod 0644 -- "$POLKIT_RULE"
    # polkitd picks up rule changes through inotify
    sleep 1
}

setup_env() {
    say "Setting up..."
    install -d -m 755 -- "$WORK" "$BIN_DIR" || return 1
    rm -rf -- "${LOG_DIR:?}"
    install -d -m 755 -- "$LOG_DIR" || return 1
    install -m 0755 -- "$DRFW" "$BIN_DIR/drfw" || return 1
    DRFW=$BIN_DIR/drfw
    if [ -n "$E2E_BIN" ]; then
        install -m 0755 -- "$E2E_BIN" "$BIN_DIR/root_e2e" || return 1
        E2E_BIN=$BIN_DIR/root_e2e
    fi
    if [ -n "$HELPER_BIN" ]; then
        install -m 0755 -- "$HELPER_BIN" "$BIN_DIR/drfw-helper" || return 1
        HELPER_BIN=$BIN_DIR/drfw-helper
    fi

    if id -u "$TEST_USER" >/dev/null 2>&1; then
        [ -e "$WORK/.created-user" ] ||
            die "user $TEST_USER exists but was not created by this kit; refusing to use it"
    fi
    # From here on, on_exit undoes whatever was set up (each step is
    # idempotent to undo, and the backup is only restored once complete)
    SETUP_DONE=1
    if ! id -u "$TEST_USER" >/dev/null 2>&1; then
        useradd --create-home --home-dir "$USER_HOME" --shell /bin/bash --user-group \
            --comment "drfw e2e kit" "$TEST_USER" || return 1
        : >"$WORK/.created-user"
    fi
    rm -rf -- "${USER_ROOT:?}" "${RT_DIR:?}"
    install -d -o "$TEST_USER" -g "$TEST_USER" -m 0700 -- \
        "$USER_ROOT" "$USER_DATA" "$USER_STATE" "$PTY_ROOT" "$RT_DIR" || return 1
    write_profiles "$USER_DATA"
    chown -R "$TEST_USER:$TEST_USER" -- "$USER_DATA"
    chmod 0600 -- "$USER_DATA"/profiles/*.json

    write_sudoers || return 1
    : >"$SUDO_LOG"
    chmod 0600 -- "$SUDO_LOG"
    write_polkit_rule

    backup_system "$BACKUP_DIR" || return 1
    note "test user $TEST_USER (uid $(id -u "$TEST_USER")), profiles in $USER_DATA/profiles"
    note "backup of $NFT_CONF, $SERVICE enablement and inet drfw in $BACKUP_DIR"
    say ""
}

net_teardown() {
    if [ -n "$CLIENT_PID" ]; then
        kill "$CLIENT_PID" 2>/dev/null
        wait "$CLIENT_PID" 2>/dev/null
        CLIENT_PID=
    fi
    [ "$NET_UP" = 1 ] || return 0
    ip netns del "$PEER_NS" 2>/dev/null
    ip link del "$VETH_A" 2>/dev/null
    NET_UP=0
}

net_setup() {
    have_cmd ip || return 1
    ip link del "$VETH_A" 2>/dev/null
    ip netns del "$PEER_NS" 2>/dev/null
    ip netns add "$PEER_NS" || return 1
    NET_UP=1
    ip link add "$VETH_A" type veth peer name "$VETH_B" &&
        ip link set "$VETH_B" netns "$PEER_NS" &&
        ip addr add "$IP_A/30" dev "$VETH_A" &&
        ip link set "$VETH_A" up &&
        ip -n "$PEER_NS" addr add "$IP_B/30" dev "$VETH_B" &&
        ip -n "$PEER_NS" link set "$VETH_B" up &&
        ip -n "$PEER_NS" link set lo up
}

on_exit() {
    local rc=$? bad=0
    trap - EXIT
    pty_cleanup
    net_teardown
    echo_stop_all
    if [ "$SETUP_DONE" = 1 ]; then
        say ""
        say "Cleaning up..."
        settle_guard
        if [ "$PHASE" = all ]; then
            restore_system "$BACKUP_DIR" table || {
                warn "restoring the system state from $BACKUP_DIR failed; it is kept there"
                bad=1
            }
        fi
        [ -f "$SUDO_LOG" ] && cp -- "$SUDO_LOG" "$LOG_DIR/sudo.log"
        rm -f -- "$SUDOERS_FILE" "$SUDO_LOG" "$POLKIT_RULE"
        helper_uninstall || bad=1
        rm -rf -- "${USER_ROOT:?}" "${RT_DIR:?}"
        if [ -e "$WORK/.created-user" ]; then
            userdel "$TEST_USER" 2>/dev/null || warn "cannot delete user $TEST_USER"
            rm -rf -- "${USER_HOME:?}"
            rm -f -- "$WORK/.created-user"
        fi
        if drfw_table_exists && [ ! -f "$BACKUP_DIR/drfw-table.nft" ] && [ "$PHASE" = all ] && [ "$bad" = 0 ]; then
            warn "an inet drfw table is still present after the restore"
            bad=1
        fi
        note "logs kept in $LOG_DIR"
    fi
    [ "$bad" -ne 0 ] && [ "$rc" -eq 0 ] && rc=1
    exit "$rc"
}
trap on_exit EXIT
trap 'exit 130' INT TERM HUP

# ----------------------------------------------------------------------------
# Scenario helpers
# ----------------------------------------------------------------------------

# log_file NAME: a log path for this scenario step
log_file() { printf '%s/%s.log\n' "$LOG_DIR" "$1"; }

# evidence_tail TEXT: the last lines of a CLI output as evidence
evidence_tail() {
    local line
    while IFS= read -r line; do
        evidence "  > $line"
    done < <(tail -n "${2:-6}" <<<"$1")
}

# apply_now LOG METHOD PROFILE: `drfw apply PROFILE --no-confirm --yes` as
# the test user without a terminal; prints nothing, returns the CLI's status.
# --yes: these scenarios test the apply itself, and the confirmation guard
# (switching profiles removes most kept rules, Server Mode) would refuse
# without a terminal (exit 9)
apply_now() {
    local log=$1 method=$2 profile=$3
    as_user_method "$method" "$DRFW" apply "$profile" --no-confirm --yes </dev/null >"$log" 2>&1
}

# baseline PROFILE LABEL: reset, then a confirmed (unguarded) PROFILE as the
# "last confirmed" state
baseline() {
    reset_state
    local log
    log=$(log_file "baseline-$1-$(now_ms)")
    if ! apply_now "$log" sudo "$1" || ! drfw_table_has_rule "$2"; then
        evidence "FAIL: could not apply the baseline profile $1"
        evidence_tail "$(cat -- "$log")"
        return 1
    fi
    evidence "ok:   baseline $1 applied without a guard ($2 live)"
}

ARM_NONCE=
ARM_T0=
# guard_arm TAG PROFILE TIMEOUT [PREV_NONCE]: `drfw apply PROFILE --confirm
# TIMEOUT --yes` in a PTY (--yes: no y/N question of the confirmation guard
# before the countdown); waits until its guard is armed
guard_arm() {
    ARM_NONCE=
    pty_start "$1" "$GUARD_METHOD" "$DRFW" apply "$2" --confirm "$3" --yes
    if ! ARM_NONCE=$(wait_new_guard "${4:-}" 60); then
        evidence "FAIL: no revert guard was armed within 60 s; CLI output:"
        evidence_tail "$(pty_out "$1")"
        return 1
    fi
    ARM_T0=$(now_ms)
    evidence "ok:   guard armed: nonce $ARM_NONCE, launcher $(guard_launcher "$ARM_NONCE")"
}

# finish_cli TAG SECONDS EXPECTED-TEXT: the CLI exits 0 and printed the text
finish_cli() {
    local rc out
    pty_wait "$1" "$2"
    rc=$PTY_RC
    out=$(pty_out "$1")
    printf '%s\n' "$out" >"$(log_file "cli-$1")"
    if [ "$rc" = 0 ] && grep -qF -- "$3" <<<"$out"; then
        evidence "ok:   CLI exited 0 and printed \"$3\""
        return 0
    fi
    evidence "FAIL: CLI exit $rc, expected \"$3\"; output:"
    evidence_tail "$out"
    return 1
}

# verdict NAME OK: PASS/FAIL from the collected sub-check results
verdict() {
    if [ "$2" -eq 0 ]; then pass "$1"; else fail "$1"; fi
}

elapsed_since() { printf '%s\n' "$(($(now_ms) - $1))"; }

# ----------------------------------------------------------------------------
# Scenario 1: elevation as a real user
# ----------------------------------------------------------------------------

scenario_1() {
    local name="1 elevation as a real user" bad=0 out rc cmds sh_n nft_n userns log
    say "--- $name"

    if as_user unshare -rn true 2>/dev/null; then
        userns=1
        evidence "info: unprivileged user namespaces are allowed for $TEST_USER"
    else
        userns=0
        evidence "info: unprivileged user namespaces are NOT allowed; verify must fall back to elevation"
    fi

    # 1a: drfw check needs no elevation at all
    sudo_log_reset
    out=$(as_user "$DRFW" check e2e-a </dev/null 2>&1)
    rc=$?
    if [ "$userns" = 1 ]; then
        check "drfw check passes without privileges (exit $rc)" \
            eval '[ "$rc" -eq 0 ] && grep -q "without privileges" <<<"$out"' || bad=1
        check "drfw check made no sudo call (sudo log: '$(sudo_log_commands | tr '\n' ' ')')" \
            test -z "$(sudo_log_commands)" || bad=1
    else
        check "drfw check reports the namespace check as unavailable (exit $rc)" \
            eval '[ "$rc" -ne 0 ] && grep -q "not available" <<<"$out"' || bad=1
    fi

    # 1b: sudo, and verify's path from the sudo log
    reset_state
    sudo_log_reset
    log=$(log_file s1-sudo)
    apply_now "$log" sudo e2e-a
    rc=$?
    check "sudo: drfw apply --no-confirm exits 0 (exit $rc)" test "$rc" -eq 0 || bad=1
    check "sudo: rule e2e-A is live in inet drfw" drfw_table_has_rule e2e-A || bad=1
    cmds=$(sudo_log_commands)
    # A helper installed before the run (a packaged drfw) replaces /bin/sh
    sh_n=$(awk -v h="$HELPER_PATH" '$2 ~ /\/sh$/ || (h != "" && $2 == h) {n += $1} END {print n + 0}' <<<"$cmds")
    nft_n=$(awk '$2 ~ /\/nft$/ {n += $1} END {print n + 0}' <<<"$cmds")
    evidence "info: sudo log: $(tr '\n' ' ' <<<"$cmds")"
    if [ "$userns" = 1 ]; then
        check "sudo: one elevation (the apply script), verify ran unprivileged ($sh_n x sh, $nft_n x nft)" \
            eval '[ "$sh_n" -eq 1 ] && [ "$nft_n" -eq 0 ]' || bad=1
    else
        check "sudo: apply script elevated once, verify fell back to elevated nft ($sh_n x sh, $nft_n x nft)" \
            eval '[ "$sh_n" -eq 1 ] && [ "$nft_n" -ge 1 ]' || bad=1
    fi
    [ "$rc" -eq 0 ] || evidence_tail "$(cat -- "$log")"

    # 1c: pkexec (no terminal, like the GUI)
    if have_pkexec; then
        reset_state
        log=$(log_file s1-pkexec)
        apply_now "$log" pkexec e2e-b
        rc=$?
        check "pkexec: drfw apply exits 0 and e2e-B is live (exit $rc)" \
            eval '[ "$rc" -eq 0 ] && drfw_table_has_rule e2e-B' || {
            bad=1
            evidence_tail "$(cat -- "$log")"
        }
    else
        evidence "skip: pkexec (pkexec or polkit.service not available)"
    fi

    # 1d: run0
    if have_run0; then
        reset_state
        log=$(log_file s1-run0)
        apply_now "$log" run0 e2e-c
        rc=$?
        check "run0: drfw apply exits 0 and e2e-C is live (exit $rc)" \
            eval '[ "$rc" -eq 0 ] && drfw_table_has_rule e2e-C' || {
            bad=1
            evidence_tail "$(cat -- "$log")"
        }
    else
        evidence "skip: run0 (run0 or polkit.service not available)"
    fi

    # 1e: no DRFW_ELEVATION_METHOD, in a PTY: the CLI picks run0, else sudo
    if have_cmd run0 && ! polkit_active; then
        evidence "skip: auto-detection (it would pick run0, but polkit is not running)"
    else
        reset_state
        sudo_log_reset
        pty_start s1-auto auto "$DRFW" apply e2e-a --no-confirm --yes
        pty_wait s1-auto 60
        rc=$PTY_RC
        local picked=sudo
        have_cmd run0 && picked=run0
        check "auto in a PTY ($picked expected): exit $rc and e2e-A is live" \
            eval '[ "$rc" = 0 ] && drfw_table_has_rule e2e-A' || {
            bad=1
            evidence_tail "$(pty_out s1-auto)"
        }
        if [ "$picked" = sudo ]; then
            check "auto picked sudo (sudo log: '$(sudo_log_commands | tr '\n' ' ')')" \
                test -n "$(sudo_log_commands)" || bad=1
        fi
    fi

    reset_state
    verdict "$name" "$bad"
}

# ----------------------------------------------------------------------------
# Scenario 2: guard timeout on the systemd path
# ----------------------------------------------------------------------------

# guard_timeout_case TAG LABEL-OF-BASELINE-OR-EMPTY: one timeout run of e2e-b
guard_timeout_case() {
    local tag=$1 base=$2 bad=0 before after status el ustate launcher timeout=6
    if [ -n "$base" ]; then
        baseline e2e-a "$base" || return 1
    else
        reset_state
        check "no inet drfw table before the apply" eval '! drfw_table_exists' || return 1
    fi
    before=$(drfw_table_dump)
    guard_arm "$tag" e2e-b "$timeout" || return 1
    launcher=$(guard_launcher "$ARM_NONCE")
    check "watcher launched by systemd-run (active file says '$launcher')" \
        test "$launcher" = systemd || bad=1
    ustate=$(unit_state "$ARM_NONCE")
    check "transient unit drfw-revert-$ARM_NONCE.service exists during the countdown (ActiveState=$ustate)" \
        test "$ustate" = active || bad=1
    check "the new rules are live during the countdown (e2e-B)" drfw_table_has_rule e2e-B || bad=1
    status=$(wait_status "$ARM_NONCE" $((timeout + 20)))
    el=$(elapsed_since "$ARM_T0")
    after=$(drfw_table_dump)
    check "status-$ARM_NONCE is 'reverted' (got '$status')" test "$status" = reverted || bad=1
    check "reverted on time: $(ms_to_s "$el") s after arming (timeout ${timeout} s)" \
        eval '[ "$el" -ge $((timeout * 1000 - 1500)) ] && [ "$el" -le $((timeout * 1000 + 4000)) ]' || bad=1
    if [ -n "$base" ]; then
        check "previous table restored exactly (before $(dump_digest "$before"), after $(dump_digest "$after"))" \
            test "$before" = "$after" || bad=1
    else
        check "no inet drfw table after the revert" eval '! drfw_table_exists' || bad=1
    fi
    check "transient unit gone after the revert" wait_unit_gone "$ARM_NONCE" 10 || bad=1
    finish_cli "$tag" 20 "Reverted to the previous rules." || bad=1
    return "$bad"
}

scenario_2() {
    local name="2 guard timeout (systemd path)" bad=0
    say "--- $name"
    evidence "case a: previous table e2e-A, then e2e-B --confirm 6, no keys"
    guard_timeout_case s2a e2e-A || bad=1
    evidence "case b: no previous table, then e2e-B --confirm 6, no keys"
    guard_timeout_case s2b "" || bad=1
    reset_state
    verdict "$name" "$bad"
}

# ----------------------------------------------------------------------------
# Scenario 3: the CLI dies during the countdown (SSH drop)
# ----------------------------------------------------------------------------

scenario_3() {
    local name="3 SSH drop: the watcher reverts without the CLI" bad=0 how cli sp before after status el i timeout=8
    say "--- $name"
    for how in HUP KILL hangup; do
        evidence "case $how:"
        baseline e2e-a e2e-A || {
            bad=1
            continue
        }
        before=$(drfw_table_dump)
        guard_arm "s3-$how" e2e-b "$timeout" || {
            bad=1
            continue
        }
        if ! cli=$(pty_cli_pid "s3-$how"); then
            evidence "FAIL: no CLI pid"
            bad=1
            continue
        fi
        sleep 2
        case $how in
            HUP | KILL)
                kill "-$how" "$cli"
                evidence "info: sent SIG$how to the CLI (pid $cli) 2 s into the countdown"
                ;;
            hangup)
                # Kill the PTY's owner (`script`, the CLI's parent): the master
                # side closes and the kernel hangs up the CLI's terminal, which
                # is what sshd does when the connection drops
                sp=$(awk '{print $4}' "/proc/$cli/stat" 2>/dev/null)
                kill -KILL "$sp"
                evidence "info: killed the PTY owner (script, pid $sp) of the CLI (pid $cli)"
                ;;
        esac
        for i in $(seq 50); do
            kill -0 "$cli" 2>/dev/null || break
            sleep 0.1
            : "$i"
        done
        check "the CLI (pid $cli) is gone" eval '! kill -0 "$cli" 2>/dev/null' || bad=1
        pty_wait "s3-$how" 5
        check "rules still live after the CLI died (e2e-B)" drfw_table_has_rule e2e-B || bad=1
        status=$(wait_status "$ARM_NONCE" $((timeout + 20)))
        el=$(elapsed_since "$ARM_T0")
        after=$(drfw_table_dump)
        check "status-$ARM_NONCE is 'reverted' (got '$status')" test "$status" = reverted || bad=1
        check "reverted on time: $(ms_to_s "$el") s after arming (timeout ${timeout} s)" \
            eval '[ "$el" -ge $((timeout * 1000 - 1500)) ] && [ "$el" -le $((timeout * 1000 + 4000)) ]' || bad=1
        check "previous table restored exactly ($(dump_digest "$before") = $(dump_digest "$after"))" \
            test "$before" = "$after" || bad=1
    done
    reset_state
    verdict "$name" "$bad"
}

# ----------------------------------------------------------------------------
# Scenario 4: confirm
# ----------------------------------------------------------------------------

scenario_4() {
    local name="4 confirm keeps the rules" bad=0 ts status el kept timeout=6 wait_ms
    say "--- $name"
    baseline e2e-a e2e-A || {
        verdict "$name" 1
        return
    }
    if guard_arm s4 e2e-b "$timeout"; then
        sleep 1.5
        ts=$(now_ms)
        pty_send s4 c
        status=$(wait_status "$ARM_NONCE" 10)
        el=$(elapsed_since "$ts")
        check "status-$ARM_NONCE is 'confirmed' (got '$status')" test "$status" = confirmed || bad=1
        check "confirmed $(ms_to_s "$el") s after the key (< 3 s)" test "$el" -lt 3000 || bad=1
        finish_cli s4 15 "Changes confirmed" || bad=1
        kept=$(drfw_table_dump)
        # Wait until 4 s past the original deadline
        wait_ms=$((ARM_T0 + timeout * 1000 + 4000 - $(now_ms)))
        [ "$wait_ms" -gt 0 ] && sleep "$(ms_to_s "$wait_ms")"
        check "rules still live 4 s after the deadline (e2e-B)" drfw_table_has_rule e2e-B || bad=1
        check "table unchanged since the confirm" test "$(drfw_table_dump)" = "$kept" || bad=1
        check "status still 'confirmed'" test "$(read_status "$ARM_NONCE")" = confirmed || bad=1
        check "watcher unit gone" wait_unit_gone "$ARM_NONCE" 5 || bad=1
        check "revert file removed" test ! -e "$GUARD_DIR/revert-$ARM_NONCE.nft" || bad=1
    else
        bad=1
    fi
    reset_state
    verdict "$name" "$bad"
}

# ----------------------------------------------------------------------------
# Scenario 5: revert now
# ----------------------------------------------------------------------------

scenario_5() {
    local name="5 revert-now key restores immediately" bad=0 before after ts status el
    say "--- $name"
    baseline e2e-a e2e-A || {
        verdict "$name" 1
        return
    }
    before=$(drfw_table_dump)
    if guard_arm s5 e2e-b 60; then
        sleep 1.5
        check "new rules live before the key (e2e-B)" drfw_table_has_rule e2e-B || bad=1
        ts=$(now_ms)
        pty_send s5 r
        status=$(wait_status "$ARM_NONCE" 10)
        el=$(elapsed_since "$ts")
        after=$(drfw_table_dump)
        check "status-$ARM_NONCE is 'reverted' (got '$status')" test "$status" = reverted || bad=1
        check "reverted $(ms_to_s "$el") s after the key (< 3 s, timeout was 60 s)" test "$el" -lt 3000 || bad=1
        check "previous table restored exactly ($(dump_digest "$before") = $(dump_digest "$after"))" \
            test "$before" = "$after" || bad=1
        finish_cli s5 15 "Reverted to the previous rules." || bad=1
        check "watcher unit gone" wait_unit_gone "$ARM_NONCE" 5 || bad=1
    else
        bad=1
    fi
    reset_state
    verdict "$name" "$bad"
}

# ----------------------------------------------------------------------------
# Scenario 6: supersede
# ----------------------------------------------------------------------------

scenario_6() {
    local name="6 supersede returns to the last confirmed state" bad=0 before after n1 n2 status timeout=6
    say "--- $name"
    baseline e2e-a e2e-A || {
        verdict "$name" 1
        return
    }
    before=$(drfw_table_dump)
    if ! guard_arm s6a e2e-b 60; then
        verdict "$name" 1
        return
    fi
    n1=$ARM_NONCE
    check "first apply live (e2e-B)" drfw_table_has_rule e2e-B || bad=1
    if guard_arm s6b e2e-c "$timeout" "$n1"; then
        n2=$ARM_NONCE
        check "second apply live (e2e-C)" drfw_table_has_rule e2e-C || bad=1
        status=$(wait_status "$n1" 5)
        check "first guard status-$n1 is 'superseded' (got '$status')" test "$status" = superseded || bad=1
        check "first guard's unit stopped" wait_unit_gone "$n1" 10 || bad=1
        # A confirm for the superseded guard must change nothing
        pty_send s6a c
        finish_cli s6a 15 "Another apply replaced these rules" || bad=1
        check "the late confirm did not touch the second guard (still pending)" \
            eval '! read_status "$n2" >/dev/null' || bad=1
        status=$(wait_status "$n2" $((timeout + 20)))
        after=$(drfw_table_dump)
        check "second guard status-$n2 is 'reverted' (got '$status')" test "$status" = reverted || bad=1
        check "back to the last confirmed state e2e-A ($(dump_digest "$before") = $(dump_digest "$after"))" \
            test "$before" = "$after" || bad=1
        check "neither e2e-B nor e2e-C is live" \
            eval '! drfw_table_has_rule e2e-B && ! drfw_table_has_rule e2e-C' || bad=1
        finish_cli s6b 20 "Reverted to the previous rules." || bad=1
    else
        bad=1
    fi
    reset_state
    verdict "$name" "$bad"
}

# ----------------------------------------------------------------------------
# Scenario 7: first apply with no table, then a timeout (the lockout bug)
# ----------------------------------------------------------------------------

scenario_7() {
    local name="7 first apply without a table, timeout: no lockout" bad=0 status timeout=6
    say "--- $name"
    if ! have_echo_tool; then
        skip "$name" "needs socat or python3 for the loopback check"
        return
    fi
    reset_state
    check "no inet drfw table before the apply" eval '! drfw_table_exists' || bad=1
    if ! echo_start 127.0.0.1 "$LO_PORT"; then
        evidence "FAIL: cannot start the loopback echo server"
        verdict "$name" 1
        return
    fi
    if guard_arm s7 e2e-srv "$timeout"; then
        check "Server Mode is live (output policy drop)" \
            eval 'nft list chain inet drfw output 2>/dev/null | grep -q "policy drop"' || bad=1
        check "loopback TCP works during the countdown" echo_once 127.0.0.1 "$LO_PORT" || bad=1
        status=$(wait_status "$ARM_NONCE" $((timeout + 20)))
        check "status-$ARM_NONCE is 'reverted' or 'removed:' (got '$status')" \
            eval 'case $status in reverted | removed:*) true ;; *) false ;; esac' || bad=1
        check "no inet drfw table after the timeout" eval '! drfw_table_exists' || bad=1
        check "loopback TCP works after the timeout" echo_once 127.0.0.1 "$LO_PORT" || bad=1
        if have_cmd ping; then
            check "ping 127.0.0.1 works after the timeout" ping -c1 -W2 127.0.0.1 >/dev/null || bad=1
        fi
        finish_cli s7 20 "Reverted to the previous rules." || bad=1
    else
        bad=1
    fi
    echo_stop_all
    reset_state
    verdict "$name" "$bad"
}

# ----------------------------------------------------------------------------
# Scenario 8: Save to System
# ----------------------------------------------------------------------------

# save_as METHOD TEST PROFILE LOG: runs one e2e save test as the test user
save_as() {
    local -a env_extra=(DRFW_E2E_DISPOSABLE=1 "DRFW_E2E_SAVE_PROFILE=$3" "DRFW_E2E_SAVE_TARGET=$NFT_CONF")
    [ -n "${DRFW_E2E_ALLOW_BARE_METAL:-}" ] && env_extra+=(DRFW_E2E_ALLOW_BARE_METAL=1)
    as_user_method "$1" "${env_extra[@]}" "$E2E_BIN" --ignored --exact "$2" --nocapture \
        --test-threads=1 </dev/null >"$4" 2>&1
}

scenario_8() {
    local name="8 Save to System" bad=0 orig bak tmpf sentinel d1 d2 n log rc method out
    local h_conf h_orig h_bak h_a
    say "--- $name"
    if [ -z "$E2E_BIN" ]; then
        skip "$name" "no e2e test binary (cargo test --release --test root_e2e --no-run; see README)"
        return
    fi
    orig="$NFT_CONF.drfw-orig"
    bak="$NFT_CONF.drfw-bak"
    tmpf="$(dirname -- "$NFT_CONF")/.$(basename -- "$NFT_CONF").drfw-tmp"
    if [ ! -d "$(dirname -- "$NFT_CONF")" ]; then
        fail "$name" "$(dirname -- "$NFT_CONF") does not exist"
        return
    fi
    reset_state
    # A known "distribution" config (comments only: valid, loads nothing)
    rm -f -- "$orig" "$bak"
    sentinel=$'#!/usr/sbin/nft -f\n# drfw e2e kit: stand-in for the original distribution config\n'
    printf '%s' "$sentinel" >"$NFT_CONF"
    chmod 0644 -- "$NFT_CONF"
    h_orig=$(file_digest "$NFT_CONF")
    evidence "info: $NFT_CONF replaced by a sentinel ($h_orig); .drfw-orig/.drfw-bak removed"

    # 8a: first save (sudo)
    sudo_log_reset
    log=$(log_file s8-save-a)
    save_as sudo e2e_save_profile e2e-a "$log"
    rc=$?
    check "save e2e-a via sudo succeeds (test exit $rc, script $(grep -o 'E2E exit=[0-9a-z]*' "$log" | head -n1))" \
        test "$rc" -eq 0 || {
        bad=1
        evidence_tail "$(cat -- "$log")" 10
    }
    check "the save elevated the save script with sudo ($(sudo_log_commands | tr '\n' ' '))" \
        eval 'sudo_log_commands | grep -Eq "/sh\$|${HELPER_PATH:-/nonexistent}\$"' || bad=1
    h_a=$(file_digest "$NFT_CONF")
    check "$NFT_CONF now holds e2e-A ($h_a)" grep -qF 'comment "e2e-A"' "$NFT_CONF" || bad=1
    check "$NFT_CONF is root-owned, mode 644 ($(stat -c '%U %a' "$NFT_CONF"))" \
        test "$(stat -c '%U %a' "$NFT_CONF")" = "root 644" || bad=1
    check ".drfw-orig created from the original ($(file_digest "$orig") = $h_orig)" \
        test "$(file_digest "$orig")" = "$h_orig" || bad=1
    check ".drfw-bak holds the previous file ($(file_digest "$bak") = $h_orig)" \
        test "$(file_digest "$bak")" = "$h_orig" || bad=1
    check "no temporary file left ($tmpf)" test ! -e "$tmpf" || bad=1
    out=$(as_user "$DRFW" status 2>&1)
    check "drfw status reports the file as written by DRFW" \
        eval 'grep -q "written by DRFW" <<<"$out"' || bad=1

    # 8b: second save (pkexec without a terminal, like the GUI; else sudo)
    method=sudo
    have_pkexec && method=auto
    log=$(log_file s8-save-b)
    save_as "$method" e2e_save_profile e2e-b "$log"
    rc=$?
    check "save e2e-b via $([ "$method" = auto ] && echo pkexec || echo sudo) succeeds (exit $rc)" \
        test "$rc" -eq 0 || {
        bad=1
        evidence_tail "$(cat -- "$log")" 10
    }
    check "$NFT_CONF now holds e2e-B" grep -qF 'comment "e2e-B"' "$NFT_CONF" || bad=1
    check ".drfw-orig unchanged by the second save ($(file_digest "$orig") = $h_orig)" \
        test "$(file_digest "$orig")" = "$h_orig" || bad=1
    check ".drfw-bak now holds the first save ($(file_digest "$bak") = $h_a)" \
        test "$(file_digest "$bak")" = "$h_a" || bad=1

    # 8c: nft -c -f on the installed file
    out=$(nft -c -f "$NFT_CONF" 2>&1)
    check "nft -c -f $NFT_CONF passes" test "$?" -eq 0 || {
        bad=1
        evidence_tail "$out"
    }

    # 8d: loading it twice gives the same table, no duplicated rules
    reset_state
    nft -f "$NFT_CONF" 2>/dev/null
    d1=$(drfw_table_dump)
    nft -f "$NFT_CONF" 2>/dev/null
    d2=$(drfw_table_dump)
    n=$(grep -cF 'comment "e2e-B"' <<<"$d2")
    check "loading twice gives the same table ($(dump_digest "$d1") = $(dump_digest "$d2"))" \
        eval '[ "$d1" = "$d2" ] && [ "$d1" != "<no inet drfw table>" ]' || bad=1
    check "rule e2e-B present exactly once after two loads ($n)" test "$n" -eq 1 || bad=1
    reset_state

    # 8e: a broken save is rejected and changes nothing
    h_conf=$(file_digest "$NFT_CONF")
    h_bak=$(file_digest "$bak")
    log=$(log_file s8-save-broken)
    save_as sudo e2e_save_broken_is_rejected e2e-b "$log"
    rc=$?
    check "broken save rejected by nft -c ($(grep -o 'E2E exit=[0-9a-z]*' "$log" | head -n1), test exit $rc)" \
        eval '[ "$rc" -eq 0 ] && grep -q "E2E exit=3" "$log"' || {
        bad=1
        evidence_tail "$(cat -- "$log")" 10
    }
    check "$NFT_CONF untouched ($(file_digest "$NFT_CONF") = $h_conf)" \
        test "$(file_digest "$NFT_CONF")" = "$h_conf" || bad=1
    check ".drfw-bak untouched ($(file_digest "$bak") = $h_bak)" \
        test "$(file_digest "$bak")" = "$h_bak" || bad=1
    check ".drfw-orig untouched" test "$(file_digest "$orig")" = "$h_orig" || bad=1
    check "no temporary file left" test ! -e "$tmpf" || bad=1

    verdict "$name" "$bad"
}

# ----------------------------------------------------------------------------
# Scenario 11: the root helper and its polkit action
# ----------------------------------------------------------------------------

HELPER_STATE=$WORK/helper-installed

# helper_install: puts the helper at HELPER_PATH (root:root 755) and the
# generated action at POLKIT_ACTION (644). An identical copy that was already
# there is used as it is and left in place; a different one is never replaced.
# Markers in HELPER_STATE record what the kit created (files, directories).
helper_install() {
    local f src mode key
    install -d -m 700 -- "$HELPER_STATE" || return 1
    printf '%s\n' "$POLICY_XML" >"$HELPER_STATE/policy.xml" || return 1
    for f in "$HELPER_PATH" "$POLKIT_ACTION"; do
        key=$(basename -- "$f")
        if [ "$f" = "$POLKIT_ACTION" ]; then
            src=$HELPER_STATE/policy.xml
            mode=0644
        else
            src=$HELPER_BIN
            mode=0755
        fi
        if [ -e "$f" ] && [ ! -e "$HELPER_STATE/$key.ours" ]; then
            if cmp -s -- "$src" "$f"; then
                note "$f is already installed (identical); using it and leaving it in place"
                continue
            fi
            warn "$f exists and differs from this build; not replacing it"
            return 1
        fi
        [ -d "$(dirname -- "$f")" ] || : >"$HELPER_STATE/$key.dir-ours"
        : >"$HELPER_STATE/$key.ours"
        install -D -o root -g root -m "$mode" -- "$src" "$f" || return 1
    done
    # polkitd picks up new actions through inotify
    sleep 1
}

# helper_uninstall: removes what helper_install put there (on exit too):
# only the two files, their directory if the kit created it, and its markers
helper_uninstall() {
    local f key bad=0
    [ -d "$HELPER_STATE" ] || return 0
    for f in "$HELPER_PATH" "$POLKIT_ACTION"; do
        [ -n "$f" ] || continue
        key=$(basename -- "$f")
        if [ -e "$HELPER_STATE/$key.ours" ]; then
            rm -f -- "$f" || bad=1
        fi
        if [ -e "$HELPER_STATE/$key.dir-ours" ]; then
            rmdir -- "$(dirname -- "$f")" 2>/dev/null
        fi
        if [ "$bad" -eq 0 ]; then
            rm -f -- "$HELPER_STATE/$key.ours" "$HELPER_STATE/$key.dir-ours"
        fi
    done
    if [ "$bad" -eq 0 ]; then
        rm -f -- "$HELPER_STATE/policy.xml"
        rmdir -- "$HELPER_STATE"
    fi
    return "$bad"
}

# helper_refuses WHAT REASON ARGS...: runs the helper as root through sudo as
# the test user (so SUDO_UID is set, as in real use) with ARGS and the payload
# in $WORK/helper-payload; it must exit 1 with REASON and print no secret
helper_refuses() {
    # shellcheck disable=SC2034 # reason is read in check's eval
    local what=$1 reason=$2 out rc
    shift 2
    out=$(as_user sudo -n -- "$HELPER_PATH" "$@" <"$WORK/helper-payload" 2>&1)
    rc=$?
    printf '%s\n' "$out" >>"$(log_file s11-refusals)"
    check "refused as root: $what (exit $rc: $(head -n1 <<<"$out"))" \
        eval '[ "$rc" -eq 1 ] && grep -qF -- "drfw: drfw-helper: " <<<"$out" && grep -qF -- "$reason" <<<"$out" && ! grep -qF -- "$SECRET" <<<"$out"'
}

# prompt_session TAG PROFILES: as the test user in a PTY, starts pkttyagent
# for one process, which then becomes the e2e binary and applies PROFILES
# (comma separated) the way the GUI does; answers every password prompt.
# Prints the number of prompts.
prompt_session() {
    local tag=$1 profiles=$2 out give_up seen=0 n agent dir
    local -a env_extra=(DRFW_E2E_DISPOSABLE=1 "DRFW_E2E_APPLY_PROFILES=$profiles")
    [ -n "${DRFW_E2E_ALLOW_BARE_METAL:-}" ] && env_extra+=(DRFW_E2E_ALLOW_BARE_METAL=1)
    dir=$(pty_dir "$tag")
    # The shell starts the agent for its own PID, then execs the e2e binary:
    # same PID and start time, so the agent answers that process's pkexec
    pty_start "$tag" auto env "${env_extra[@]}" sh -c \
        'pkttyagent --process "$$" & echo "$!" > "$1/agent"; sleep 2
         exec "$0" --ignored --exact e2e_gui_applies_in_one_process --nocapture --test-threads=1' \
        "$E2E_BIN" "$dir"
    give_up=$(($(now_ms) + 150000))
    while kill -0 "${PTY_RUNNER[$tag]}" 2>/dev/null && [ "$(now_ms)" -lt "$give_up" ]; do
        out=$(pty_out "$tag")
        n=$(grep -c 'Password:' <<<"$out")
        if [ "$n" -gt "$seen" ]; then
            seen=$n
            sleep 0.3
            pty_send "$tag" "$HELPER_PW"$'\n'
        fi
        # The agent outlives the process it serves: stop it (by PID) once
        # the test binary has printed its summary
        if grep -q '^test result:' <<<"$out" && [ -s "$dir/agent" ]; then
            read -r agent <"$dir/agent" && kill "$agent" 2>/dev/null
            rm -f -- "$dir/agent"
        fi
        sleep 0.2
    done
    if [ -s "$dir/agent" ]; then
        read -r agent <"$dir/agent" && kill "$agent" 2>/dev/null
    fi
    pty_wait "$tag" 5
    out=$(pty_out "$tag")
    printf '%s\n' "$out" >"$(log_file "cli-$tag")"
    grep -c 'Password:' <<<"$out"
}

scenario_11() {
    local name="11 root helper and polkit action" bad=0 out rc cmds n before after helper_n sh_n nft_n
    local h_passwd tag
    say "--- $name"
    if [ -z "$HELPER_PATH" ]; then
        skip "$name" "this drfw has no print-polkit-policy (built before the helper)"
        return
    fi
    if [ -z "$HELPER_BIN" ]; then
        skip "$name" "no drfw-helper binary (cargo build --release --bin drfw-helper; or --helper)"
        return
    fi
    reset_state
    if ! helper_install; then
        fail "$name" "could not install the helper at $HELPER_PATH or $POLKIT_ACTION"
        helper_uninstall
        return
    fi

    # 11a: installed as a package would
    check "helper installed root:root 755 at $HELPER_PATH ($(stat -c '%U:%G %a' "$HELPER_PATH"))" \
        test "$(stat -c '%U:%G %a' "$HELPER_PATH")" = "root:root 755" || bad=1
    check "polkit action file names the helper" \
        grep -qF "<annotate key=\"org.freedesktop.policykit.exec.path\">$HELPER_PATH</annotate>" "$POLKIT_ACTION" || bad=1
    if have_cmd pkaction && polkit_active; then
        out=$(pkaction --action-id org.drfw.helper --verbose 2>&1)
        printf '%s\n' "$out" >"$(log_file s11-pkaction)"
        check "polkitd loaded org.drfw.helper: implicit active auth_admin_keep, any/inactive auth_admin" \
            eval 'grep -Eq "implicit active: +auth_admin_keep" <<<"$out" && grep -Eq "implicit any: +auth_admin$" <<<"$out" && grep -Eq "implicit inactive: +auth_admin$" <<<"$out"' || bad=1
        check "polkitd reports the exec path $HELPER_PATH" \
            eval 'grep -qF -- "$HELPER_PATH" <<<"$out"' || bad=1
    else
        evidence "skip: pkaction (pkaction or polkit.service not available)"
    fi

    # 11b: refusals as root (and not as root)
    SECRET="drfw-e2e-secret-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
    printf '%s\n' "$SECRET" >"$WORK/helper-secret"
    chmod 0600 -- "$WORK/helper-secret"
    printf '{"nftables":[]}\n' >"$WORK/helper-payload"
    chmod 0644 -- "$WORK/helper-payload"
    : >"$(log_file s11-refusals)"
    before=$(drfw_table_dump)
    h_passwd=$(file_digest /etc/passwd)
    out=$(as_user "$HELPER_PATH" check <"$WORK/helper-payload" 2>&1)
    rc=$?
    check "as the test user (not root): refused (exit $rc: $out)" \
        eval '[ "$rc" -eq 1 ] && grep -qF "must run as root" <<<"$out"' || bad=1
    out=$(env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin "$HELPER_PATH" check <"$WORK/helper-payload" 2>&1)
    rc=$?
    check "as root without pkexec/sudo/run0: refused (exit $rc: $out)" \
        eval '[ "$rc" -eq 1 ] && grep -qF "must be started by pkexec, sudo or run0" <<<"$out"' || bad=1
    out=$(env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin SUDO_UID=0 DRFW_HELPER_TEST_MODE=1 \
        DRFW_HELPER_TEST_STATE_DIR="$WORK/fake-state" "$HELPER_PATH" apply "$WORK/fake-state" 5 \
        0123456789abcdef0123456789abcdef "$RT_DIR" nft setsid 0 <"$WORK/helper-payload" 2>&1)
    rc=$?
    check "release build: the test-mode variables are ignored as root (exit $rc: $out)" \
        eval '[ "$rc" -eq 1 ] && grep -qF "the state directory must be" <<<"$out" && [ ! -e "$WORK/fake-state" ]' || bad=1
    local uid nonce=0123456789abcdef0123456789abcdef nft_arg
    uid=$(id -u "$TEST_USER")
    # The nft argument DRFW passes is NFT_COMMAND: read it from a refusal
    nft_arg=$(as_user sudo -n -- "$HELPER_PATH" save-config "$NFT_CONF" __probe__ "" \
        <"$WORK/helper-payload" 2>&1 | sed -n 's/.*nft must be "\([^"]*\)".*/\1/p')
    nft_arg=${nft_arg:-nft}
    evidence "info: the helper's nft is '$nft_arg'"
    helper_refuses "unknown request" "unknown request" list ruleset || bad=1
    helper_refuses "no request" "missing request" || bad=1
    helper_refuses "check with a file argument" "check takes 0 arguments" check -f "$WORK/helper-secret" || bad=1
    helper_refuses "apply to another state dir" "the state directory must be" \
        apply /tmp/drfw-e2e-state 5 "$nonce" "$RT_DIR" "$nft_arg" auto "$uid" || bad=1
    helper_refuses "apply with a bad nonce" "invalid nonce" \
        apply "$GUARD_DIR" 5 "../../etc/passwd" "$RT_DIR" "$nft_arg" auto "$uid" || bad=1
    helper_refuses "apply for another uid" "the uid must be the caller's" \
        apply "$GUARD_DIR" 5 "$nonce" "$RT_DIR" "$nft_arg" auto 0 || bad=1
    helper_refuses "apply with another nft" "nft must be" \
        apply "$GUARD_DIR" 5 "$nonce" "$RT_DIR" /bin/true auto "$uid" || bad=1
    helper_refuses "save-config to /etc/passwd" "the target must be" \
        save-config /etc/passwd "$nft_arg" "" || bad=1
    helper_refuses "save-config enabling another service" "the service must be" \
        save-config "$NFT_CONF" "$nft_arg" sshd.service || bad=1
    printf 'include "%s"\n' "$WORK/helper-secret" >"$WORK/helper-payload"
    helper_refuses "check of an include payload" "include statement" check || bad=1
    helper_refuses "apply of an include payload" "include statement" \
        apply "$GUARD_DIR" 0 "$nonce" "$RT_DIR" "$nft_arg" auto "$uid" || bad=1
    out=$(nft -j -c -f - <"$WORK/helper-payload" 2>&1)
    check "(control: plain root nft -j -c follows the include and prints the secret)" \
        eval 'grep -qF -- "$SECRET" <<<"$out"' || bad=1
    after=$(drfw_table_dump)
    check "the refusals changed no rules ($(dump_digest "$before") = $(dump_digest "$after"))" \
        test "$before" = "$after" || bad=1
    check "the refusals left /etc/passwd alone" test "$(file_digest /etc/passwd)" = "$h_passwd" || bad=1
    rm -f -- "$WORK/helper-secret" "$WORK/helper-payload"

    # 11c: DRFW elevates the helper, never /bin/sh or nft (sudo log)
    reset_state
    sudo_log_reset
    tag=s11-apply
    apply_now "$(log_file "$tag")" sudo e2e-a
    rc=$?
    cmds=$(sudo_log_commands)
    evidence "info: sudo log: $(tr '\n' ' ' <<<"$cmds")"
    check "sudo: drfw apply exits 0 and e2e-A is live (exit $rc)" \
        eval '[ "$rc" -eq 0 ] && drfw_table_has_rule e2e-A' || {
        bad=1
        evidence_tail "$(cat -- "$(log_file "$tag")")"
    }
    helper_n=$(awk -v h="$HELPER_PATH" '$2 == h {n += $1} END {print n + 0}' <<<"$cmds")
    sh_n=$(awk '$2 ~ /\/sh$/ {n += $1} END {print n + 0}' <<<"$cmds")
    nft_n=$(awk '$2 ~ /\/nft$/ {n += $1} END {print n + 0}' <<<"$cmds")
    check "sudo elevated only the helper ($helper_n x helper, $sh_n x sh, $nft_n x nft)" \
        eval '[ "$helper_n" -ge 1 ] && [ "$sh_n" -eq 0 ] && [ "$nft_n" -eq 0 ]' || bad=1
    if [ "$GUARD_METHOD" = sudo ]; then
        evidence "guard timeout through the helper (systemd watcher, revert on time):"
        guard_timeout_case s11-guard e2e-A || bad=1
    fi
    if [ -n "$E2E_BIN" ]; then
        sudo_log_reset
        save_as sudo e2e_save_profile e2e-a "$(log_file s11-save)"
        rc=$?
        cmds=$(sudo_log_commands)
        check "Save to System through the helper (exit $rc; sudo log: $(tr '\n' ' ' <<<"$cmds"))" \
            eval '[ "$rc" -eq 0 ] && grep -qF -- "$HELPER_PATH" <<<"$cmds" && ! grep -Eq "/sh$" <<<"$cmds"' || {
            bad=1
            evidence_tail "$(cat -- "$(log_file s11-save)")" 10
        }
    fi

    # 11d: one password for two GUI applies from one process (auth_admin_keep)
    if [ -z "$E2E_BIN" ] || ! have_pkexec || ! have_cmd pkttyagent || ! have_cmd chpasswd; then
        evidence "skip: prompt count (needs the e2e binary, pkexec + polkit, pkttyagent, chpasswd)"
    else
        HELPER_PW="e2e-$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
        printf '%s:%s\n' "$TEST_USER" "$HELPER_PW" | chpasswd || bad=1
        reset_state
        n=$(prompt_session s11-prompt-a e2e-a,e2e-b)
        out=$(pty_out s11-prompt-a)
        check "two applies from one process: both applied, e2e-B live" \
            eval 'grep -q "E2E applied=e2e-a result=ok" <<<"$out" && grep -q "E2E applied=e2e-b result=ok" <<<"$out" && drfw_table_has_rule e2e-B' || {
            bad=1
            evidence_tail "$out" 12
        }
        check "the polkit agent asked for a password once for both ($n)" test "$n" -eq 1 || bad=1
        check "the dialog was for org.drfw.helper and said what it is for" \
            eval 'grep -q "AUTHENTICATING FOR org.drfw.helper" <<<"$out" && grep -qF "Authentication is required to change the firewall rules" <<<"$out"' || bad=1
        n=$(prompt_session s11-prompt-b e2e-c)
        out=$(pty_out s11-prompt-b)
        check "a new process asks again ($n prompt(s)), e2e-C live" \
            eval '[ "$n" -eq 1 ] && grep -q "E2E applied=e2e-c result=ok" <<<"$out" && drfw_table_has_rule e2e-C' || {
            bad=1
            evidence_tail "$out" 12
        }
        passwd -l "$TEST_USER" >/dev/null 2>&1
    fi

    reset_state
    helper_uninstall || bad=1
    check "helper and action removed again (unless they were installed before the run)" \
        eval '[ ! -e "$HELPER_STATE" ]' || bad=1
    verdict "$name" "$bad"
}

# ----------------------------------------------------------------------------
# Scenario 10: Server Mode over the network
# ----------------------------------------------------------------------------

scenario_10() {
    local name="10 Server Mode: established inbound TCP and loopback keep working" bad=0 dir log rc i res
    say "--- $name"
    if ! have_echo_tool || ! have_cmd ip; then
        skip "$name" "needs ip (iproute2) and socat or python3"
        return
    fi
    reset_state
    if ! net_setup; then
        evidence "FAIL: cannot create the peer namespace / veth pair"
        net_teardown
        verdict "$name" 1
        return
    fi
    evidence "info: peer netns $PEER_NS ($IP_B) <-> this host ($IP_A on $VETH_A)"
    evidence "info: nftables tables present: $(nft list tables 2>/dev/null | tr '\n' ' ')"
    dir=$WORK/net
    rm -rf -- "${dir:?}"
    mkdir -p -- "$dir"

    if ! echo_start "$IP_A" "$ECHO_PORT" || ! echo_start 127.0.0.1 "$LO_PORT"; then
        evidence "FAIL: cannot start the echo servers"
        net_teardown
        echo_stop_all
        verdict "$name" 1
        return
    fi
    check "control: a new connection from the peer works without a firewall" \
        echo_once "$IP_A" "$ECHO_PORT" "$PEER_NS" || bad=1

    # A long-lived session from the peer, opened before the firewall
    ip netns exec "$PEER_NS" bash -c '
        exec 3<>"/dev/tcp/$1/$2" || { echo connect=failed >>"$3/result"; exit 1; }
        printf "before\n" >&3
        IFS= read -r -t 3 l <&3; echo "before=$l" >>"$3/result"
        for i in $(seq 300); do [ -e "$3/go" ] && break; sleep 0.1; done
        printf "after\n" >&3
        IFS= read -r -t 5 l <&3; echo "after=$l" >>"$3/result"
        for i in $(seq 300); do [ -e "$3/done" ] && break; sleep 0.1; done
    ' e2e "$IP_A" "$ECHO_PORT" "$dir" &
    CLIENT_PID=$!
    for i in $(seq 50); do
        grep -q '^before=' "$dir/result" 2>/dev/null && break
        sleep 0.1
        : "$i"
    done
    check "session established before the apply ($(tr '\n' ' ' <"$dir/result" 2>/dev/null))" \
        grep -qx 'before=before' "$dir/result" || bad=1

    log=$(log_file s10-apply)
    apply_now "$log" sudo e2e-srv
    rc=$?
    check "drfw apply e2e-srv (Server Mode) --no-confirm --yes exits 0 ($rc)" test "$rc" -eq 0 || {
        bad=1
        evidence_tail "$(cat -- "$log")"
    }
    check "output chain policy is drop" \
        eval 'nft list chain inet drfw output 2>/dev/null | grep -q "policy drop"' || bad=1

    touch -- "$dir/go"
    for i in $(seq 80); do
        grep -q '^after=' "$dir/result" 2>/dev/null && break
        sleep 0.1
        : "$i"
    done
    res=$(tr '\n' ' ' <"$dir/result" 2>/dev/null)
    check "the established session still echoes after the apply ($res)" \
        grep -qx 'after=after' "$dir/result" || bad=1
    check "a NEW inbound connection to port $ECHO_PORT is blocked (no rule for it)" \
        eval '! echo_once "$IP_A" "$ECHO_PORT" "$PEER_NS"' || bad=1
    check "loopback TCP works in Server Mode" echo_once 127.0.0.1 "$LO_PORT" || bad=1
    touch -- "$dir/done"
    wait "$CLIENT_PID" 2>/dev/null
    CLIENT_PID=

    reset_state
    net_teardown
    echo_stop_all
    verdict "$name" "$bad"
}

# ----------------------------------------------------------------------------
# Scenario 9: boot persistence (two phases around a reboot)
# ----------------------------------------------------------------------------

boot_id() { cat /proc/sys/kernel/random/boot_id 2>/dev/null; }

phase_boot_prep() {
    local name="9 boot persistence: prepare" bad=0 data log rc
    say "--- $name"
    systemctl cat -- "$SERVICE" >/dev/null 2>&1 || {
        fail "$name" "service $SERVICE not found (install nftables)"
        return
    }
    install -d -m 700 -- "$BOOT_DIR"
    backup_system "$BOOT_DIR/backup" || {
        fail "$name" "cannot back up the system state"
        return
    }
    data=$BOOT_DIR/data
    rm -rf -- "${data:?}"
    write_profiles "$data"
    log=$(log_file boot-prep-save)
    if [ -n "$E2E_BIN" ]; then
        # As root: Save to System's script without elevation, with the real nft
        env DRFW_E2E_DISPOSABLE=1 DRFW_TEST_DATA_DIR="$data" DRFW_TEST_STATE_DIR="$BOOT_DIR/state" \
            DRFW_E2E_SAVE_PROFILE=e2e-b DRFW_E2E_SAVE_TARGET="$NFT_CONF" \
            "$E2E_BIN" --ignored --exact e2e_save_profile --nocapture --test-threads=1 >"$log" 2>&1
        rc=$?
        check "Save to System of e2e-b into $NFT_CONF (exit $rc)" test "$rc" -eq 0 || bad=1
    else
        evidence "info: no e2e test binary; writing 'drfw export e2e-b' instead of Save to System"
        DRFW_TEST_DATA_DIR="$data" DRFW_TEST_STATE_DIR="$BOOT_DIR/state" \
            "$DRFW" export e2e-b --format nft >"$BOOT_DIR/export.nft" 2>"$log" &&
            nft -c -f "$BOOT_DIR/export.nft" &&
            install -m 0644 -- "$BOOT_DIR/export.nft" "$NFT_CONF"
        rc=$?
        check "export of e2e-b installed as $NFT_CONF (exit $rc)" test "$rc" -eq 0 || bad=1
    fi
    [ "$rc" -eq 0 ] || evidence_tail "$(cat -- "$log")" 10
    # The table the file produces, loaded in a throwaway network namespace
    unshare -n sh -c 'nft -f "$1" && nft list table inet drfw' e2e "$NFT_CONF" 2>&1 |
        sed -E 's/counter packets [0-9]+ bytes [0-9]+/counter/g' >"$BOOT_DIR/expected.nft"
    check "expected table recorded ($(dump_digest "$(cat "$BOOT_DIR/expected.nft")"))" \
        grep -qF 'comment "e2e-B"' "$BOOT_DIR/expected.nft" || bad=1
    boot_id >"$BOOT_DIR/boot_id"
    systemctl enable --quiet -- "$SERVICE"
    check "$SERVICE enabled ($(systemctl is-enabled -- "$SERVICE" 2>&1))" \
        test "$(systemctl is-enabled -- "$SERVICE" 2>/dev/null)" = enabled || bad=1
    # The live table must come from the boot, not from this session
    drfw_table_delete
    verdict "$name" "$bad"
    say ""
    say "Next: reboot this machine/container, then run"
    say "  DRFW_E2E_DISPOSABLE=1 $SELF --phase boot-check"
    say "(nspawn: tools/e2e/nspawn.sh boot-check does both). The original"
    say "$NFT_CONF and $SERVICE state stay in $BOOT_DIR/backup until then."
}

phase_boot_check() {
    local name="9 boot persistence: check after reboot" bad=0 actual expected state
    say "--- $name"
    if [ ! -f "$BOOT_DIR/expected.nft" ]; then
        fail "$name" "no $BOOT_DIR/expected.nft: run --phase boot-prep first"
        return
    fi
    expected=$(cat -- "$BOOT_DIR/expected.nft")
    check "the machine rebooted since boot-prep (boot id $(boot_id | cut -c1-8) != $(cut -c1-8 "$BOOT_DIR/boot_id"))" \
        test "$(boot_id)" != "$(cat -- "$BOOT_DIR/boot_id")" || bad=1
    check "$SERVICE is enabled" test "$(systemctl is-enabled -- "$SERVICE" 2>/dev/null)" = enabled || bad=1
    state=$(systemctl show -p ActiveState -p Result --value -- "$SERVICE" | tr '\n' ' ')
    check "$SERVICE ran at boot and succeeded ($state)" \
        eval 'systemctl show -p Result --value -- "$SERVICE" | grep -qx success && systemctl is-active --quiet -- "$SERVICE"' || bad=1
    actual=$(drfw_table_dump)
    check "the live inet drfw table equals the recorded one ($(dump_digest "$actual") = $(dump_digest "$expected"))" \
        test "$actual" = "$expected" || {
        bad=1
        diff <(printf '%s\n' "$expected") <(printf '%s\n' "$actual") | head -n 20 >"$(log_file boot-diff)"
        evidence "  diff in $(log_file boot-diff)"
    }
    check "rule e2e-B is live" drfw_table_has_rule e2e-B || bad=1
    verdict "$name" "$bad"

    say ""
    say "Restoring the state saved by boot-prep..."
    if restore_system "$BOOT_DIR/backup" table; then
        rm -rf -- "${BOOT_DIR:?}"
        note "restored $NFT_CONF and the enablement of $SERVICE (the service was not stopped)"
    else
        fail "9 restore after boot-check" "kept in $BOOT_DIR/backup"
    fi
}

# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------

install -d -m 755 -- "$WORK" "$LOG_DIR" || die "cannot create $WORK"
case $PHASE in
    all)
        setup_env || die "setup failed"
        for s in $SCENARIOS; do
            case $s in
                9) skip "9 boot persistence" "two-phase: run --phase boot-prep, reboot, then --phase boot-check" ;;
                *) "scenario_$s" ;;
            esac
            say ""
        done
        ;;
    boot-prep)
        phase_boot_prep
        ;;
    boot-check)
        phase_boot_check
        ;;
esac

say ""
say "Summary:"
for r in "${E2E_RESULTS[@]}"; do
    say "  $r"
done
say "  $E2E_PASS passed, $E2E_FAIL failed, $E2E_SKIP skipped"
if [ "$E2E_FAIL" -gt 0 ] || { [ "$STRICT" = 1 ] && [ "$E2E_SKIP" -gt 0 ]; }; then
    exit 1
fi
exit 0
