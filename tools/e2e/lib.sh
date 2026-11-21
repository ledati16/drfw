# shellcheck shell=bash
# The bash -c bodies are single-quoted on purpose (SC2016); PTY_RC and
# friends are read by run.sh (SC2034).
# shellcheck disable=SC2016,SC2034
# Helpers for tools/e2e/run.sh (sourced, never executed on its own).
#
# Everything here that changes the system is only ever called by run.sh after
# its safety checks passed and it is running as root inside a disposable
# container or VM. Nothing here touches any nftables table other than
# `inet drfw`.

# ----------------------------------------------------------------------------
# Results
# ----------------------------------------------------------------------------

E2E_PASS=0
E2E_FAIL=0
E2E_SKIP=0
E2E_RESULTS=()
# Evidence lines collected for the scenario that is running
E2E_EVIDENCE=()

say() { printf '%s\n' "$*"; }
note() { printf '    %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
die() {
    printf 'e2e: %s\n' "$*" >&2
    exit 2
}

# evidence TEXT: remember a line printed under the scenario's verdict
evidence() { E2E_EVIDENCE+=("$*"); }

_flush_evidence() {
    local line
    for line in "${E2E_EVIDENCE[@]}"; do
        printf '      | %s\n' "$line"
    done
    E2E_EVIDENCE=()
}

pass() {
    E2E_PASS=$((E2E_PASS + 1))
    E2E_RESULTS+=("PASS  $1")
    printf 'PASS  %s\n' "$1"
    _flush_evidence
}

fail() {
    E2E_FAIL=$((E2E_FAIL + 1))
    E2E_RESULTS+=("FAIL  $1${2:+: $2}")
    printf 'FAIL  %s%s\n' "$1" "${2:+: $2}"
    _flush_evidence
}

skip() {
    E2E_SKIP=$((E2E_SKIP + 1))
    E2E_RESULTS+=("SKIP  $1: $2")
    printf 'SKIP  %s: %s\n' "$1" "$2"
    _flush_evidence
}

# check WHAT COMMAND...: one sub-check; records "ok:"/"FAIL:" WHAT as
# evidence and returns the command's status
check() {
    local what=$1
    shift
    if "$@"; then
        evidence "ok:   $what"
        return 0
    fi
    evidence "FAIL: $what"
    return 1
}

# ----------------------------------------------------------------------------
# Time
# ----------------------------------------------------------------------------

# Milliseconds since the epoch (EPOCHREALTIME needs LC_ALL=C for the '.')
now_ms() {
    local t=${EPOCHREALTIME/./}
    printf '%s\n' "$((t / 1000))"
}

# ms_to_s MS: "8.214"
ms_to_s() { printf '%d.%03d' "$(($1 / 1000))" "$(($1 % 1000))"; }

# ----------------------------------------------------------------------------
# nftables (only ever `inet drfw`)
# ----------------------------------------------------------------------------

drfw_table_exists() {
    local tables
    tables=$(nft list tables 2>/dev/null) || return 1
    grep -qx 'table inet drfw' <<<"$tables"
}

# The `inet drfw` table with counter values removed (they change with
# traffic), or "<no inet drfw table>"
drfw_table_dump() {
    if ! drfw_table_exists; then
        printf '<no inet drfw table>\n'
        return 0
    fi
    nft list table inet drfw 2>&1 | sed -E 's/counter packets [0-9]+ bytes [0-9]+/counter/g'
}

# drfw_table_has_rule LABEL: the live table has a rule commented LABEL
drfw_table_has_rule() {
    local dump
    dump=$(drfw_table_dump)
    grep -qF "comment \"$1\"" <<<"$dump"
}

drfw_table_delete() {
    if drfw_table_exists; then
        nft delete table inet drfw
    fi
}

# Short fingerprint of a dump for evidence lines
dump_digest() { sha256sum <<<"$1" | cut -c1-12; }

file_digest() {
    if [ -e "$1" ]; then
        sha256sum -- "$1" | cut -c1-12
    else
        printf 'absent\n'
    fi
}

# ----------------------------------------------------------------------------
# Revert guard (state written by drfw's APPLY_SCRIPT / WATCHER_SCRIPT)
# ----------------------------------------------------------------------------

valid_nonce() {
    case $1 in
        *[!0-9a-f]* | '') return 1 ;;
    esac
    [ "${#1}" -eq 32 ]
}

# Prints "<nonce> <launcher>" from the guard's active file, or nothing
guard_active() {
    local nonce='' launcher=''
    [ -f "$GUARD_DIR/active" ] || return 0
    read -r nonce launcher _ <"$GUARD_DIR/active" 2>/dev/null || true
    valid_nonce "$nonce" || return 0
    printf '%s %s\n' "$nonce" "$launcher"
}

# wait_new_guard PREV_NONCE SECONDS: prints the nonce of a newly armed guard
# (active file naming a nonce other than PREV_NONCE)
wait_new_guard() {
    local prev=$1 give_up=$(($(now_ms) + $2 * 1000)) active nonce
    while [ "$(now_ms)" -lt "$give_up" ]; do
        active=$(guard_active)
        nonce=${active%% *}
        # A nonce with a status file is a finished guard, not a new one
        if [ -n "$nonce" ] && [ "$nonce" != "$prev" ] && [ ! -e "$GUARD_DIR/status-$nonce" ]; then
            printf '%s\n' "$nonce"
            return 0
        fi
        sleep 0.1
    done
    return 1
}

guard_launcher() {
    local active
    active=$(guard_active)
    [ "${active%% *}" = "$1" ] && printf '%s\n' "${active#* }"
}

# wait_status NONCE SECONDS: prints the first line of status-NONCE
wait_status() {
    local file="$GUARD_DIR/status-$1" give_up=$(($(now_ms) + $2 * 1000)) line
    while [ "$(now_ms)" -lt "$give_up" ]; do
        if [ -f "$file" ]; then
            IFS= read -r line <"$file" || true
            printf '%s\n' "$line"
            return 0
        fi
        sleep 0.1
    done
    return 1
}

read_status() {
    local line=
    [ -f "$GUARD_DIR/status-$1" ] || return 1
    IFS= read -r line <"$GUARD_DIR/status-$1" || true
    printf '%s\n' "$line"
}

# ActiveState of the watcher's transient unit ("active", "inactive", ...)
unit_state() {
    systemctl show -p ActiveState --value "drfw-revert-$1.service" 2>/dev/null
}

# wait_unit_gone NONCE SECONDS
wait_unit_gone() {
    local give_up=$(($(now_ms) + $2 * 1000)) state
    while [ "$(now_ms)" -lt "$give_up" ]; do
        state=$(unit_state "$1")
        case $state in
            active | activating | deactivating | reloading) ;;
            *) return 0 ;;
        esac
        sleep 0.2
    done
    return 1
}

# Finishes a guard left pending by an earlier scenario so the next apply does
# not inherit its revert file: asks its watcher to revert through the normal
# user-side token, and only if the watcher is gone cleans up by hand.
settle_guard() {
    local active nonce launcher
    active=$(guard_active)
    [ -n "$active" ] || return 0
    nonce=${active%% *}
    launcher=${active#* }
    [ -e "$GUARD_DIR/status-$nonce" ] && return 0
    if id -u "$TEST_USER" >/dev/null 2>&1 && [ -d "$RT_DIR" ]; then
        as_user touch -- "$RT_DIR/drfw-revert-$nonce" 2>/dev/null || true
    fi
    if ! wait_status "$nonce" 15 >/dev/null; then
        warn "guard $nonce ($launcher) did not answer; cleaning up by hand"
        systemctl stop "drfw-revert-$nonce.service" >/dev/null 2>&1 || true
        rm -f -- "$GUARD_DIR/active" "$GUARD_DIR/revert-$nonce.nft" "$GUARD_DIR/watcher-$nonce.sh"
    fi
    rm -f -- "$RT_DIR/drfw-revert-$nonce" "$RT_DIR/drfw-confirm-$nonce"
}

# Starting point of every guard scenario: no pending guard, no drfw table
reset_state() {
    settle_guard
    drfw_table_delete
}

# ----------------------------------------------------------------------------
# The unprivileged test user
# ----------------------------------------------------------------------------

# Environment of every command run as the test user. `DRFW_NFT_COMMAND` is
# never part of it: the real elevation and the real nft are the point.
user_env() {
    printf '%s\n' \
        "HOME=$USER_HOME" \
        "USER=$TEST_USER" \
        "LOGNAME=$TEST_USER" \
        "SHELL=/bin/bash" \
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
        "TERM=xterm-256color" \
        "LANG=C.UTF-8" \
        "NO_COLOR=1" \
        "XDG_RUNTIME_DIR=$RT_DIR" \
        "DRFW_TEST_DATA_DIR=$USER_DATA" \
        "DRFW_TEST_STATE_DIR=$USER_STATE"
}

# as_user [VAR=value...] COMMAND...: run as the test user with user_env
as_user() {
    local -a env_list
    mapfile -t env_list < <(user_env)
    runuser -u "$TEST_USER" -- env -i "${env_list[@]}" "$@"
}

# as_user_method METHOD COMMAND...: METHOD is sudo, pkexec, run0 or auto
as_user_method() {
    local method=$1
    shift
    if [ "$method" = auto ]; then
        as_user "$@"
    else
        as_user "DRFW_ELEVATION_METHOD=$method" "$@"
    fi
}

# Number of sudo invocations by the test user, by command, since the log was
# truncated: prints lines like "1 /bin/sh"
sudo_log_commands() {
    [ -f "$SUDO_LOG" ] || return 0
    grep -o 'COMMAND=[^ ]*' -- "$SUDO_LOG" | sed 's/^COMMAND=//' | sort | uniq -c | sed 's/^ *//'
}

sudo_log_reset() { : >"$SUDO_LOG"; }

# ----------------------------------------------------------------------------
# CLI in a pseudo-terminal (util-linux `script`), keys fed through a FIFO
# ----------------------------------------------------------------------------

declare -A PTY_FD=()
declare -A PTY_RUNNER=()

pty_dir() { printf '%s/pty-%s\n' "$PTY_ROOT" "$1"; }

# pty_start TAG METHOD COMMAND...: starts COMMAND as the test user inside a
# PTY. Keys are sent with pty_send; output goes to $(pty_dir TAG)/out.
pty_start() {
    local tag=$1 method=$2
    shift 2
    local dir inner fd
    local -a env_list
    mapfile -t env_list < <(user_env)
    [ "$method" = auto ] || env_list+=("DRFW_ELEVATION_METHOD=$method")
    dir=$(pty_dir "$tag")
    rm -rf -- "$dir"
    mkdir -p -- "$dir"
    chown "$TEST_USER:" "$dir"
    mkfifo -m 600 "$dir/in"
    # Held open read-write so the FIFO never reports EOF to `script`
    exec {fd}<>"$dir/in"
    PTY_FD[$tag]=$fd
    printf -v inner '%q ' "$@"
    # The shell that `script` starts writes its PID, then becomes the CLI.
    # runuser is started directly (not through a function) so that $! is its
    # PID and pty_wait can wait for it.
    runuser -u "$TEST_USER" -- env -i "${env_list[@]}" \
        script -qfec "echo \$\$ > $dir/pid; exec $inner" /dev/null \
        <"$dir/in" >"$dir/out" 2>&1 &
    PTY_RUNNER[$tag]=$!
}

# pty_cli_pid TAG: PID of the CLI itself (waits up to 10 s for it)
pty_cli_pid() {
    local file give_up pid
    file="$(pty_dir "$1")/pid"
    give_up=$(($(now_ms) + 10000))
    while [ "$(now_ms)" -lt "$give_up" ]; do
        if [ -s "$file" ]; then
            read -r pid <"$file"
            printf '%s\n' "$pid"
            return 0
        fi
        sleep 0.1
    done
    return 1
}

pty_send() {
    printf '%s' "$2" >&"${PTY_FD[$1]}"
}

pty_out() { cat -- "$(pty_dir "$1")/out" 2>/dev/null | tr -d '\r'; }

# pty_wait TAG SECONDS: waits for the PTY runner and sets PTY_RC to its
# exit status ("timeout" if it is still running). Must not run in a
# subshell (`$(...)`): only this shell can wait for its children.
PTY_RC=
pty_wait() {
    local tag=$1 pid=${PTY_RUNNER[$1]:-} give_up=$(($(now_ms) + $2 * 1000))
    PTY_RC=none
    [ -n "$pid" ] || return 1
    while kill -0 "$pid" 2>/dev/null; do
        if [ "$(now_ms)" -ge "$give_up" ]; then
            PTY_RC=timeout
            return 1
        fi
        sleep 0.1
    done
    wait "$pid"
    PTY_RC=$?
    pty_close "$tag"
}

pty_close() {
    local fd=${PTY_FD[$1]:-}
    if [ -n "$fd" ]; then
        exec {fd}>&-
        unset 'PTY_FD[$1]'
    fi
    unset 'PTY_RUNNER[$1]'
}

# Kills every PTY runner still alive (by PID) and closes the FIFOs
pty_cleanup() {
    local tag pid cli
    for tag in "${!PTY_RUNNER[@]}"; do
        pid=${PTY_RUNNER[$tag]}
        if [ -s "$(pty_dir "$tag")/pid" ]; then
            read -r cli <"$(pty_dir "$tag")/pid" || cli=
            [ -n "$cli" ] && kill -KILL "$cli" 2>/dev/null
        fi
        kill -KILL "$pid" 2>/dev/null
        wait "$pid" 2>/dev/null
        pty_close "$tag"
    done
}

# ----------------------------------------------------------------------------
# TCP echo servers and clients (no firewall changes of their own)
# ----------------------------------------------------------------------------

ECHO_PIDS=()

ECHO_PY='import socket, sys, threading
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2])))
s.listen(16)
def serve(c):
    with c:
        while True:
            d = c.recv(4096)
            if not d:
                return
            c.sendall(d)
while True:
    c, _ = s.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()'

have_echo_tool() { command -v socat >/dev/null 2>&1 || command -v python3 >/dev/null 2>&1; }

# echo_once ADDR PORT [NETNS]: one new connection, one line echoed back
echo_once() {
    local -a pre=()
    [ -n "${3:-}" ] && pre=(ip netns exec "$3")
    "${pre[@]}" timeout 4 bash -c '
        exec 3<>"/dev/tcp/$1/$2" || exit 1
        printf "e2e-ping\n" >&3
        IFS= read -r -t 3 line <&3 || exit 1
        [ "$line" = e2e-ping ]' e2e "$1" "$2" 2>/dev/null
}

# echo_start ADDR PORT [NETNS]: starts an echo server, waits until it answers
echo_start() {
    local -a pre=()
    [ -n "${3:-}" ] && pre=(ip netns exec "$3")
    if command -v socat >/dev/null 2>&1; then
        "${pre[@]}" socat "TCP-LISTEN:$2,bind=$1,reuseaddr,fork" EXEC:cat >/dev/null 2>&1 &
    else
        "${pre[@]}" python3 -c "$ECHO_PY" "$1" "$2" >/dev/null 2>&1 &
    fi
    ECHO_PIDS+=("$!")
    local i
    for i in $(seq 50); do
        echo_once "$1" "$2" "${3:-}" && return 0
        sleep 0.1
        : "$i"
    done
    return 1
}

echo_stop_all() {
    local pid
    for pid in "${ECHO_PIDS[@]}"; do
        kill "$pid" 2>/dev/null
        wait "$pid" 2>/dev/null
    done
    ECHO_PIDS=()
}

# ----------------------------------------------------------------------------
# Profiles (current on-disk format, see src/core/profiles.rs and
# src/core/firewall.rs: `version` plus the flattened FirewallRuleset)
# ----------------------------------------------------------------------------

# profile_json LABEL PORT EGRESS(Desktop|Server) ID_SUFFIX
profile_json() {
    cat <<EOF
{
  "version": 1,
  "rules": [
    {
      "id": "00000000-0000-4000-8000-0000000000$4",
      "label": "$1",
      "protocol": "Tcp",
      "ports": [$2],
      "sources": [],
      "interface": null,
      "output_interface": null,
      "chain": "Input",
      "enabled": true,
      "created_at": "2026-01-01T00:00:00Z",
      "tags": ["e2e"],
      "destinations": [],
      "action": "Accept",
      "reject_type": "Default",
      "rate_limit": null,
      "connection_limit": 0,
      "log_enabled": false
    }
  ],
  "advanced_security": {
    "strict_icmp": false,
    "icmp_rate_limit": 0,
    "enable_rpf": false,
    "log_dropped": false,
    "log_rate_per_minute": 5,
    "log_prefix": "DRFW-DROP: ",
    "egress_profile": "$3",
    "block_forwarding": false
  }
}
EOF
}

# write_profiles DIR: the kit's profiles in DIR/profiles/
#   e2e-a / e2e-b / e2e-c: Desktop mode, one input rule each (e2e-A/B/C)
#   e2e-srv: Server Mode (output policy drop), one rule for a port nobody uses
write_profiles() {
    local dir="$1/profiles"
    mkdir -p -- "$dir"
    profile_json e2e-A 40001 Desktop 0a >"$dir/e2e-a.json"
    profile_json e2e-B 40002 Desktop 0b >"$dir/e2e-b.json"
    profile_json e2e-C 40003 Desktop 0c >"$dir/e2e-c.json"
    profile_json e2e-srv 40022 Server 0d >"$dir/e2e-srv.json"
}
