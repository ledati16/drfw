#!/bin/bash
# Mock nft command for testing
# This script simulates nftables behavior for CI/testing without requiring root privileges.
# It only accepts input shaped like what DRFW sends (it does not check nft
# semantics: real verification is tested against the real nft in
# tests/verify_errors.rs and tests/real_nft.rs). Needs jq.

# True if stdin is an nftables JSON command list as DRFW generates it: a
# non-empty `nftables` array of objects with a single add/delete/flush key.
is_drfw_json() {
    jq -e '
        (.nftables | type == "array" and length > 0)
        and all(.nftables[];
            type == "object" and length == 1
            and (keys[0] | IN("add", "delete", "flush")))
    ' > /dev/null 2>&1
}

# True if stdin is a revert batch (APPLY_SCRIPT's revert file, or the
# watcher's last resort): it starts by adding and deleting the drfw table.
is_revert_batch() {
    [ "$(head -n 2)" = "$(printf 'add table inet drfw\ndelete table inet drfw')" ]
}

# Handle different nft commands
case "$1" in
    --version)
        echo "nftables v1.0.0 (mock)"
        exit 0
        ;;

    --json)
        if [ "$2" = "--check" ] && [ "$3" = "-f" ] && [ "$4" = "-" ]; then
            # Verification mode
            if is_drfw_json; then
                exit 0
            fi
            echo "Error: Invalid nftables JSON (mock)" >&2
            exit 1
        elif [ "$2" = "-f" ] && [ "$3" = "-" ]; then
            # Apply mode - validate and pretend to apply
            if ! is_drfw_json; then
                echo "Error: Invalid nftables JSON (mock)" >&2
                exit 1
            fi
            # Guard tests: the apply script is killed (SIGKILL) right after
            # the rules went live. Kills the outermost `drfw-apply` shell (a
            # command substitution may run in a forked copy of it).
            if [ -n "${DRFW_GUARD_STATE_DIR-}" ] && [ -e "$DRFW_GUARD_STATE_DIR/mock-kill-apply" ]; then
                rm -f "$DRFW_GUARD_STATE_DIR/mock-kill-apply"
                pid=$PPID
                while parent=$(awk '{print $4}' "/proc/$pid/stat") \
                        && grep -qa drfw-apply "/proc/$parent/cmdline" 2>/dev/null; do
                    pid=$parent
                done
                kill -KILL "$pid"
            fi
            exit 0
        fi
        ;;

    list)
        # Guarded apply (APPLY_SCRIPT): `nft list tables` / `nft list table inet drfw`.
        # The mock kernel is always empty.
        if [ "$2" = "tables" ]; then
            exit 0
        fi
        echo "Error: No such file or directory (mock)" >&2
        exit 1
        ;;

    -f)
        # Revert batch from the guard's watcher: `nft -f FILE` or `nft -f -`
        if [ "$2" = "-" ]; then
            if is_revert_batch; then
                exit 0
            fi
        elif [ -r "$2" ]; then
            if is_revert_batch < "$2"; then
                exit 0
            fi
        fi
        echo "Error: not a drfw revert batch (mock)" >&2
        exit 1
        ;;

    -c|--check)
        # Text file syntax check (Save to System): `nft -c -f FILE`.
        # Accepts any readable file whose first line is the DRFW shebang. The
        # nft path in it is the compile-time DRFW_NFT_PATH (default
        # /usr/sbin/nft; packagers set e.g. /usr/bin/nft), so accept any path.
        if [ "$2" = "-f" ] && [ -r "$3" ]; then
            if head -n 1 "$3" | grep -qE '^#!/[^ ]*/nft -f$'; then
                exit 0
            fi
            echo "Error: syntax error (mock)" >&2
            exit 1
        fi
        ;;
esac

# Unknown command
echo "Error: Unsupported mock nft command: $*" >&2
exit 1
