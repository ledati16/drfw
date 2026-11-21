#!/bin/bash
# Mock nft command for testing
# This script simulates nftables behavior for CI/testing without requiring root privileges

# Store last input for inspection (useful for debugging tests)
MOCK_NFT_DIR="${TMPDIR:-/tmp}/drfw_mock_nft_$$"
mkdir -p "$MOCK_NFT_DIR"

# Handle different nft commands
case "$1" in
    --version)
        echo "nftables v1.0.0 (mock)"
        exit 0
        ;;

    --json)
        if [ "$2" = "--check" ] && [ "$3" = "-f" ] && [ "$4" = "-" ]; then
            # Verification mode - read stdin and validate JSON structure
            input=$(cat)
            echo "$input" > "$MOCK_NFT_DIR/last_check.json"

            # Basic JSON validation using jq
            if echo "$input" | jq . > /dev/null 2>&1; then
                # Check for required nftables structure
                if echo "$input" | jq -e '.nftables' > /dev/null 2>&1; then
                    exit 0
                else
                    echo "Error: Invalid nftables JSON structure" >&2
                    exit 1
                fi
            else
                echo "Error: Invalid JSON" >&2
                exit 1
            fi
        elif [ "$2" = "-f" ] && [ "$3" = "-" ]; then
            # Apply mode - read stdin and pretend to apply
            input=$(cat)
            echo "$input" > "$MOCK_NFT_DIR/last_apply.json"
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
            cat > "$MOCK_NFT_DIR/last_revert.nft"
            exit 0
        elif [ -r "$2" ]; then
            cp "$2" "$MOCK_NFT_DIR/last_revert.nft"
            exit 0
        fi
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
