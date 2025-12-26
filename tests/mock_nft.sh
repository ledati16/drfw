#!/bin/bash
# Mock nft command for testing
# This script simulates nftables behavior for CI/testing without requiring root privileges

# Store last input for inspection
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

            # Basic JSON validation
            if echo "$input" | jq . > /dev/null 2>&1; then
                # Check for required nftables structure
                if echo "$input" | jq -e '.nftables' > /dev/null 2>&1; then
                    # Simulate permission check (fail if MOCK_NFT_FAIL_PERMS is set)
                    if [ -n "$MOCK_NFT_FAIL_PERMS" ]; then
                        echo "Error: Operation not permitted" >&2
                        exit 1
                    fi
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

            # Simulate permission check
            if [ -n "$MOCK_NFT_FAIL_PERMS" ]; then
                echo "Error: Operation not permitted" >&2
                exit 1
            fi

            # Simulate apply failure if requested
            if [ -n "$MOCK_NFT_FAIL_APPLY" ]; then
                echo "Error: Could not process rule" >&2
                exit 1
            fi

            exit 0
        fi
        ;;
esac

# Unknown command
echo "Error: Unsupported mock nft command: $*" >&2
exit 1
