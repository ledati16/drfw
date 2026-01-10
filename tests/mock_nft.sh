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
            exit 0
        fi
        ;;
esac

# Unknown command
echo "Error: Unsupported mock nft command: $*" >&2
exit 1
