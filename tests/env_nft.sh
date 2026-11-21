#!/bin/sh
# Stand-in for nft in tests/helper.rs: prints what the root helper passed on
# (arguments, working directory, environment, stdin), so the test can check
# that the child got nothing but the fixed PATH.
printf 'args=%s\n' "$*"
printf 'pwd=%s\n' "$(pwd)"
env | LC_ALL=C sort | sed 's/^/env=/'
printf 'stdin='
cat
