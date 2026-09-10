#!/usr/bin/env bash
# Lint the bash port and run the bats suites against both implementations.
#
#   test/run.sh          both ports
#   test/run.sh bash     one port
#
# Needs bats and (for the vault suites) keepassxc-cli; tests that need a tool
# that isn't installed report themselves as skipped rather than failing.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

if [ $# -eq 0 ]; then
    ports=(bash zsh)
else
    ports=("$@")
fi

status=0

# ShellCheck has no zsh dialect, so the zsh port is covered by the suites alone.
if command -v shellcheck >/dev/null 2>&1; then
    printf '== shellcheck\n'
    shellcheck -s bash skm.bash test/helper.bash test/run.sh || status=1
else
    printf '== shellcheck not installed, skipping lint\n'
fi

for port in "${ports[@]}"; do
    printf '\n== bats, %s port\n' "$port"
    SKM_PORT="$port" bats test || status=1
done

exit "$status"
