#!/usr/bin/env bash
# Checks that the x86_64 binaries in $1 run on the first x86-64 level (SSE2; no SSE4, no
# AVX): both start on an emulated CPU of that level, the panel up to serving its page. A
# build whose C parts (mimalloc, SQLite) took AVX2 from the compiler's default stops here
# with "Illegal instruction", as it would on an older server.
set -euo pipefail
bin=${1:?usage: check-baseline.sh <dir with wormhole and wormhole-panel>}
command -v qemu-x86_64 >/dev/null || sudo apt-get install -y qemu-user >/dev/null
run() { qemu-x86_64 -cpu qemu64 "$@"; }
run "$bin/wormhole" --version
run "$bin/wormhole-panel" --version
dir=$(mktemp -d)
printf 'listen = "127.0.0.1:47777"\npath = "w-12345678"\ndata_dir = "%s"\n' "$dir" >"$dir/panel.toml"
status=0
timeout 15 qemu-x86_64 -cpu qemu64 "$bin/wormhole-panel" serve -c "$dir/panel.toml" >"$dir/log" 2>&1 || status=$?
if [ "$status" != 124 ]; then
    cat "$dir/log" >&2
    echo "the panel stopped with status $status on the baseline CPU" >&2
    exit 1
fi
echo "both run on the x86-64 baseline"
