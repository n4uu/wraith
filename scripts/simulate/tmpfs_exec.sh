#!/usr/bin/env bash
set -euo pipefail

target="$(mktemp /tmp/wraith-demo.XXXXXX)"
cleanup() { rm -f "$target"; }
trap cleanup EXIT

cp /bin/true "$target"
chmod +x "$target"
echo "[tmpfs_exec demo] executing $target"
"$target"
