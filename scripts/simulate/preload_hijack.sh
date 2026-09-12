#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
make -s preload_lib.so
echo "[preload_hijack demo] running /bin/true with LD_PRELOAD=$(pwd)/preload_lib.so"
LD_PRELOAD="$(pwd)/preload_lib.so" /bin/true
