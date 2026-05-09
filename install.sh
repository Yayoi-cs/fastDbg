#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

missing=()
for tool in go clang make git setcap; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        missing+=("$tool")
    fi
done
if [ "${#missing[@]}" -gt 0 ]; then
    echo "[-] missing prerequisites: ${missing[*]}" >&2
    echo "    install with: sudo apt install build-essential golang clang libcap2-bin git" >&2
    exit 1
fi

if [ ! -d capstone/capstone ]; then
    mkdir -p capstone
    git clone --depth 1 https://github.com/capstone-engine/capstone.git capstone/capstone
fi

make

