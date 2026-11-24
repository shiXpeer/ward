#!/bin/bash
# Scope the metadata mirror to Homebrew processes launched by Ward. Rewrite
# Homebrew's fallback URL too; a failed Ward backend never bypasses this route.
set -euo pipefail
args=()
for arg in "$@"; do
    case "$arg" in
        https://formulae.brew.sh/api/*) arg="https://ward.shixpeer.com/v1/homebrew/${arg#https://formulae.brew.sh/api/}";;
    esac
    args+=("$arg")
done
exec /usr/bin/curl "${args[@]}"
