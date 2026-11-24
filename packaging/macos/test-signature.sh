#!/bin/bash
# Local fixture only; uses the existing Sparkle Keychain signing identity.
set -euo pipefail
cd "$(dirname "$0")/../.."
tool="$PWD/dist/sparkle-2.10.1/bin/sign_update"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
printf 'Ward local signing fixture\n' > "$tmp/archive.zip"
signature="$("$tool" --account com.shixpeer.ward -p "$tmp/archive.zip")"
"$tool" --account com.shixpeer.ward --verify "$tmp/archive.zip" "$signature"
printf 'tampered\n' >> "$tmp/archive.zip"
if "$tool" --account com.shixpeer.ward --verify "$tmp/archive.zip" "$signature" >/dev/null 2>&1; then
  echo 'FAIL: tampered archive accepted' >&2; exit 1
fi
echo 'PASS: signed fixture verifies; tampered archive rejected'
