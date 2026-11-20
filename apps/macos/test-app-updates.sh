#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
sed 's/@main struct WardApp: App/struct WardApp: App/' apps/macos/Ward.swift > "$tmp/Ward.swift"
# Append in the same file to exercise the production private update record policy.
cat apps/macos/AppUpdatesTests.swift >> "$tmp/Ward.swift"
swiftc -parse-as-library -target "$(uname -m)-apple-macos14.0" "$tmp/Ward.swift" \
    apps/macos/ServerReports.swift apps/macos/ServerEnrollment.swift apps/macos/NativeInstallerUpdates.swift -o "$tmp/app-tests"
"$tmp/app-tests"
