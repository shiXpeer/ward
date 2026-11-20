#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# Use the production decoder and archive; no network or real account state.
sed 's/@main struct WardApp: App/struct WardApp: App/' apps/macos/Ward.swift > "$tmp/Ward.swift"
swiftc -parse-as-library -target "$(uname -m)-apple-macos14.0" \
    "$tmp/Ward.swift" apps/macos/ServerReports.swift apps/macos/ServerEnrollment.swift apps/macos/NativeInstallerUpdates.swift apps/macos/ServerReportsTests.swift -o "$tmp/server-tests"
"$tmp/server-tests"
