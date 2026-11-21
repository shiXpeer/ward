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
fixture="$tmp/Lifecycle Fixture.app"
mkdir -p "$fixture/Contents/MacOS"
cat > "$tmp/LifecycleFixture.swift" <<'SWIFT'
import AppKit
let app = NSApplication.shared
app.setActivationPolicy(.prohibited)
app.run()
SWIFT
cat > "$fixture/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>org.example.ward.lifecycle-fixture</string>
<key>CFBundleExecutable</key><string>LifecycleFixture</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>1.0</string>
<key>LSUIElement</key><true/>
</dict></plist>
PLIST
swiftc "$tmp/LifecycleFixture.swift" -o "$fixture/Contents/MacOS/LifecycleFixture"
codesign --force --sign - "$fixture" >/dev/null 2>&1
WARD_TEST_LIFECYCLE_APP="$fixture" "$tmp/app-tests"
