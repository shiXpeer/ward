#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
app="$PWD/dist/macos/Shixpeer Ward.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp apps/macos/Info.plist "$app/Contents/Info.plist"
icon_tmp="$(mktemp -d)"
trap 'rm -rf "$icon_tmp"' EXIT
iconset="$icon_tmp/Ward.iconset"
mkdir "$iconset"
for size in 16 32 128 256 512; do
    retina=$((size * 2))
    sips -z "$size" "$size" apps/macos/WardIcon.png --out "$iconset/icon_${size}x${size}.png" >/dev/null
    sips -z "$retina" "$retina" apps/macos/WardIcon.png --out "$iconset/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$iconset" -o "$app/Contents/Resources/WardMatte.icns"
arch="$(uname -m)"
case "$arch" in arm64) goarch=arm64;; x86_64) goarch=amd64;; *) exit 1;; esac
CGO_ENABLED=0 GOOS=darwin GOARCH="$goarch" go build -trimpath -o "$app/Contents/MacOS/shixpeer-ward-agent" ./cmd/shixpeer-ward-agent
swiftc -parse-as-library -O -target "$arch-apple-macos14.0" apps/macos/Ward.swift -o "$app/Contents/MacOS/Ward"
codesign --force --sign - "$app/Contents/MacOS/shixpeer-ward-agent"
codesign --force --sign - "$app"
codesign --verify --deep --strict "$app"
printf '%s\n' "$app"
