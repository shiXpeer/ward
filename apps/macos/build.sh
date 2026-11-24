#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
app="$PWD/dist/macos/Shixpeer Ward.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp internal/distribution/install-agent.sh "$app/Contents/Resources/InstallAgent.sh"
cp apps/macos/BrewCurl.sh "$app/Contents/Resources/BrewCurl.sh"
chmod 755 "$app/Contents/Resources/BrewCurl.sh"
cp apps/macos/OfficialFeed.pub "$app/Contents/Resources/OfficialFeed.pub"
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
arch="${WARD_ARCH:-$(uname -m)}"
identity="${WARD_SIGN_IDENTITY:--}"
sparkle_flags=()
rm -rf "$app/Contents/Frameworks/Sparkle.framework"
if [[ "${WARD_SPARKLE:-0}" == 1 ]]; then
    bash packaging/macos/fetch-sparkle.sh
    cp dist/sparkle-2.10.1/LICENSE "$app/Contents/Resources/Sparkle-LICENSE"
    mkdir -p "$app/Contents/Frameworks"
    ditto dist/sparkle-2.10.1/Sparkle.framework "$app/Contents/Frameworks/Sparkle.framework"
    sparkle_flags=(-F "$app/Contents/Frameworks" -framework Sparkle -Xlinker -rpath -Xlinker @executable_path/../Frameworks)
fi
case "$arch" in arm64) goarch=arm64;; x86_64) goarch=amd64;; *) exit 1;; esac
CGO_ENABLED=0 GOOS=darwin GOARCH="$goarch" go build -trimpath -o "$app/Contents/MacOS/shixpeer-ward-agent" ./cmd/shixpeer-ward-agent
swiftc -parse-as-library -O -target "$arch-apple-macos14.0" apps/macos/Ward.swift apps/macos/ServerReports.swift apps/macos/ServerEnrollment.swift apps/macos/NativeInstallerUpdates.swift apps/macos/MetadataBackend.swift "${sparkle_flags[@]}" -o "$app/Contents/MacOS/Ward"
if [[ -n "${WARD_VERSION:-}" && -n "${WARD_BUILD:-}" ]]; then
    /usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $WARD_VERSION" "$app/Contents/Info.plist"
    /usr/libexec/PlistBuddy -c "Set :CFBundleVersion $WARD_BUILD" "$app/Contents/Info.plist"
fi
sign_flags=(--force --sign "$identity")
if [[ "$identity" != - ]]; then sign_flags+=(--options runtime --timestamp); fi
if [[ "${WARD_SPARKLE:-0}" == 1 ]]; then
    while IFS= read -r -d '' nested; do codesign "${sign_flags[@]}" "$nested"; done < <(find "$app/Contents/Frameworks" -depth \( -name '*.xpc' -o -name '*.app' -o -name '*.framework' -o -name Autoupdate \) -print0)
fi
if [[ "${WARD_SPARKLE:-0}" == 1 ]]; then
    /usr/libexec/PlistBuddy -c "Set :SUFeedURL https://ward.shixpeer.com/releases/appcast-$arch.xml" "$app/Contents/Info.plist"
fi
codesign "${sign_flags[@]}" "$app/Contents/MacOS/shixpeer-ward-agent"
codesign "${sign_flags[@]}" "$app"
codesign --verify --deep --strict "$app"
printf '%s\n' "$app"
