#!/bin/bash
# Release artifacts are never published until Apple notarization succeeds.
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${WARD_SIGN_IDENTITY:?Set WARD_SIGN_IDENTITY to your Developer ID Application identity}"
: "${WARD_NOTARY_PROFILE:?Set WARD_NOTARY_PROFILE to a notarytool Keychain profile}"
version="${1:?Usage: release.sh VERSION BUILD [arm64|x86_64]}"
build="${2:?A monotonically increasing build number is required}"
arch="${3:-arm64}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && "$build" =~ ^[1-9][0-9]*$ ]] || { echo 'Invalid version or build number' >&2; exit 1; }
[[ "$arch" == arm64 || "$arch" == x86_64 ]] || exit 1
[[ "$WARD_SIGN_IDENTITY" == 'Developer ID Application:'* ]] || { echo 'Developer ID Application is required' >&2; exit 1; }
security find-identity -v -p codesigning | grep -F -- "\"$WARD_SIGN_IDENTITY\"" >/dev/null || { echo 'Signing identity with private key not found' >&2; exit 1; }
# Fail before compiling if the local notarization profile is missing or invalid.
xcrun notarytool history --keychain-profile "$WARD_NOTARY_PROFILE" >/dev/null
export WARD_VERSION="$version" WARD_BUILD="$build" WARD_ARCH="$arch" WARD_SPARKLE=1
bash apps/macos/build.sh
app="$PWD/dist/macos/Shixpeer Ward.app"
out="$PWD/dist/releases/$version-$arch"
mkdir -p "$out"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
ditto -c -k --keepParent "$app" "$tmp/notarize.zip"
xcrun notarytool submit "$tmp/notarize.zip" --keychain-profile "$WARD_NOTARY_PROFILE" --wait
xcrun stapler staple "$app"
xcrun stapler validate "$app"
spctl --assess --type execute --verbose=2 "$app"
mkdir "$tmp/image"
ditto "$app" "$tmp/image/Shixpeer Ward.app"
ln -s /Applications "$tmp/image/Applications"
dmg="$out/Ward-$version-$arch.dmg"
hdiutil create -quiet -volname 'Shixpeer Ward' -srcfolder "$tmp/image" -format UDZO "$dmg"
codesign --force --timestamp --sign "$WARD_SIGN_IDENTITY" "$dmg"
xcrun notarytool submit "$dmg" --keychain-profile "$WARD_NOTARY_PROFILE" --wait
xcrun stapler staple "$dmg"
xcrun stapler validate "$dmg"
# Sparkle signatures cover the final, stapled DMG bytes.
dist/sparkle-2.10.1/bin/sign_update --account com.shixpeer.ward "$dmg" > "$out/sparkle-signature.txt"
(cd "$out" && shasum -a 256 *.dmg > SHA256SUMS)
echo "READY: $out (notarized; publish explicitly with publish.sh)"
