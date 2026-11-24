#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/../.."
version="${1:?Usage: publish.sh VERSION BUILD ARCH}"
build="${2:?BUILD required}"
arch="${3:?ARCH required}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && "$build" =~ ^[1-9][0-9]*$ ]] || exit 1
[[ "$arch" == arm64 || "$arch" == x86_64 ]] || exit 1
out="$PWD/dist/releases/$version-$arch"
dmg="$out/Ward-$version-$arch.dmg"
xcrun stapler validate "$dmg"
# Verify a complete release before touching GitHub or the public feed.
(cd "$out" && shasum -a 256 -c SHA256SUMS)
signature="$(dist/sparkle-2.10.1/bin/sign_update --account com.shixpeer.ward -p "$dmg")"
dist/sparkle-2.10.1/bin/sign_update --account com.shixpeer.ward --verify "$dmg" "$signature"
if ! gh release view "v$version" --repo shiXpeer/ward >/dev/null 2>&1; then
  gh release create "v$version" --repo shiXpeer/ward --draft --title "Ward $version" --notes "macOS $version"
fi
gh release upload "v$version" "$dmg" "$out/SHA256SUMS#SHA256SUMS-$arch" --repo shiXpeer/ward
echo 'Uploaded to GitHub draft. Publish the release, then deploy its appcast using docs/macos-distribution.md.'
