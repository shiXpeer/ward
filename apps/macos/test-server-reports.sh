#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# Use the production decoder and archive; no network or real account state.
sed 's/@main struct WardApp: App/struct WardApp: App/' apps/macos/Ward.swift > "$tmp/Ward.swift"
swiftc -parse-as-library -target "$(uname -m)-apple-macos14.0" \
    "$tmp/Ward.swift" apps/macos/ServerReports.swift apps/macos/ServerEnrollment.swift apps/macos/NativeInstallerUpdates.swift apps/macos/MetadataBackend.swift apps/macos/ServerReportsTests.swift -o "$tmp/server-tests"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=relay.example.test \
    -sha256 -addext 'basicConstraints=critical,CA:FALSE' -addext 'keyUsage=critical,digitalSignature,keyEncipherment' -addext 'extendedKeyUsage=serverAuth' -addext 'subjectAltName=DNS:relay.example.test' -keyout "$tmp/key.pem" -out "$tmp/cert.pem" >/dev/null 2>&1
openssl x509 -in "$tmp/cert.pem" -outform der -out "$tmp/cert.der"
WARD_TEST_RELAY_CERT="$tmp/cert.der" "$tmp/server-tests"
