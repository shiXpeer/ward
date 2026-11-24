#!/bin/sh
set -eu
umask 077
if [ -f /signing/signing.key ]; then
    test -s /tls/server.key && test -s /tls/server.crt && test -s /trust/ca.crt && test -s /public/feed.pub
    exit 0
fi
# Never replace a partially provisioned identity silently.
test -z "$(ls -A /signing)" && test -z "$(ls -A /tls)"
shixpeer-ward-beacon init -pki /tmp/ward-identity -hosts ward-api,ward-publisher,localhost,127.0.0.1
cp /tmp/ward-identity/signing.key /signing/signing.key
cp /tmp/ward-identity/feed.pub /public/feed.pub
cp /tmp/ward-identity/server.key /tls/server.key
cp /tmp/ward-identity/server.crt /tls/server.crt
cp /tmp/ward-identity/ca.crt /trust/ca.crt
chmod 644 /public/feed.pub /trust/ca.crt /tls/server.crt
