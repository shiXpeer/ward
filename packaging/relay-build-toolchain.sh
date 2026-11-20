#!/usr/bin/env bash
# Sourced by relay setup. Keep bootstrap downloads pinned and outside system paths.
relay_go_suitable() {
    local version major minor patch
    command -v go >/dev/null 2>&1 || return 1
    version=$(GOTOOLCHAIN=local go version 2>/dev/null) || return 1
    [[ $version =~ go([0-9]+)\.([0-9]+)\.([0-9]+) ]] || return 1
    major=${BASH_REMATCH[1]} minor=${BASH_REMATCH[2]} patch=${BASH_REMATCH[3]}
    (( major > 1 || (major == 1 && (minor > 26 || (minor == 26 && patch >= 10))) ))
}
relay_go_archive() {
    case "$1" in
        x86_64) go_arch=amd64; go_digest=7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840;;
        aarch64|arm64) go_arch=arm64; go_digest=3392582988a273a87ab5043ee1b2c9c17a2c3c00580bf9326c47a2e0aaaeac92;;
        *) return 1;;
    esac
}
relay_prepare_go() {
    local scratch=$1 log=$2 go_arch go_digest archive
    if relay_go_suitable; then return 0; fi
    relay_go_archive "$(uname -m)" || { fail 1 'Automatic Go setup supports Linux x86_64 and arm64. Install Go 1.26.10+ on this architecture.'; }
    command -v tar >/dev/null || { fail 1 'Missing prerequisite: tar.'; }
    command -v sha256sum >/dev/null || { fail 1 'Missing prerequisite: sha256sum (coreutils).'; }
    archive="$scratch/go.tar.gz"
    printf 'Preparing Go build tools (official download; SHA-256 verified)…\n'
    if command -v curl >/dev/null; then
        curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
            --connect-timeout 20 --max-time 600 --output "$archive" \
            "https://go.dev/dl/go1.27.4.linux-$go_arch.tar.gz" >> "$log" 2>&1 || { fail 1 'Could not download Go. Check HTTPS access to go.dev and dl.google.com.'; }
    elif command -v wget >/dev/null; then
        wget --https-only --timeout=30 --tries=2 -q -O "$archive" \
            "https://go.dev/dl/go1.27.4.linux-$go_arch.tar.gz" >> "$log" 2>&1 || { fail 1 'Could not download Go. Check HTTPS access to go.dev and dl.google.com.'; }
    else
        fail 1 'Install curl or wget, then rerun setup to prepare Go automatically.'
    fi
    printf '%s  %s\n' "$go_digest" "$archive" | sha256sum --check --status || { fail 1 'Go download checksum mismatch. Nothing from the archive was executed.'; }
    tar -xzf "$archive" -C "$scratch" >> "$log" 2>&1
    export PATH="$scratch/go/bin:$PATH"
    unset GOROOT
    relay_go_suitable || { fail 1 'Downloaded Go could not run on this server.'; }
}
