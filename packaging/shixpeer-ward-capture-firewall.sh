#!/bin/bash
# Capture local evidence for manual audit. Run explicitly as root.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
umask 077
[[ ${EUID} == 0 && ${HOME} == /* ]] || {
    echo 'Run as root with an absolute HOME.' >&2
    exit 1
}
base="$HOME/.shixpeer.ward"
mkdir -p -- "$base"
stage=$(mktemp -d -- "$base/firewall.XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT
capture() {
    local name=$1
    shift
    if command -v "$1" >/dev/null && timeout 10s "$@" >"$stage/$name"; then
        printf '%s OK\n' "$name" >>"$stage/status"
    else
        rm -f -- "$stage/$name"
        printf '%s UNAVAILABLE\n' "$name" >>"$stage/status"
    fi
}
date -u +%FT%TZ >"$stage/captured-at"
capture nft.json nft -j list ruleset
capture iptables-legacy.rules iptables-legacy-save
capture ip6tables-legacy.rules ip6tables-legacy-save
capture listeners.txt ss -H -lntup
capture addresses.json ip -j address show
capture routes-v4.json ip -j -4 route show table all
capture routes-v6.json ip -j -6 route show table all
trap - EXIT
printf '%s\n' "$stage"
