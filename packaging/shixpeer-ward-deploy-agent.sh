#!/usr/bin/env bash
# Run from an operator workstation with verified SSH host keys for both servers.
set -euo pipefail
if [[ $# != 3 || ! $1 =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*$ || ! $2 =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*$ || ! $3 =~ ^https://[a-zA-Z0-9.-]+:[0-9]+$ ]]; then
  echo "Usage: bash $0 BEACON_SSH_HOST AGENT_SSH_HOST https://BEACON_HOST:8443" >&2
  exit 2
fi
beacon=$1 agent=$2 origin=$3
opts=(-o StrictHostKeyChecking=yes -o ForwardAgent=no -o ClearAllForwardings=yes)
# Transport trust material and bootstrap code directly over authenticated SSH.
# The second SSH session uses a private temporary directory and checks transfer
# success before invoking the existing signed-release installer.
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
ssh "${opts[@]}" "root@$beacon" 'cat /home/shixpeer-ward-beacon/.shixpeer.ward/pki/ca.crt' > "$tmp/ca.crt"
ssh "${opts[@]}" "root@$beacon" 'cat /home/shixpeer-ward-beacon/.shixpeer.ward/pki/feed.pub' > "$tmp/feed.pub"
ssh "${opts[@]}" "root@$beacon" 'cat /home/shixpeer-ward-beacon/.shixpeer.ward/beacon/public/install.sh' > "$tmp/install.sh"
remote=$(ssh "${opts[@]}" "root@$agent" 'umask 077; mktemp -d /tmp/shixpeer-ward-install.XXXXXXXX')
[[ $remote =~ ^/tmp/shixpeer-ward-install\.[a-zA-Z0-9]+$ ]] || exit 1
cleanup() {
  ssh "${opts[@]}" "root@$agent" "rm -rf -- '$remote'" || true
  rm -rf -- "$tmp"
}
trap cleanup EXIT
scp "${opts[@]}" "$tmp/ca.crt" "$tmp/feed.pub" "$tmp/install.sh" "root@$agent:$remote/"
ssh "${opts[@]}" "root@$agent" "bash '$remote/install.sh' --beacon '$origin' --ca-file '$remote/ca.crt' --trusted-key '$remote/feed.pub'"
