#!/usr/bin/env bash
# Run from an operator workstation with verified SSH host keys for both servers.
set -euo pipefail
if [[ $# != 3 || ! $1 =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*(:[0-9]{1,5})?$ || ! $2 =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*(:[0-9]{1,5})?$ || ! $3 =~ ^https://[a-zA-Z0-9.-]+:[0-9]+$ ]]; then
  echo "Usage: bash $0 BEACON_SSH_HOST[:PORT] AGENT_SSH_HOST[:PORT] https://BEACON_HOST:8443" >&2
  exit 2
fi
beacon=$1 agent=$2 origin=$3
split_ssh() {
  ssh_host=${1%%:*}
  ssh_opts=() scp_opts=()
  if [[ $1 == *:* ]]; then
    local port=${1##*:}
    if (( 10#$port < 1 || 10#$port > 65535 )); then
      echo "Invalid SSH port: $port" >&2
      exit 2
    fi
    ssh_opts=(-p "$((10#$port))")
    scp_opts=(-P "$((10#$port))")
  fi
}
split_ssh "$1"
beacon=$ssh_host
beacon_opts=(${ssh_opts[@]+"${ssh_opts[@]}"})
split_ssh "$2"
agent=$ssh_host

opts=(-o StrictHostKeyChecking=yes -o ForwardAgent=no -o ClearAllForwardings=yes)
# Transport trust material and bootstrap code directly over authenticated SSH.
# The second SSH session uses a private temporary directory and checks transfer
# success before invoking the existing signed-release installer.
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
ssh "${opts[@]}" ${beacon_opts[@]+"${beacon_opts[@]}"} "root@$beacon" 'cat /home/shixpeer-ward-beacon/.shixpeer.ward/pki/ca.crt' > "$tmp/ca.crt"
ssh "${opts[@]}" ${beacon_opts[@]+"${beacon_opts[@]}"} "root@$beacon" 'cat /home/shixpeer-ward-beacon/.shixpeer.ward/pki/feed.pub' > "$tmp/feed.pub"
ssh "${opts[@]}" ${beacon_opts[@]+"${beacon_opts[@]}"} "root@$beacon" 'cat /home/shixpeer-ward-beacon/.shixpeer.ward/beacon/public/install.sh' > "$tmp/install.sh"
remote=$(ssh "${opts[@]}" ${ssh_opts[@]+"${ssh_opts[@]}"} "root@$agent" 'umask 077; mktemp -d /tmp/shixpeer-ward-install.XXXXXXXX')
[[ $remote =~ ^/tmp/shixpeer-ward-install\.[a-zA-Z0-9]+$ ]] || exit 1
cleanup() {
  ssh "${opts[@]}" ${ssh_opts[@]+"${ssh_opts[@]}"} "root@$agent" "rm -rf -- '$remote'" || true
  rm -rf -- "$tmp"
}
trap cleanup EXIT
scp "${opts[@]}" ${scp_opts[@]+"${scp_opts[@]}"} "$tmp/ca.crt" "$tmp/feed.pub" "$tmp/install.sh" "root@$agent:$remote/"
ssh "${opts[@]}" ${ssh_opts[@]+"${ssh_opts[@]}"} "root@$agent" "bash '$remote/install.sh' --beacon '$origin' --ca-file '$remote/ca.crt' --trusted-key '$remote/feed.pub'"
