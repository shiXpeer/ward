#!/usr/bin/env bash
# Run from the project directory on an operator workstation.
set -euo pipefail
if [[ $# != 2 || ! $1 =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*(:[0-9]{1,5})?$ || ! $2 =~ ^https://[a-zA-Z0-9.-]+:8443$ ]]; then
  echo "Usage: bash $0 BEACON_SSH_HOST[:PORT] https://BEACON_HOST:8443" >&2
  exit 2
fi
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

opts=(-o StrictHostKeyChecking=yes -o ForwardAgent=no -o ClearAllForwardings=yes)
archive=dist/shixpeer-ward-ubuntu.tar.gz
[[ -s $archive ]] || { echo 'Build the archive first: make ubuntu-bundle' >&2; exit 1; }
host=root@$beacon
ssh "${opts[@]}" ${ssh_opts[@]+"${ssh_opts[@]}"} "$host" 'command -v setfacl >/dev/null || { echo "Install acl on the Beacon first" >&2; exit 1; }; install -d -m 700 /root/.shixpeer.ward/bootstrap'
scp "${opts[@]}" ${scp_opts[@]+"${scp_opts[@]}"} "$archive" "$host:/root/.shixpeer.ward/bootstrap/"
ssh "${opts[@]}" ${ssh_opts[@]+"${ssh_opts[@]}"} "$host" "cd /root/.shixpeer.ward/bootstrap && tar -xzf shixpeer-ward-ubuntu.tar.gz && bash ubuntu/packaging/shixpeer-ward-install-beacon.sh --origin '$2'"
