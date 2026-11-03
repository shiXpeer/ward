#!/usr/bin/env bash
# Run from the project directory on an operator workstation.
set -euo pipefail
if [[ $# != 2 || ! $1 =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*$ || ! $2 =~ ^https://[a-zA-Z0-9.-]+:8443$ ]]; then
  echo "Usage: bash $0 BEACON_SSH_HOST https://BEACON_HOST:8443" >&2
  exit 2
fi
opts=(-o StrictHostKeyChecking=yes -o ForwardAgent=no -o ClearAllForwardings=yes)
archive=dist/shixpeer-ward-ubuntu.tar.gz
[[ -s $archive ]] || { echo 'Build the archive first: make ubuntu-bundle' >&2; exit 1; }
host=root@$1
ssh "${opts[@]}" "$host" 'command -v setfacl >/dev/null || { echo "Install acl on the Beacon first" >&2; exit 1; }; install -d -m 700 /root/.shixpeer.ward/bootstrap'
scp "${opts[@]}" "$archive" "$host:/root/.shixpeer.ward/bootstrap/"
ssh "${opts[@]}" "$host" "cd /root/.shixpeer.ward/bootstrap && tar -xzf shixpeer-ward-ubuntu.tar.gz && bash ubuntu/packaging/shixpeer-ward-install-beacon.sh --origin '$2'"
