#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/../.."
host="${1:?Usage: deploy-site.sh SSH_HOST}"
# Static site only. No keys or database volumes are copied or recreated.
ssh -o BatchMode=yes "$host" 'mkdir -p "$HOME/apps/shixpeer-ward/site/releases"'
scp packaging/docker/site/index.html "$host:apps/shixpeer-ward/site/index.html"
for file in packaging/docker/site/releases/*; do
  name="$(basename "$file")"
  scp "$file" "$host:apps/shixpeer-ward/site/releases/.$name.next"
  ssh -o BatchMode=yes "$host" "mv \"\$HOME/apps/shixpeer-ward/site/releases/.$name.next\" \"\$HOME/apps/shixpeer-ward/site/releases/$name\""
done
