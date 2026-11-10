#!/usr/bin/env bash
# Shixpeer Ward agent installer. Download over authenticated HTTPS, then execute.
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
beacon= key= ca= pin= user_name=shixpeer-ward-agent
while (($#)); do
  case "$1" in
    --beacon|--trusted-key|--ca-file|--key-sha256|--user)
      (($# >= 2)) || { echo "Missing value: $1" >&2; exit 1; }
      case "$1" in --beacon) beacon=$2;; --trusted-key) key=$2;; --ca-file) ca=$2;; --key-sha256) pin=$2;; --user) user_name=$2;; esac
      shift 2;;
    *) echo "Unknown argument: $1" >&2; exit 1;;
  esac
done
[[ $(id -u) == 0 ]] || { echo 'Run with sudo to install the systemd service.' >&2; exit 1; }
[[ $(uname -s) == Linux && -d /run/systemd/system ]] || { echo 'Linux with systemd required.' >&2; exit 1; }
[[ $beacon =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?$ ]] || { echo '--beacon must be an HTTPS origin, without path or credentials.' >&2; exit 1; }
[[ $user_name =~ ^[a-z_][a-z0-9_-]{0,31}$ && $user_name != root ]] || { echo 'A non-root service user is required.' >&2; exit 1; }
[[ -n $key || $pin =~ ^[a-f0-9]{64}$ ]] || { echo 'Provide a trusted public key or independently obtained SHA256 SPKI fingerprint.' >&2; exit 1; }
for tool in curl openssl sha256sum systemctl getent runuser install awk stat; do command -v "$tool" >/dev/null || { echo "Missing prerequisite: $tool" >&2; exit 1; }; done
case $(uname -m) in x86_64) arch=amd64;; aarch64|arm64) arch=arm64;; *) echo 'Only amd64 and arm64 are supported.' >&2; exit 1;; esac
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
curl_args=(--fail --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 180 --noproxy '*' --user-agent Shixpeer-Ward-Installer/1)
if [[ -n $ca ]]; then [[ -f $ca ]] || { echo 'CA file missing.' >&2; exit 1; }; curl_args+=(--cacert "$ca"); fi
fetch() { curl "${curl_args[@]}" --max-filesize "$3" "$beacon/$1" -o "$2"; }
if [[ -n $key ]]; then
  [[ -f $key ]] || { echo 'Trusted key file missing.' >&2; exit 1; }
  install -m 600 "$key" "$tmp/feed.pub"
else
  fetch feed.pub "$tmp/feed.pub" 4096
fi
actual=$(openssl pkey -pubin -in "$tmp/feed.pub" -outform DER | sha256sum | awk '{print $1}')
if [[ -n $pin && $actual != "$pin" ]]; then echo 'Publisher key fingerprint mismatch.' >&2; exit 1; fi
fetch agents.txt "$tmp/agents.txt" 4096
fetch agents.sig "$tmp/agents.sig" 128
openssl pkeyutl -verify -pubin -inkey "$tmp/feed.pub" -rawin -in "$tmp/agents.txt" -sigfile "$tmp/agents.sig" >/dev/null || { echo 'Agent release signature rejected.' >&2; exit 1; }
mapfile -t lines < "$tmp/agents.txt"
[[ ${#lines[@]} == 6 && ${lines[0]} == WARD-AGENT-RELEASE-V1 && ${lines[1]} =~ ^[0-9]{10}$ && ${lines[2]} =~ ^[0-9]{10}$ && ${lines[3]} =~ ^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$ ]] || { echo 'Invalid signed release manifest.' >&2; exit 1; }
now=$(date +%s); revision=${lines[1]}; expires=${lines[2]}
(( revision <= now + 300 && expires > now && expires > revision && expires - revision <= 2592000 )) || { echo 'Agent release is expired or outside its validity window.' >&2; exit 1; }
name= seen_amd64= seen_arm64=
for line in "${lines[@]:4}"; do
  IFS=$'\t' read -r hash bytes filename extra <<< "$line"
  [[ $hash =~ ^[a-f0-9]{64}$ && $bytes =~ ^[0-9]{1,8}$ && $filename =~ ^agent-linux-(amd64|arm64)-[a-f0-9]{64}$ && -z ${extra:-} && $filename == *"-$hash" ]] || { echo 'Invalid artifact entry.' >&2; exit 1; }
  (( bytes > 0 && bytes <= 67108864 )) || exit 1
  if [[ $filename == agent-linux-amd64-* ]]; then [[ -z $seen_amd64 ]] || exit 1; seen_amd64=1; else [[ -z $seen_arm64 ]] || exit 1; seen_arm64=1; fi
  # Every installer fetches/verifies both builds. The Beacon does not learn the
  # host architecture from the selected download; selection stays local.
  fetch "$filename" "$tmp/$filename" 67108864
  [[ $(stat -c %s "$tmp/$filename") == "$bytes" ]] || { echo 'Agent size mismatch.' >&2; exit 1; }
  [[ $(sha256sum "$tmp/$filename" | awk '{print $1}') == "$hash" ]] || { echo 'Agent digest mismatch.' >&2; exit 1; }
  if [[ $filename == agent-linux-$arch-* ]]; then [[ -z $name ]] || exit 1; name=$filename; fi
done
[[ -n $name ]] || { echo 'No signed agent for this architecture.' >&2; exit 1; }
[[ -n $seen_amd64 && -n $seen_arm64 ]] || { echo 'Release must include both supported architectures.' >&2; exit 1; }
cp "$tmp/$name" "$tmp/agent"
if [[ $user_name == shixpeer-ward-agent ]] && { id ward-agent >/dev/null 2>&1 || [[ -e /home/ward-agent ]]; }; then
  echo 'Legacy agent account/state found. Follow the migration steps in docs/ubuntu-deployment.uk.md.' >&2
  exit 1
fi
# Mutate the host only after validating all downloaded code.
if ! id "$user_name" >/dev/null 2>&1; then
  [[ $user_name == shixpeer-ward-agent ]] || { echo 'Requested user must already exist.' >&2; exit 1; }
  useradd --system --user-group --create-home --home-dir /home/shixpeer-ward-agent --shell /usr/sbin/nologin shixpeer-ward-agent
fi
home_dir=$(getent passwd "$user_name" | cut -d: -f6)
# Safe systemd paths: reject whitespace/specifiers instead of embedding shell text.
[[ $home_dir =~ ^/[A-Za-z0-9_./-]+$ && $home_dir != / && $home_dir != *'/../'* ]] || { echo 'Unsupported service home path.' >&2; exit 1; }
base=$home_dir/.shixpeer.ward
as_user() { runuser -u "$user_name" -- env -i HOME="$home_dir" PATH=/usr/sbin:/usr/bin:/sbin:/bin "$@"; }
# Home files are always written with the service user's privileges, preventing
# user-controlled symlinks from turning this root installer into arbitrary writes.
chmod 711 "$tmp"
chmod 644 "$tmp/agent" "$tmp/feed.pub"
if [[ -n $ca ]]; then install -m 644 "$ca" "$tmp/ca.crt"; fi
as_user install -d -m 700 "$base" "$base/bin" "$base/config" "$base/agent"
if [[ -f $base/config/install-key.sha256 && $(as_user cat "$base/config/install-key.sha256") != "$actual" ]]; then echo 'Installed publisher key differs; refusing implicit trust rotation.' >&2; exit 1; fi
manifest_hash=$(sha256sum "$tmp/agents.txt" | awk '{print $1}')
if [[ -f $base/config/install-revision ]]; then
  old=$(as_user cat "$base/config/install-revision")
  [[ $old =~ ^[0-9]{10}$ ]] || { echo 'Invalid installed release checkpoint.' >&2; exit 1; }
  (( revision >= old )) || { echo 'Agent release rollback rejected.' >&2; exit 1; }
  if [[ $revision == "$old" && -f $base/config/install-manifest.sha256 && $(as_user cat "$base/config/install-manifest.sha256") != "$manifest_hash" ]]; then echo 'Conflicting release at installed revision.' >&2; exit 1; fi
fi
as_user install -m 600 "$tmp/feed.pub" "$base/config/feed.pub"
ca_flags=()
if [[ -n $ca ]]; then as_user install -m 600 "$tmp/ca.crt" "$base/config/ca.crt"; ca_flags=(-ca-file "$base/config/ca.crt"); fi
as_user install -m 755 "$tmp/agent" "$base/bin/.agent-next"
# Configure with the verified binary before replacing the running executable.
as_user "$base/bin/.agent-next" setup -state "$base/agent" -feed-url "$beacon/v1/manifest.json" -trusted-key "$base/config/feed.pub" "${ca_flags[@]}"
as_user mv -f "$base/bin/.agent-next" "$base/bin/shixpeer-ward-agent"
unit=$(mktemp /etc/systemd/system/.shixpeer-ward-agent.XXXXXX)
cat > "$unit" <<UNIT
[Unit]
Description=Shixpeer Ward local security reports and signed database sync
After=network-online.target shixpeer-ward-agent-capture.service
Wants=network-online.target shixpeer-ward-agent-capture.service
[Service]
Type=simple
User=$user_name
Environment=HOME=$home_dir
Environment=SHIXPEER_WARD_MANAGED_CAPTURE=1
ExecStart=$base/bin/shixpeer-ward-agent run -feed-interval 1m -collect-interval 1h
WorkingDirectory=$home_dir
UMask=0077
Restart=on-failure
RestartSec=15
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$base
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
[Install]
WantedBy=multi-user.target
UNIT
chmod 644 "$unit"
mv -f "$unit" /etc/systemd/system/shixpeer-ward-agent.service
# Root executes only the verified, root-owned copy. The unprivileged
# receiver writes the snapshot, including the atomic rename inside its HOME.
install -d -o root -g root -m 0755 /usr/local/libexec/shixpeer-ward
install -o root -g root -m 0755 "$tmp/agent" /usr/local/libexec/shixpeer-ward/.shixpeer-ward-agent-next
mv -fT /usr/local/libexec/shixpeer-ward/.shixpeer-ward-agent-next /usr/local/libexec/shixpeer-ward/shixpeer-ward-agent
cat > "$tmp/capture" <<'CAPTURE'
#!/bin/bash
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
snapshot=$(mktemp)
trap 'rm -f -- "$snapshot"' EXIT
/usr/local/libexec/shixpeer-ward/shixpeer-ward-agent capture-docker > "$snapshot"
runuser -u "$1" -- /bin/bash -c '
    set -euo pipefail
    umask 077
    tmp=$(mktemp "$1/.docker-snapshot.XXXXXXXX")
    trap '"'"'rm -f -- "$tmp"'"'"' EXIT
    cat > "$tmp"
    [[ -s $tmp ]]
    mv -fT -- "$tmp" "$1/docker-snapshot.json"
  ' bash "$2" < "$snapshot"
CAPTURE
install -o root -g root -m 0755 "$tmp/capture" /usr/local/libexec/shixpeer-ward/shixpeer-ward-capture
cat > "$tmp/capture.service" <<UNIT
[Unit]
Description=Capture Shixpeer Ward Docker and local firewall evidence
Before=shixpeer-ward-agent.service
[Service]
Type=oneshot
Environment=HOME=/root
ExecStart=/usr/local/libexec/shixpeer-ward/shixpeer-ward-capture $user_name $base/agent
TimeoutStartSec=75s
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$base/agent
PrivateTmp=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6
UNIT
cat > "$tmp/capture.timer" <<'UNIT'
[Unit]
Description=Refresh Shixpeer Ward Docker and firewall evidence
[Timer]
OnBootSec=30s
OnUnitActiveSec=5min
[Install]
WantedBy=timers.target
UNIT
install -m 644 "$tmp/capture.service" /etc/systemd/system/shixpeer-ward-agent-capture.service
install -m 644 "$tmp/capture.timer" /etc/systemd/system/shixpeer-ward-agent-capture.timer
systemctl daemon-reload
systemctl enable --now shixpeer-ward-agent-capture.timer
systemctl enable shixpeer-ward-agent.service
systemctl restart shixpeer-ward-agent.service
printf '%s\n' "$actual" > "$tmp/pin"
printf '%s\n' "$revision" > "$tmp/revision"
printf '%s\n' "$manifest_hash" > "$tmp/manifest-hash"
chmod 644 "$tmp/pin" "$tmp/revision" "$tmp/manifest-hash"
as_user install -m 600 "$tmp/pin" "$base/config/install-key.sha256"
as_user install -m 600 "$tmp/revision" "$base/config/install-revision"
as_user install -m 600 "$tmp/manifest-hash" "$base/config/install-manifest.sha256"
echo "Agent installed as $user_name. Data/reports: $base/agent"
echo 'No software updates or firewall changes performed. Database sync and scans run in the service.'
echo "Follow reports: sudo -u $user_name tail -f $base/logs/agent.log"
echo 'Startup errors: sudo journalctl -u shixpeer-ward-agent -n 50 --no-pager'
