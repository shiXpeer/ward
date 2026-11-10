#!/usr/bin/env bash
# Run explicitly as root from a verified, locally uploaded Ubuntu release bundle.
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
origin= bundle=$(cd -- "$(dirname -- "$0")/.." && pwd)
while (($#)); do
  case "$1" in --origin) origin=${2:?}; shift 2;; --bundle) bundle=${2:?}; shift 2;; *) echo "Unknown argument: $1" >&2; exit 1;; esac
done
[[ $(id -u) == 0 && $(uname -s) == Linux && -d /run/systemd/system ]] || { echo 'Run with sudo on Ubuntu/systemd.' >&2; exit 1; }
[[ $origin =~ ^https://([A-Za-z0-9.-]+):8443$ ]] || { echo 'Provide --origin https://BEACON_DNS_OR_IPV4:8443 (use a stable address).' >&2; exit 1; }
host=${BASH_REMATCH[1]}
for tool in setfacl runuser systemctl getent install; do command -v "$tool" >/dev/null || { echo "Missing prerequisite: $tool (install acl if setfacl is missing)" >&2; exit 1; }; done
case $(uname -m) in x86_64) arch=amd64;; aarch64|arm64) arch=arm64;; *) exit 1;; esac
[[ -f $bundle/bin/shixpeer-ward-beacon-linux-$arch && -f $bundle/configs/beacon.default.json ]] || { echo 'Release bundle files missing.' >&2; exit 1; }
for legacy in ward-beacon ward-serve; do
  if id "$legacy" >/dev/null 2>&1 || [[ -e /home/$legacy ]]; then
    echo 'Legacy Beacon accounts/state found. Follow the migration steps in docs/ubuntu-deployment.ru.md before reinstalling.' >&2
    exit 1
  fi
done
for user_name in shixpeer-ward-beacon shixpeer-ward-serve; do
  if ! id "$user_name" >/dev/null 2>&1; then useradd --system --user-group --create-home --home-dir "/home/$user_name" --shell /usr/sbin/nologin "$user_name"; fi
  actual_home=$(getent passwd "$user_name" | cut -d: -f6)
  [[ $actual_home == /home/$user_name ]] || { echo "Existing $user_name has unexpected home; use a dedicated account." >&2; exit 1; }
done
base=/home/shixpeer-ward-beacon/.shixpeer.ward
serve=/home/shixpeer-ward-serve/.shixpeer.ward
as_beacon() { runuser -u shixpeer-ward-beacon -- env HOME=/home/shixpeer-ward-beacon "$@"; }
as_serve() { runuser -u shixpeer-ward-serve -- env HOME=/home/shixpeer-ward-serve "$@"; }
# Source bundle is root-readable; stage public binaries so unprivileged install
# operations cannot follow a service user's symlink with root privileges.
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
chmod 755 "$stage"
install -m 644 "$bundle/bin/shixpeer-ward-beacon-linux-$arch" "$stage/beacon"
install -m 644 "$bundle/configs/beacon.default.json" "$stage/sources.json"
for target in amd64 arm64; do install -m 644 "$bundle/bin/shixpeer-ward-agent-linux-$target" "$stage/shixpeer-ward-agent-linux-$target"; done
as_beacon install -d -m 700 "$base/bin" "$base/config" "$base/beacon" "$base/releases"
as_serve install -d -m 700 "$serve/bin" "$serve/pki"
as_beacon install -m 755 "$stage/beacon" "$base/bin/shixpeer-ward-beacon".next
as_beacon mv -f "$base/bin/shixpeer-ward-beacon.next" "$base/bin/shixpeer-ward-beacon"
as_serve install -m 755 "$stage/beacon" "$serve/bin/shixpeer-ward-beacon".next
as_serve mv -f "$serve/bin/shixpeer-ward-beacon.next" "$serve/bin/shixpeer-ward-beacon"
if ! as_beacon test -f "$base/config/beacon.json"; then as_beacon install -m 600 "$stage/sources.json" "$base/config/beacon.json"; fi
for target in amd64 arm64; do as_beacon install -m 644 "$stage/shixpeer-ward-agent-linux-$target" "$base/releases/shixpeer-ward-agent-linux-$target"; done
if ! as_beacon test -d "$base/pki"; then as_beacon "$base/bin/shixpeer-ward-beacon" init -pki "$base/pki" -hosts "$host,localhost,127.0.0.1,::1"; fi
# Transport keys only. The HTTP worker never gets CA/signing private keys.
# Use runuser readers and a root-owned staging directory for privilege separation.
as_beacon cat "$base/pki/server.crt" > "$stage/server.crt"
as_beacon cat "$base/pki/server.key" > "$stage/server.key"
chmod 644 "$stage/server.crt"
chown shixpeer-ward-serve "$stage/server.key"
chmod 600 "$stage/server.key"
as_serve install -m 600 "$stage/server.crt" "$serve/pki/server.crt"
as_serve install -m 600 "$stage/server.key" "$serve/pki/server.key"
as_beacon install -d -m 700 "$base/beacon/public"
# Traverse only to the public directory; no broad home or private-key read grant.
as_beacon setfacl -m u:shixpeer-ward-serve:--x /home/shixpeer-ward-beacon "$base" "$base/beacon"
as_beacon setfacl -m u:shixpeer-ward-serve:r-x,d:u:shixpeer-ward-serve:r-x "$base/beacon/public"
as_beacon "$base/bin/shixpeer-ward-beacon" release -state "$base/beacon" -binaries "$base/releases" -signing-key "$base/pki/signing.key" -release-ttl 720h
cat > "$stage/sync.sh" <<'SYNC'
#!/usr/bin/env bash
set -euo pipefail
base=$HOME/.shixpeer.ward
"$base/bin/shixpeer-ward-beacon" sync -state "$base/beacon" -sources "$base/config/beacon.json" -signing-key "$base/pki/signing.key" -ttl 24h -with-default-ubuntu-vex -source-workers "${SHIXPEER_WARD_SOURCE_WORKERS:-3}"
"$base/bin/shixpeer-ward-beacon" release -state "$base/beacon" -binaries "$base/releases" -signing-key "$base/pki/signing.key" -release-ttl 720h
SYNC
chmod 644 "$stage/sync.sh"
as_beacon install -m 700 "$stage/sync.sh" "$base/bin/shixpeer-ward-sync.sh.next"
as_beacon mv -f "$base/bin/shixpeer-ward-sync.sh.next" "$base/bin/shixpeer-ward-sync.sh"
cat > /etc/systemd/system/shixpeer-ward-beacon.service <<UNIT
[Unit]
Description=Shixpeer Ward read-only HTTPS publisher and agent distribution
After=network-online.target
Wants=network-online.target
[Service]
User=shixpeer-ward-serve
Environment=HOME=/home/shixpeer-ward-serve
ExecStart=$serve/bin/shixpeer-ward-beacon serve -out $base/beacon/public -listen :8443 -tls-cert $serve/pki/server.crt -tls-key $serve/pki/server.key
UMask=0077
Restart=on-failure
RestartSec=15
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
InaccessiblePaths=-$base/pki -$base/beacon/cache -$base/beacon/catalogs
[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/systemd/system/shixpeer-ward-beacon-sync.service <<UNIT
[Unit]
Description=Refresh and sign Shixpeer Ward vulnerability data
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
User=shixpeer-ward-beacon
Environment=HOME=/home/shixpeer-ward-beacon
ExecStart=$base/bin/shixpeer-ward-sync.sh
UMask=0077
TimeoutStartSec=6h
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
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
UNIT
cat > /etc/systemd/system/shixpeer-ward-beacon-sync.timer <<'UNIT'
[Unit]
Description=Periodic Shixpeer Ward vulnerability refresh
[Timer]
OnBootSec=2min
OnUnitInactiveSec=6h
RandomizedDelaySec=5min
Persistent=true
[Install]
WantedBy=timers.target
UNIT
chmod 644 /etc/systemd/system/shixpeer-ward-beacon.service /etc/systemd/system/shixpeer-ward-beacon-sync.service /etc/systemd/system/shixpeer-ward-beacon-sync.timer
systemctl daemon-reload
systemctl enable shixpeer-ward-beacon.service
systemctl restart shixpeer-ward-beacon.service
systemctl enable --now shixpeer-ward-beacon-sync.timer
systemctl start --no-block shixpeer-ward-beacon-sync.service
printf '\nBeacon: %s\nData: %s\n' "$origin" "$base"
echo "Trusted agent CA: $base/pki/ca.crt (transfer via authenticated SSH; never copy *.key)"
echo 'Initial import is asynchronous; wait for a successful sync before agent update/scan.'
echo 'Progress: sudo journalctl -u shixpeer-ward-beacon-sync -f'
echo 'No firewall, UFW, SSH configuration or application packages were modified.'
