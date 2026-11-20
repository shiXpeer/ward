#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

usage() {
    printf 'Usage: bash %s --hostname relay.example.com [--port 8444] [--listen 0.0.0.0] [--tls-cert /path/cert.pem --tls-key /path/key.pem]\n' "$0"
}
hostname= port=8444 cert= key= listen=0.0.0.0
if [[ ${1:-} == --* || $# == 0 ]]; then
    while (( $# )); do
        case "$1" in
            --help) usage; exit 0;;
            --hostname|--port|--listen|--tls-cert|--tls-key)
                (( $# >= 2 )) || { usage >&2; exit 2; }
                case "$1" in
                    --hostname) hostname=$2;; --port) port=$2;; --listen) listen=$2;;
                    --tls-cert) cert=$2;; --tls-key) key=$2;;
                esac
                shift 2;;
            *) usage >&2; exit 2;;
        esac
    done
else
    # Legacy positional syntax remains usable for existing deployments.
    if [[ ( $# != 3 && $# != 4 ) || ! $1 =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then usage >&2; exit 2; fi
    port=$2
    if [[ $# == 3 ]]; then hostname=$3; else
        cert=$3 key=$4
        hostname=$(openssl x509 -in "$cert" -noout -subject -nameopt RFC2253 | sed -n 's/.*CN=\([^,]*\).*/\1/p')
    fi
fi
if [[ ! $hostname =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ || $hostname == *..* ||
      $hostname =~ ^[0-9.]+$ || ! $port =~ ^[1-9][0-9]{0,4}$ ]] || (( 10#$port < 1024 || 10#$port > 65535 )); then
    usage >&2; exit 2
fi
[[ $listen == 0.0.0.0 || $listen == 127.0.0.1 ]] || { echo '--listen must be 0.0.0.0 or 127.0.0.1.' >&2; exit 2; }
if [[ -n $cert || -n $key ]]; then
    for path in "$cert" "$key"; do
        [[ $path == /* && $path != *$'\n'* && $path != *$'\r'* && -f $path && -r $path ]] || { echo 'Supply both readable absolute TLS certificate/key paths.' >&2; exit 2; }
    done
fi
[[ $(uname -s) == Linux && -d /run/systemd/system ]] || { echo 'Requires Linux with systemd.' >&2; exit 1; }
for tool in go openssl systemctl loginctl install; do
    command -v "$tool" >/dev/null || { echo "Install prerequisite: $tool" >&2; exit 1; }
done
admin() { if [[ $(id -u) == 0 ]]; then "$@"; else sudo -- "$@"; fi; }
# One explicit setup command handles the system action; sudo prompts here only
# when the calling user lacks permission. The relay itself remains a user service.
if [[ $(loginctl show-user "$(id -un)" --property=Linger --value 2>/dev/null || true) != yes ]]; then
    printf 'Enabling startup after reboot (may request sudo).\n'
    admin loginctl enable-linger "$(id -un)"
fi
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
export DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-unix:path=$XDG_RUNTIME_DIR/bus}"
if ! systemctl --user show-environment >/dev/null 2>&1; then
    admin systemctl start "user@$(id -u).service"
    systemctl --user show-environment >/dev/null
fi

umask 077
root="$HOME/.shixpeer.ward"
config="$root/relay.json"
binary="$root/bin/shixpeer-ward-relay"
unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
unit=shixpeer-ward-relay.service
cd "$(dirname "$0")/.."
install -d -m 700 "$root/bin" "$unit_dir"

temp=$(mktemp -d "$root/.relay-setup.XXXXXXXX")
unit_temp=$(mktemp "$unit_dir/.ward-relay.XXXXXXXX")
trap 'rm -rf -- "$temp"; rm -f -- "$unit_temp"' EXIT
go build -trimpath -o "$temp/shixpeer-ward-relay" ./cmd/shixpeer-ward-relay

if [[ -z $cert ]]; then
    tls_dir="$root/relay-tls"
    cert="$tls_dir/relay.crt"
    key="$tls_dir/relay.key"
    if [[ ! -e $tls_dir ]]; then
        mkdir "$temp/tls"
        openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 365 \
            -subj "/CN=$hostname" -addext "subjectAltName=DNS:$hostname" \
            -addext 'basicConstraints=critical,CA:FALSE' \
            -addext 'keyUsage=critical,digitalSignature,keyEncipherment' \
            -addext 'extendedKeyUsage=serverAuth' \
            -keyout "$temp/tls/relay.key" -out "$temp/tls/relay.crt" 2>/dev/null
        if mkdir "$tls_dir"; then
            mv "$temp/tls/relay.crt" "$temp/tls/relay.key" "$tls_dir/"
        fi
    fi
    if [[ ! -r $key ]] || ! openssl verify -partial_chain -trusted "$cert" -verify_hostname "$hostname" "$cert" >/dev/null; then
        printf 'Existing relay certificate is missing, expired, or does not match %s. Supply valid TLS files explicitly.\n' "$hostname" >&2
        exit 1
    fi
fi

if [[ ! -e $config && ! -L $config ]]; then
    reader=$(openssl rand -hex 32)
    # Server credentials are now created by authenticated enrollment, not by
    # reserving the initial setup ID before an agent exists.
    printf '{\n  "reader_token": "%s",\n  "writer_tokens": {}\n}\n' \
        "$reader" > "$temp/relay.json"
    ln "$temp/relay.json" "$config"
else
    printf 'Reusing %s. New servers can be enrolled from Ward.\n' "$config"
fi

# Adds a separate management capability without changing reader/existing writers.
"$temp/shixpeer-ward-relay" enable-enrollment -config "$config"

systemd_quote() {
    local value=$1
    value=${value//\\/\\\\}
    value=${value//\"/\\\"}
    value=${value//%/%%}
    printf '"%s"' "$value"
}

{
    cat <<'UNIT'
[Unit]
Description=Shixpeer Ward report relay

[Service]
UNIT
    printf 'ExecStart=:%s -config %s -listen %s:%s -tls-cert %s -tls-key %s\n' \
        "$(systemd_quote "$binary")" "$(systemd_quote "$config")" "$listen" "$port" \
        "$(systemd_quote "$cert")" "$(systemd_quote "$key")"
    cat <<'UNIT'
UMask=0077
NoNewPrivileges=yes
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=default.target
UNIT
} > "$unit_temp"

mv -f "$temp/shixpeer-ward-relay" "$binary"
mv -f "$unit_temp" "$unit_dir/$unit"
systemctl --user daemon-reload
systemctl --user enable "$unit"
systemctl --user restart "$unit"
systemctl --user is-enabled --quiet "$unit"
if ! systemctl --user is-active --quiet "$unit"; then
    journalctl --user -u "$unit" -n 20 --no-pager >&2
    exit 1
fi
printf 'Checking authenticated HTTPS…\n'
ready=false
for attempt in {1..12}; do
    if "$binary" check -config "$config" -url "https://$hostname:$port" -ca-file "$cert" > "$temp/connection.txt" 2> "$temp/check-error.txt"; then
        ready=true
        break
    fi
    sleep 1
done
if [[ $ready != true ]]; then
    cat "$temp/check-error.txt" >&2
    printf 'HTTPS verification failed. Check hostname/DNS, port and TLS certificate. Logs: journalctl --user -u %s -n 30\n' "$unit" >&2
    exit 1
fi
printf '\nStartup after reboot: enabled\n'
cat "$temp/connection.txt"
printf 'Public TLS certificate: %s\nKeep the tokens private. Use these values in Ward.\n' "$cert"
