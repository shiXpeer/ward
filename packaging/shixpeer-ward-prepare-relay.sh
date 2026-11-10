#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

server_id=${1:-}
port=${2:-}
if [[ ( $# != 3 && $# != 4 ) || ! $server_id =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ||
      ! $port =~ ^[1-9][0-9]{0,4}$ ]] || (( port < 1024 || port > 65535 )); then
    printf 'Usage: %s SERVER_ID PORT HOSTNAME | SERVER_ID PORT TLS_CERT TLS_KEY (port 1024–65535)\n' "$0" >&2
    exit 2
fi

hostname=
if [[ $# == 3 ]]; then
    hostname=$3
    if [[ ! $hostname =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ || $hostname == *..* ||
          $hostname =~ ^[0-9.]+$ ]]; then
        printf 'Enter the DNS hostname clients will use to reach the relay.\n' >&2
        exit 2
    fi
else
    for path in "$3" "$4"; do
        if [[ $path != /* || $path == *$'\n'* || $path == *$'\r'* || ! -f $path || ! -r $path ]]; then
            printf 'TLS certificate and key must be readable files specified by absolute path.\n' >&2
            exit 2
        fi
    done
fi

if [[ $(loginctl show-user "$(id -un)" --property=Linger --value) != yes ]]; then
    printf 'Enable boot startup for this account first: sudo loginctl enable-linger "%s"\n' "$(id -un)" >&2
    exit 1
fi
systemctl --user show-environment >/dev/null

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

cert=$3
key=${4:-}
if [[ -n $hostname ]]; then
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
    writer=$(openssl rand -hex 32)
    printf '{\n  "reader_token": "%s",\n  "writer_tokens": {\n    "%s": "%s"\n  }\n}\n' \
        "$reader" "$server_id" "$writer" > "$temp/relay.json"
    ln "$temp/relay.json" "$config"
else
    printf 'Reusing %s. Ensure writer_tokens contains %s.\n' "$config" "$server_id"
fi

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
    printf 'ExecStart=:%s -config %s -listen 0.0.0.0:%s -tls-cert %s -tls-key %s\n' \
        "$(systemd_quote "$binary")" "$(systemd_quote "$config")" "$port" \
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
systemctl --user is-active "$unit"
printf 'Listening port: %s\nPrivate config: %s\nService unit: %s/%s\n' "$port" "$config" "$unit_dir" "$unit"
if [[ -n $hostname ]]; then
    printf 'Relay URL: https://%s:%s\nPublic certificate for clients: %s\n' "$hostname" "$port" "$cert"
fi
