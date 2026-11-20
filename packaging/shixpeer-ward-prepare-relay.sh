#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C

stage='Checking settings'
setup_log=
fail() {
    local code=$1
    shift
    trap - ERR
    printf '\nFAILED: %s\n' "$*" >&2
    if [[ -n $setup_log ]]; then printf 'Details: %s\n' "$setup_log" >&2; fi
    exit "$code"
}
on_error() { fail "$1" "$stage did not complete."; }
trap 'on_error "$?"' ERR
progress() { stage=$2; printf '[%s/4] %s…\n' "$1" "$2"; }

usage() {
    printf 'Usage: bash %s --hostname relay.example.com [--port 8444] [--listen 0.0.0.0] [--tls-cert /path/cert.pem --tls-key /path/key.pem]\n' "$0"
}
hostname= port=8444 cert= key= listen=0.0.0.0
if [[ ${1:-} == --* || $# == 0 ]]; then
    while (( $# )); do
        case "$1" in
            --help) usage; exit 0;;
            --hostname|--port|--listen|--tls-cert|--tls-key)
                (( $# >= 2 )) || { fail 2 "Missing value for $1."; }
                case "$1" in
                    --hostname) hostname=$2;; --port) port=$2;; --listen) listen=$2;;
                    --tls-cert) cert=$2;; --tls-key) key=$2;;
                esac
                shift 2;;
            *) fail 2 "Unknown option: $1. Use --help for supported options.";;
        esac
    done
else
    # Legacy positional syntax remains usable for existing deployments.
    if [[ ( $# != 3 && $# != 4 ) || ! $1 =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then fail 2 'Use --hostname IP_OR_HOSTNAME --port PORT. See --help.'; fi
    port=$2
    if [[ $# == 3 ]]; then hostname=$3; else
        cert=$3 key=$4
        hostname=$(openssl x509 -in "$cert" -noout -subject -nameopt RFC2253 | sed -n 's/.*CN=\([^,]*\).*/\1/p')
    fi
fi
if [[ $hostname == '['*']' ]]; then hostname=${hostname:1:${#hostname}-2}; fi
address_type=DNS
if [[ $hostname =~ ^[0-9.]+$ ]]; then
    [[ $hostname =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { fail 2 "Invalid IPv4 address: $hostname."; }
    IFS=. read -r -a octets <<< "$hostname"
    for octet in "${octets[@]}"; do
        [[ $octet == 0 || $octet =~ ^[1-9][0-9]{0,2}$ ]] && (( 10#$octet <= 255 )) || { fail 2 "Invalid IPv4 address: $hostname."; }
    done
    address_type=IP
elif [[ $hostname == *:* ]]; then
    [[ $hostname =~ ^[A-Fa-f0-9:]+$ ]] || { fail 2 "Invalid IPv6 address: $hostname."; }
    address_type=IP
elif [[ ! $hostname =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ || $hostname == *..* ]]; then
    fail 2 'Enter an IP address or DNS hostname with --hostname.'
fi
if [[ ! $port =~ ^[1-9][0-9]{0,4}$ ]] || (( 10#$port < 1024 || 10#$port > 65535 )); then fail 2 "Port must be between 1024 and 65535 (received: $port)."; fi
[[ $listen == 0.0.0.0 || $listen == 127.0.0.1 || $listen == :: || $listen == ::1 ]] || { fail 2 'Unsupported listen address. Use 0.0.0.0, 127.0.0.1, :: or ::1.'; }
if [[ $hostname == *:* && $listen == 0.0.0.0 ]]; then listen=::; fi
origin="https://$hostname:$port"
if [[ $hostname == *:* ]]; then origin="https://[$hostname]:$port"; fi
listen_host=$listen
if [[ $listen_host == *:* ]]; then listen_host="[$listen_host]"; fi
verify_name=(-verify_hostname "$hostname")
if [[ $address_type == IP ]]; then verify_name=(-verify_ip "$hostname"); fi
if [[ -n $cert || -n $key ]]; then
    for path in "$cert" "$key"; do
        [[ $path == /* && $path != *$'\n'* && $path != *$'\r'* && -f $path && -r $path ]] || { fail 2 'Supply both readable absolute TLS certificate and key paths.'; }
    done
fi
[[ $(uname -s) == Linux && -d /run/systemd/system ]] || { fail 1 'Requires a Linux server with systemd. Nothing was installed.'; }
for tool in go openssl systemctl loginctl install; do
    command -v "$tool" >/dev/null || { fail 1 "Missing prerequisite: $tool. Install it and rerun the command."; }
done
umask 077
root="$HOME/.shixpeer.ward"
config="$root/relay.json"
binary="$root/bin/shixpeer-ward-relay"
unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
unit=shixpeer-ward-relay.service
cd "$(dirname "$0")/.."
install -d -m 700 "$root/bin" "$root/logs" "$unit_dir"
setup_log="$root/logs/relay-setup.log"
: > "$setup_log"
chmod 600 "$setup_log"

temp=$(mktemp -d "$root/.relay-setup.XXXXXXXX")
unit_temp=$(mktemp "$unit_dir/.ward-relay.XXXXXXXX")
trap 'rm -rf -- "$temp"; rm -f -- "$unit_temp"' EXIT
progress 1 'Building relay'
go build -trimpath -o "$temp/shixpeer-ward-relay" ./cmd/shixpeer-ward-relay >> "$setup_log" 2>&1
progress 2 'Configuring TLS and credentials'

if [[ -z $cert ]]; then
    tls_dir="$root/relay-tls"
    cert="$tls_dir/relay.crt"
    key="$tls_dir/relay.key"
    if [[ ! -e $tls_dir ]]; then
        mkdir "$temp/tls"
        openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 365 \
            -subj "/CN=$hostname" -addext "subjectAltName=$address_type:$hostname" \
            -addext 'basicConstraints=critical,CA:FALSE' \
            -addext 'keyUsage=critical,digitalSignature,keyEncipherment' \
            -addext 'extendedKeyUsage=serverAuth' \
            -keyout "$temp/tls/relay.key" -out "$temp/tls/relay.crt" >> "$setup_log" 2>&1
        if mkdir "$tls_dir"; then
            mv "$temp/tls/relay.crt" "$temp/tls/relay.key" "$tls_dir/"
        fi
    fi
    if [[ ! -r $key ]] || ! openssl verify -partial_chain -trusted "$cert" "${verify_name[@]}" "$cert" >> "$setup_log" 2>&1; then
        fail 1 "TLS certificate is missing, expired, or does not match $hostname. Supply valid --tls-cert and --tls-key files."
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
    printf 'Reusing existing relay credentials.\n' >> "$setup_log"
fi

# Adds a separate management capability without changing reader/existing writers.
"$temp/shixpeer-ward-relay" enable-enrollment -config "$config" >> "$setup_log" 2>&1

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
        "$(systemd_quote "$binary")" "$(systemd_quote "$config")" "$listen_host" "$port" \
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

progress 3 'Enabling startup and starting service'
admin() { if [[ $(id -u) == 0 ]]; then "$@"; else sudo -- "$@"; fi; }
# One explicit setup command handles the system action; sudo prompts here only
# when the calling user lacks permission. The relay itself remains a user service.
if [[ $(loginctl show-user "$(id -un)" --property=Linger --value 2>/dev/null || true) != yes ]]; then
    printf 'Administrator approval may be requested for boot startup.\n'
    admin loginctl enable-linger "$(id -un)" >> "$setup_log" 2>&1
fi
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
export DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-unix:path=$XDG_RUNTIME_DIR/bus}"
if ! systemctl --user show-environment >/dev/null 2>&1; then
    admin systemctl start "user@$(id -u).service" >> "$setup_log" 2>&1
    systemctl --user show-environment >> "$setup_log" 2>&1
fi


mv -f "$temp/shixpeer-ward-relay" "$binary"
mv -f "$unit_temp" "$unit_dir/$unit"
systemctl --user daemon-reload >> "$setup_log" 2>&1
systemctl --user enable "$unit" >> "$setup_log" 2>&1
systemctl --user restart "$unit" >> "$setup_log" 2>&1
systemctl --user is-enabled --quiet "$unit"
if ! systemctl --user is-active --quiet "$unit"; then
    journalctl --user -u "$unit" -n 20 --no-pager >> "$setup_log" 2>&1 || true
    fail 1 'Relay service did not start.'
fi
progress 4 'Verifying authenticated HTTPS'
ready=false
for attempt in {1..12}; do
    if "$binary" check -config "$config" -url "$origin" -ca-file "$cert" > "$temp/connection.txt" 2> "$temp/check-error.txt"; then
        ready=true
        break
    fi
    sleep 1
done
if [[ $ready != true ]]; then
    cat "$temp/check-error.txt" >> "$setup_log"
    fail 1 'HTTPS verification failed. Check the address, port, firewall and TLS certificate.'
fi
printf '\nSUCCESS: Relay is running. Startup after reboot is enabled.\n'
cat "$temp/connection.txt"
printf 'Public TLS certificate: %s\nPaste the URL and tokens into Ward. Keep the tokens private.\n' "$cert"
