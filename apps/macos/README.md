# Shixpeer Ward for macOS

Build on macOS 14 or later with Swift and the Go version required by the repository:

```bash
bash apps/macos/build.sh
open 'dist/macos/Shixpeer Ward.app'
```

The build is native to the current Mac and uses a local ad-hoc signature. The
app opens a version 1 `report.json` through **Import Report**. **Scan This Mac**
runs the bundled Go agent against its existing local signed database. If that
database is missing or expired, the report explains the incomplete coverage.
**Add Beacon** accepts any number of entries. To use one for local scanning,
enter its HTTPS origin and the trusted `feed.pub` path, select it under
**Database**, then click **Update & Scan**. Enter a CA file for private Beacon
TLS. Each selected Beacon has its own local database directory.

Docker Desktop update availability is checked through the Docker-signed
updater bundled with the installed application, using `desktop update --check-only`.
Ward never installs a Docker Desktop update.

## Optional encrypted report relay

Build the separate service with `go build -o bin/shixpeer-ward-relay
./cmd/shixpeer-ward-relay`. Run it under a dedicated account with a trusted
HTTPS certificate and a private token configuration. The Mac validates relay
TLS using system trust. For a private CA, install the CA in the Mac trust store
before adding the relay. Use separate random tokens, for example
`openssl rand -hex 32` for each entry, and store the configuration mode 0600.

```json
{
  "reader_token": "REPLACE_WITH_A_RANDOM_READ_TOKEN",
  "writer_tokens": {
    "web-01": "REPLACE_WITH_A_SEPARATE_RANDOM_WRITE_TOKEN"
  }
}
```

```bash
bin/shixpeer-ward-relay -config /path/to/relay.json \
  -listen :8444 -tls-cert /path/to/tls.crt -tls-key /path/to/tls.key
```

Click **Copy Encryption Public Key** in the app and transfer that public key
to the agent through a trusted channel. Create a mode-0600 configuration on
the agent:

```json
{
  "url": "https://relay.example.com:8444",
  "server_id": "web-01",
  "writer_token": "REPLACE_WITH_THE_WEB_01_WRITE_TOKEN",
  "recipient_public_key": "PASTE_THE_MAC_PUBLIC_KEY",
  "ca_file": ""
}
```

Add `-report-upload-config /absolute/path/to/upload.json` to the agent
service's existing `run` arguments, or to an explicit `scan` invocation.
Upload is opt-in and runs after a successful local scan. Add the relay origin
and read token to the corresponding Beacon in the app and click **Fetch
Encrypted Reports**. Each relay retains the most recent encrypted envelope
per configured server ID. Downloads are decrypted in memory. Imported and
fetched reports stay in the current app session.

The report envelope uses ephemeral X25519, HKDF-SHA256 and AES-256-GCM.
The server ID is authenticated as associated data. The recipient private key
and read tokens are stored in macOS Keychain. The relay can see server IDs,
upload times and ciphertext lengths. Writer tokens authenticate uploads to
the relay. End-to-end sender signatures, replay protection, history and key
recovery are outside this MVP. Keep the recipient Keychain entry to retain
access to previously encrypted reports.

## Discover Beacon profiles

Place each profile in its own directory under `~/.shixpeer.ward/trust/`.
Include `feed.pub`, `beacon.json`, and `ca.crt` if Beacon uses a private CA.
Example `beacon.json`:

```json
{"name":"Production","origin":"https://beacon.example.com:8443"}
```

Open **Add Beacon** to review the discovered profiles and confirm an addition.
Use **Refresh** if the files were copied while the sheet was open.
An optional `relay` HTTPS origin can be included in the JSON. Enter its read
token in the app so it can store the token in Keychain.
