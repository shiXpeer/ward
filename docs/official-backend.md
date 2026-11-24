# Official Ward backend

Ward uses https://ward.shixpeer.com for update metadata and the signed scanner
feed. Installer archives still come directly from their vendors; Ward verifies
archive checksums where declared, Sparkle signatures, and macOS bundle identity,
team and code signature locally. Native macOS Software Update remains a system
service exception. Relay connections remain user-configured.

## Containers

`packaging/docker/compose.yaml` defines an isolated API, publisher and edge proxy.
The publisher refreshes the complete Beacon source set every six hours and signs
snapshots valid for 24 hours. File-backed Docker volumes retain state and signing
identity. The API cannot read the signing key or raw source state. Do not delete
these volumes during upgrades. Back up the signing volume securely; key rotation
requires a deliberate client trust update.

Build a Linux binary matching the server architecture into `build/`:

```sh
mkdir -p build
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false -o build/shixpeer-ward-beacon ./cmd/shixpeer-ward-beacon
```

The deployment directory contains `compose.yaml`, `edge.conf`, and a `build/`
context containing `Dockerfile.backend` renamed `Dockerfile`, executable
`init.sh`, the binary, and `configs/{beacon.default,update-metadata-sources}.json`.
Run `docker compose build ward-init && docker compose up -d`. Initial publication
needs a full upstream sync. The external frontend network is `compose_default`;
use `spark-nginx.conf` in the existing frontend, then validate and reload Nginx.
The Cloudflare public hostname routes to that frontend at `http://nginx:80`.
No host port is opened by the Ward containers.

For an API-only upgrade after building the image:

```sh
docker compose up -d --no-deps --no-build --pull never ward-api
```

## Metadata policy

`configs/update-metadata-sources.json` lists allowed provider origins/path scopes.
New sources require an operator configuration update, not scanner recompilation.
The API rejects unknown destinations, non-public DNS addresses, unapproved
redirects, credentials, oversized responses and arbitrary methods. It has bounded
memory, concurrency and timeouts, and does not log requested URLs. Backend failure
never silently switches the client to direct metadata requests.

Homebrew metadata uses a bounded on-disk mirror retaining original JWS bytes.
The scoped curl wrapper also redirects Homebrew's default API fallback. Bottle
and source archive downloads remain direct and Homebrew checks their hashes.
No global proxy or Homebrew configuration is modified.

## Verification

Check `/healthz`, then `/v1/manifest.json` and its signature using the bundled
`apps/macos/OfficialFeed.pub`. Health alone does not establish database readiness.
Inspect `docker compose logs ward-publisher` for a successful signed export and
`docker compose ps` for running containers. In Ward, Database should select Ward;
refresh the database, scan, then check application versions. Unknown channels
must report a failed/unsupported check rather than a clean result.

`make check` and the macOS fixture test scripts exercise errors, allowlists,
checksums and protocol behavior without contacting production.

## Server-side version subscriptions and optional failure counts

`POST /v1/app-version` takes a public bundle ID, architecture and declared channel
(Sparkle, Electron, App Store, JetBrains, Docker, VS Code-style, product XML,
plain version or bounded PKG metadata). No installed version is needed. All
vendor fetching and version parsing happen on the server; Ward compares the
normalized result locally. `installable` is only a UI capability hint: installation
still independently verifies the vendor artifact locally.

Active channel queries are cached in memory (512 entries max); a background
worker refreshes them every 15 minutes and drops inactive channels after 24h.
There are no client subscription IDs. Ward polls with ETags every minute in the
foreground or five minutes in the background, without invoking native macOS
Software Update on each poll. The subscription can be disabled in Settings.
This is polling, not APNs or a persistent push connection.

Operator `version_rules` in `configs/update-metadata-sources.json` can override
normal channels or add previously unsupported apps. Each rule has `bundle_id`,
optional `architecture`, an allowlisted HTTPS `url`, and either `json_path` (array
of keys/indices) or a RE2 `pattern` with exactly one capture. A plain version
response needs neither. Example using a fixture-only provider:

```json
{"bundle_id":"com.example.product","url":"https://feed.example/releases.json","json_path":["stable","version"]}
```

Add its provider to `sources`, rebuild/restart the API, and existing new-protocol
clients pick up the result without updating Ward. Rules never add executable
commands or bypass archive verification. Supporting a completely new transport
may still require a server adapter; local discovery of an entirely new kind of
app configuration may require a client update.

`POST /v1/update-failures` is opt-in from the client and accepts exactly
`bundle_id` and `reason` (`unsupported_channel` or `check_failed`). No public read
endpoint exists. Inspect counters over SSH:

```sh
docker compose exec -T ward-api cat /metadata-cache/diagnostics/failures.json
```

At most 2,048 daily counters are retained, capped at one million events each;
files have mode 0600. Startup/hourly pruning removes old days even when no new
reports arrive. Input bodies, unknown fields and categories are rejected, and
the edge rate limit applies. These are untrusted event counts, not unique users
or authenticated evidence. Never automatically publish a rule based on a report.
Ward 0.5.0 uses the earlier metadata proxy protocol; one client upgrade is needed
for server-side parsing, subscriptions and opt-in diagnostics.
