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
