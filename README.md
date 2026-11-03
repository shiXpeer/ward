# Shixpeer Ward

Private host monitoring and an open vulnerability-data pipeline.

**[shixpeer.com](https://shixpeer.com)** · [Русский](README.ru.md) ·
[Architecture](docs/architecture.md) · [Security](SECURITY.md) · [Contributing](CONTRIBUTING.md)

Shixpeer Ward keeps host inventory local. A separate publisher gathers configured
vulnerability sources and produces a compact, signed disk database for agents to download.
It does not install updates, change firewalls, accept remote commands, or require an account.

Two Go applications, no Postgres, SQLite, Redis, or other database service/engine:

| Application | Responsibility |
| --- | --- |
| `shixpeer-ward-agent` | Observe a host locally and download changed parts of signed disk snapshots |
| `shixpeer-ward-beacon` | Aggregate configured sources, stream and normalize sources, publish indexed snapshots |

**Status: partial local scanner.** Inventories OS/kernel, Debian/Ubuntu and
Homebrew packages, macOS applications, service registries, local ports, Docker
metadata and global npm/Python packages. Matches supported distro/language rules
and explicitly mapped NVD CPE products locally. macOS release entries and complex
conditions require review. Unknown identities, container packages and project
lockfiles remain explicitly unchecked. No automatic software updates or remote commands.

## Ubuntu deployment

See the [step-by-step Ubuntu guide](docs/ubuntu-deployment.ru.md) for the split
Beacon publisher, signed two-command agent installation after trust provisioning,
systemd and home-state migration. Build the Linux bundle with `make ubuntu-bundle`.

## Local scan and report

After setup and database update:

```sh
bin/shixpeer-ward-agent scan
```

The console shows coverage counts, highest-priority findings, uncertain records
and warnings automatically. Reports `report.json` and `report.md` are saved in the agent state directory.
Use `scan -report-dir .local/reports` for another output directory. Scanning is
offline and does not update installed software. Unchecked software and unsupported
rules remain explicit; zero findings does not mean safe.
See [coverage and report interpretation](docs/scanning.md).


## Simple database updates

Save the publisher URL and its independently provisioned public signing key once:

```sh
bin/shixpeer-ward-agent setup -feed-url https://YOUR-BEACON/v1/manifest.json -trusted-key /path/to/feed.pub
bin/shixpeer-ward-agent update
```

The URL is a placeholder; no hosted public Ward service is currently supplied.
For private HTTPS add `-ca-file /path/to/ca.crt` during setup. Public HTTPS uses
system roots. Agents never need private keys. After setup, no arguments are
required; running the binary without a command also updates the database.
All agents download the same publication, reusing unchanged objects. No ecosystem,
package inventory, or installed versions are sent. This updates vulnerability data,
not installed software.

Settings are atomically saved with mode 600 to `~/.shixpeer.ward/config/agent.json`.
Database and reports live under `~/.shixpeer.ward/agent/` on Linux/macOS, including
root's `/root/.shixpeer.ward/`. Setup copies a configured CA into home config.
Use the same account for setup/update/scan. `-config` and `-state` remain explicit
overrides. Run `migrate-home` before using legacy state with the new defaults.
Explicit flags override saved settings for one invocation; setup saves
changes. URL precedence: explicit flag, `SHIXPEER_WARD_AGENT_FEED_URL`, saved URL.

Signature, expiry, and rollback checks remain mandatory. Signing key arguments are
optional after initial trust provisioning. Offline package lookup still requires
an explicit ecosystem. Use scan for automatic inventory and supported matching.


## Try it locally, without sending host data anywhere

Requires Go 1.26.10+; `make` is optional. Linux and macOS are the initial platforms.
The binaries embed two Go libraries: a pure Go XZ decoder and the Go HTML parser.
See THIRD_PARTY_NOTICES.md. Building may download pinned Go modules/toolchain;
normal execution does not download code or tools.

```sh
make build
mkdir -p "$HOME/.shixpeer.ward/demo"
bin/shixpeer-ward-beacon init -pki "$HOME/.shixpeer.ward/demo/pki"
bin/shixpeer-ward-beacon sync -sources configs/beacon.demo.json -state "$HOME/.shixpeer.ward/demo/beacon"
bin/shixpeer-ward-beacon export -state "$HOME/.shixpeer.ward/demo/beacon" -out "$HOME/.shixpeer.ward/demo/public" -signing-key "$HOME/.shixpeer.ward/demo/pki/signing.key"
bin/shixpeer-ward-beacon serve -out "$HOME/.shixpeer.ward/demo/public" -state "$HOME/.shixpeer.ward/demo/beacon" -tls-cert "$HOME/.shixpeer.ward/demo/pki/server.crt" -tls-key "$HOME/.shixpeer.ward/demo/pki/server.key"
```

The server listens on `https://localhost:8443`. The demo uses a **synthetic advisory**
from this repository; it is not a real CVE. No live upstream source is contacted.
In another terminal, from the repository directory:

```sh
bin/shixpeer-ward-agent collect -state "$HOME/.shixpeer.ward/demo/agent"
bin/shixpeer-ward-agent pull -state "$HOME/.shixpeer.ward/demo/download" -feed-url https://localhost:8443/v1/manifest.json -ca-file "$HOME/.shixpeer.ward/demo/pki/ca.crt" -trusted-key "$HOME/.shixpeer.ward/demo/pki/feed.pub"
bin/shixpeer-ward-agent lookup -state "$HOME/.shixpeer.ward/demo/download" -ecosystem npm -package ward-demo-package
```

The inventory is `~/.shixpeer.ward/demo/agent/snapshot.json`; the verified database is
under `~/.shixpeer.ward/demo/download/database/`. The collector never uploads the inventory.
`lookup` is offline; use the ecosystem/package from your configured sources.

All generated private keys are local and gitignored. Provision only `ca.crt` and
`feed.pub` to agents through a trusted channel. Never publish the `.local/` directory.
See [TLS and trust](docs/trust.md) before deploying beyond this local exercise.

## Use real, explicitly configured sources

```sh
bin/shixpeer-ward-beacon sync -sources configs/beacon.example.json -state .local/beacon-live
```

For real platform coverage use `configs/beacon.default.json`, or start with
`configs/beacon.quickstart.json`. Supported integrations include Canonical OSV,
Debian Tracker, Apple/SOFA, all annual NVD files, EPSS, KEV and OSV archives.
Direct CVE JSON 5 and GitHub Advisory Database archives are included in the default profile.
Run `check-sources -sources CONFIG` to validate real downloads, and `status -state DIR`
after synchronization. A catalog entry alone does not enable an integration.

[Source configuration and normalization](docs/sources.md) explains the exact behavior,
limits, failures, attribution and what “urgent” means. [Operations](docs/operations.md)
explains state paths, schedules, process isolation and recovery.

## Direct HTTPS or GitHub

Beacon exports the same files for either route:

```text
manifest.json                  Ed25519-signed manifest envelope (protocol v3)
db-<sha256>.wdb              immutable compressed disk-index buckets
```

Agents verify the manifest, expiry, revision, byte count and digest before accepting
data. HTTPS private keys are separate from database signing keys. A mirror does not
need a private key to serve already-signed artifacts.

For GitHub releases/Pages and offline transport, see [distribution](docs/distribution.md).
Publishing is an operator action; the application never silently pushes to GitHub.
No hostname, inventory, installed package list or per-CVE queries are sent to a feed.
A feed/mirror still sees the downloader's IP, timing, and ordinary HTTP/TLS metadata.

## Repository

```text
cmd/shixpeer-ward-agent/       agent entry point
cmd/shixpeer-ward-beacon/      Beacon entry point
internal/agent/               observation, download and local state
internal/beacon/              source adapters, normalization, sync and serving
internal/snapshot/            signed immutable disk artifacts
internal/compactdb/           bounded external sort and disk lookup
internal/identity/            private TLS identity and separate signing keys
pkg/inventory/, pkg/vuln/      shared versioned data contracts
configs/                      documented example inputs, no credentials
api/                          JSON schemas
packaging/systemd/            optional Linux service/timer templates
testdata/                     synthetic public fixtures
docs/                         operator and protocol documentation
```

All mutable state/config/reports default to the executing account's
`~/.shixpeer.ward/`, including root. Explicit flags remain optional overrides.
Use `migrate-home` to preserve legacy trust and anti-rollback checkpoints.

```sh
make fmt
make check
make build VERSION=0.4.0-dev
```

Tests use local TLS servers and generated temporary keys, not live upstream services.
CI covers Linux/macOS; release packaging targets linux/darwin on amd64/arm64.
Use Conventional Commits, Semantic Versioning and the [release checklist](docs/releases.md).
Dependencies and workflow actions must be reviewed and pinned. Source data retains
upstream provenance; check its redistribution terms separately from the code license.

Source-available under the [PolyForm Internal Use License 1.0.0](LICENSE). The licensor is shixpeer. See [NOTICE](NOTICE).
